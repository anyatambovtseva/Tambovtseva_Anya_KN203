import poplib
import email
from email.header import decode_header
import os
import datetime


class POP3Client:
    def __init__(self, server, username, password):
        self.server = server
        self.username = username
        self.password = password
        self.connection = None

        self.server_settings = {
            'mail.ru': {'pop3': 'pop.mail.ru', 'port': 995},
            'yandex.ru': {'pop3': 'pop.yandex.ru', 'port': 995},
            'gmail.com': {'pop3': 'pop.gmail.com', 'port': 995}
        }

    def connect(self):
        """Подключение к POP3 серверу"""
        domain = self.username.split('@')[-1]
        if domain not in self.server_settings:
            raise ValueError(f"Unsupported email provider: {domain}")

        settings = self.server_settings[domain]
        self.connection = poplib.POP3_SSL(settings['pop3'], settings['port'])
        self.connection.user(self.username)
        self.connection.pass_(self.password)
        print(f"Connected to {settings['pop3']}. Messages: {self.connection.stat()[0]}")

    def disconnect(self):
        """Отключение от сервера"""
        if self.connection:
            self.connection.quit()
            self.connection = None
            print("Disconnected from server")

    def get_headers(self, message_num):
        """Получение заголовков письма"""
        if not self.connection:
            raise ConnectionError("Not connected to server")

        _, lines, _ = self.connection.top(message_num, 0)
        msg = email.message_from_bytes(b'\r\n'.join(lines))

        headers = {}
        headers['From'] = self._decode_header(msg.get('From'))
        headers['To'] = self._decode_header(msg.get('To'))
        headers['Subject'] = self._decode_header(msg.get('Subject'))
        headers['Date'] = self._parse_date(msg.get('Date'))

        return headers

    def get_message_top(self, message_num, lines=10):
        """Получение начала письма (TOP command)"""
        if not self.connection:
            raise ConnectionError("Not connected to server")

        _, header_lines, _ = self.connection.top(message_num, 0)
        _, body_lines, _ = self.connection.top(message_num, lines)

        msg_header = email.message_from_bytes(b'\r\n'.join(header_lines))
        msg_body = b'\r\n'.join(body_lines).decode('utf-8', errors='ignore')

        result = {
            'headers': {
                'From': self._decode_header(msg_header.get('From')),
                'Subject': self._decode_header(msg_header.get('Subject')),
                'Date': self._parse_date(msg_header.get('Date'))
            },
            'body_preview': msg_body
        }

        return result

    def download_message(self, message_num, download_dir='attachments'):
        """Скачивание полного письма с вложениями"""
        if not self.connection:
            raise ConnectionError("Not connected to server")

        _, lines, _ = self.connection.retr(message_num)
        msg = email.message_from_bytes(b'\r\n'.join(lines))

        if not os.path.exists(download_dir):
            os.makedirs(download_dir)

        message_data = {
            'headers': {
                'From': self._decode_header(msg.get('From')),
                'To': self._decode_header(msg.get('To')),
                'Subject': self._decode_header(msg.get('Subject')),
                'Date': self._parse_date(msg.get('Date'))
            },
            'body': '',
            'attachments': []
        }

        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))

            if content_type == "text/plain" and "attachment" not in content_disposition:
                charset = part.get_content_charset() or 'utf-8'
                message_data['body'] = part.get_payload(decode=True).decode(charset, errors='ignore')

            elif "attachment" in content_disposition:
                filename = part.get_filename()
                if filename:
                    filename = self._decode_header(filename)
                    attachment_path = os.path.join(download_dir, filename)

                    with open(attachment_path, 'wb') as f:
                        f.write(part.get_payload(decode=True))

                    message_data['attachments'].append({
                        'filename': filename,
                        'path': os.path.abspath(attachment_path)
                    })

        return message_data

    def _decode_header(self, header):
        """Декодирование заголовков"""
        if header is None:
            return None

        decoded = decode_header(header)
        result = []
        for part, encoding in decoded:
            if isinstance(part, bytes):
                try:
                    result.append(part.decode(encoding if encoding else 'utf-8'))
                except:
                    result.append(part.decode('utf-8', errors='replace'))
            else:
                result.append(part)

        return ''.join(result)

    def _parse_date(self, date_str):
        """Парсинг даты из заголовка"""
        if not date_str:
            return None

        try:
            date_tuple = email.utils.parsedate_tz(date_str)
            if date_tuple:
                dt = datetime.datetime.fromtimestamp(email.utils.mktime_tz(date_tuple))
                return dt.strftime('%Y-%m-%d %H:%M:%S')
        except:
            return date_str


def main():
    email_address = input("Enter your email: ")
    password = input("Enter your password: ")

    client = POP3Client('auto', email_address, password)

    try:
        client.connect()

        num_messages = client.connection.stat()[0]
        print(f"\nYou have {num_messages} messages in your inbox")

        if num_messages > 0:
            print("\nHeaders of the last message:")
            headers = client.get_headers(num_messages)
            for key, value in headers.items():
                print(f"{key}: {value}")

            print("\nTop of the message:")
            top = client.get_message_top(num_messages)
            for key, value in top['headers'].items():
                print(f"{key}: {value}")
            print("\nBody preview:")
            print(top['body_preview'][:500] + "...")

            download = input("\nDownload full message with attachments? (y/n): ")
            if download.lower() == 'y':
                message = client.download_message(num_messages)
                print("\nMessage downloaded:")
                print(f"From: {message['headers']['From']}")
                print(f"Subject: {message['headers']['Subject']}")
                print(f"Date: {message['headers']['Date']}")
                print("\nMessage body:")
                print(message['body'][:1000] + ("..." if len(message['body']) > 1000 else ""))

                if message['attachments']:
                    print("\nAttachments downloaded:")
                    for attachment in message['attachments']:
                        print(f"- {attachment['filename']} (saved to {attachment['path']})")
                else:
                    print("\nNo attachments found")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client.disconnect()


if __name__ == "__main__":
    main()
