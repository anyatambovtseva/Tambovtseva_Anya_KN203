import base64
import socket
import ssl

HOST_ADDRESS = 'smtp.mail.ru'
PORT = 465


class SMTPException(Exception):
    pass


class Client:

    def _request(self, socket, request):
        """Метод для обмена данными с сервером."""
        socket.send((request + '\n').encode())
        recv_data = b""
        try:
            while chunk := socket.recv(4096):
                recv_data += chunk
        finally:
            self._check_response(recv_data.decode())
            return recv_data.decode()

    def _create_ssl_context(self):
        """Метод для создания SSL соединения."""
        try:
            ssl_contex = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_contex.check_hostname = False
            ssl_contex.verify_mode = ssl.CERT_NONE
            return ssl_contex
        except SMTPException as e:
            print(e)

    def _create_connect(self):
        """Метод для создания соединения с сервером."""
        try:
            ssl_contex = self._create_ssl_context()
            with socket.create_connection((HOST_ADDRESS, PORT), timeout=1) as sock:
                return ssl_contex.wrap_socket(sock, server_hostname=HOST_ADDRESS)
        except SMTPException as e:
            print(e)

    def _authorization(self, client, name_from, password):
        """Метод для авторизации."""
        try:
            base64login = base64.b64encode(name_from.encode()).decode()
            base64password = base64.b64encode(password.encode()).decode()
            self._request(client, 'AUTH LOGIN')
            self._request(client, base64login)
            self._request(client, base64password)
        except SMTPException as e:
            print(e)

    def _check_response(self, response):
        """Метод для проверки на ошибки."""
        code = response[:3]
        if code not in ['250', '235', '334', '354']:
            raise SMTPException(f"SMTP server returned an error: {response}")

    def _configure_recipients(self, name_to, names_to_copy, client):
        try:
            self._request(client, f"RCPT TO:{name_to}")
            if names_to_copy:
                for user in names_to_copy:
                    self._request(client, f"RCPT TO:{user}")
        except SMTPException as e:
            print(e)

    def send_message(self, header, message, password, names_to_copy):
        """Метод для отправки смс."""
        try:
            client = self._create_connect()

            print(client.recv(1024))
            self._request(client, f'EHLO {HOST_ADDRESS}')

            self._authorization(client, header.name_from, password)
            self._request(client, f'MAIL FROM:{header.name_from}')
            self._configure_recipients(header.name_to, names_to_copy, client)

            self._request(client, 'DATA')
            self._request(client, message)
        except SMTPException as e:
            print(e)
