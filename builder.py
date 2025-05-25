from data import Header
from handler import handle_config, handle_text_message, handle_files

BOUNDARY = "bound.40629"


def build_send_message():
    """Метод для обработки смс для отправки."""
    header, path_to_send_files, file_with_message, names_to_copy = handle_config()
    _text_message = handle_text_message(file_with_message)
    files = handle_files(path_to_send_files)

    header_message = _build_header(header)
    text_message = _build_text_message(_text_message)
    files_message = _build_files_message(files)
    message = header_message + text_message + files_message + f'--{BOUNDARY}--\n.'
    return header, message, names_to_copy


def _build_header(header: Header) -> str:
    """Метод для сборки заголовка смс."""
    header_message = f'From: {header.name_from}\n' \
                     f'To: {header.name_to}\n' \
                     f'Cc: {header.names_to_copy}\n' \
                     f'Subject: {header.subject}\n' \
                     f'MIME-Version: 1.0\n' \
                     f'Date: {header.date}\n' \
                     f'Content-Type: multipart/mixed; ' \
                     f'boundary={BOUNDARY}\n\n'
    return header_message


def _build_text_message(text_message):
    """Метод для сборки текста смс."""
    text_body = f'--{BOUNDARY}\n' \
                f'Content-Type: text/plain; charset=utf-8\n\n' \
                f'{text_message}\n\n'
    return text_body


def _build_files_message(files):
    """Метод для сборки сообщения с файлами."""
    files_body = ''
    for file in files:
        files_body += f'--{BOUNDARY}\n' \
                      f'Content-Disposition: attachment;\n' \
                      f'filename="{file.name_file}"\n' \
                      f'Content-Transfer-Encoding: base64\n' \
                      f'Content-Type: {file.file_type}; ' \
                      f'name="{file.name_file}"\n\n' \
                      f'{file.data}\n\n'
    return files_body
