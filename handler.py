import base64
import json
import os
from datetime import datetime

from data import Header, File, content_types


def handle_config():
    """Метод для обработки информации из конфигурации."""
    with open('dependencies/config.json', 'r', encoding="utf-8") as json_file:  # новое
        file = json.load(json_file)

        name_from = file['from']
        name_to = file['to']
        subject = file['subject']
        path_to_files = file['attachments']
        names_to_copy = file['cc']
        address = names_to_copy.split(', ')
        file_with_message = file['file_with_message']

        subject_to_message = _handle_subject(subject)
        date = _handle_date()

        return Header(name_from, name_to, subject_to_message, names_to_copy, date), \
            path_to_files, file_with_message, address


def _handle_subject(subject: str):
    """Метод для обработки заголовка."""
    max_length = 998
    folded_header = ""

    while len(subject) > max_length:
        folded_header += subject[:max_length] + "\r\n "
        subject = subject[max_length:]

    folded_header += subject

    return folded_header


def _handle_date():
    """Метод для обработки даты отправки."""
    now = datetime.now()
    formatted_date = now.strftime('%a, %d %b %Y %H:%M:%S %z')
    return formatted_date


def handle_text_message(file_with_message):
    """Метод для обработки текста сообщения."""
    with open(file_with_message, encoding='utf-8') as file:
        text = file.read().split('\n')
        new_text = ''
        for i in range(len(text)):
            if text[i] == len(text[i]) * '.':
                new_text += text[i] + '.\n'
            else:
                new_text += text[i] + '\n'
    return new_text


def handle_files(path_to_send_files):
    """Метод для обработки файлов."""
    files = []
    for filename in os.listdir(path_to_send_files):
        file_path = os.path.join(path_to_send_files, filename)
        if os.path.isfile(file_path):
            file_extension = os.path.splitext(file_path)[1]
            with open(file_path, 'rb') as f:
                send_file = base64.b64encode(f.read()).decode()
                file_type = content_types.get(file_extension)
                files.append(File(filename, file_type, send_file))
    return files


def handle_password():
    """Метод для считывания пароля из файла."""
    with open("dependencies/password.txt", "r", encoding="UTF-8") as file:
        password = file.read().strip()
    return password
