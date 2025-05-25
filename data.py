from dataclasses import dataclass


# Поля в заголовке сообщения
@dataclass
class Header:
    name_from: str
    name_to: str
    subject: str
    names_to_copy: str
    date: str


# Поля для сущности файлов
@dataclass
class File:
    name_file: str
    file_type: str
    data: str


# Типы файлов
content_types = {
    '.txt': 'text/plain',
    '.html': 'text/html',
    '.json': 'application/json',
    '.xml': 'application/xml',
    '.pdf': 'application/pdf',
    '.jpg': 'image/jpeg',
    '.png': 'image/png',
    '.mp3': 'audio/mpeg',
    '.mp4': 'video/mp4'
}
