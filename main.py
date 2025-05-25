from builder import build_send_message
from handler import handle_password
from client import Client


def start():
    header, message, names_to_copy = build_send_message()
    password = handle_password()
    print(header)
    print(' ')
    print(message)
    client = Client()
    client.send_message(header, message, password, names_to_copy)


if __name__ == '__main__':
    start()
