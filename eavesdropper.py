from logging import receive, send
from checking import check_cmd, check_file
from server import save_to_file, reset_state
import socket
import os
ID = '22F1F1'
SECRET = '0e56aad7a7a4a24726f48e26a9ea63b5'
HOST = '127.0.0.1'


def relay(conn, fake_client_sock, spy):
    # Reset buffer information
    buffer = reset_state()
    start = True

    # Varible to indicate the data section had started
    start_mail_content = False

    auth = False
    while True:
        if start:
            start = False
            try:
                server_data = receive(fake_client_sock, "S")
            except (ConnectionResetError, BrokenPipeError, UnicodeDecodeError):
                print("AS: Connection lost\r\n", flush=True, end='')
                exit(3)
            # Send the original string
            send(conn, server_data, "AC", "")

        # Recieve client response and send to server
        client_data = receive(conn, "C")
        try:
            send(fake_client_sock, client_data, "AS", "")
        except (ConnectionResetError, BrokenPipeError, UnicodeDecodeError):
            print("AS: Connection lost\r\n", flush=True, end='')
            exit(3)

        # Recieve server response and send to client
        try:
            server_data = receive(fake_client_sock, "S")
        except (ConnectionResetError, BrokenPipeError, UnicodeDecodeError):
            print("AS: Connection lost\r\n", flush=True, end='')
            exit(3)
        send(conn, server_data, "AC", "")

        if client_data == "QUIT\r\n":
            exit(0)

        # Get client request
        if len(client_data) >= 6:
            command = client_data[:4]
        else:
            command = "NONE"

        # Get server response code
        server_code = server_data[:3]

        # If the data section had started
        if start_mail_content and server_code == "354":
            buffer["data"] += client_data.rstrip("\r\n") + "\n"

        elif start_mail_content and server_code == "250":
            save_to_file(buffer, spy, auth)
            start_mail_content = False

        # Outside of data section
        elif command == "MAIL" and server_code == "250":
            buffer = reset_state()
            buffer["sender"] = client_data[10:].rstrip("\r\n")

        elif command == "RCPT" and server_code == "250":
            buffer["recipient_ls"].append(client_data[8:].rstrip("\r\n"))

        elif command == "DATA" and server_code == "354":
            start_mail_content = True

        elif server_code == "235":
            auth = True


def connecting(fake_server_sock, fake_client_sock, spy, port):
    with fake_server_sock:
        while True:
            try:
                # Connect to client
                fake_server_sock.listen()
                conn, addr = fake_server_sock.accept()
                with conn:
                    # Connect to server
                    fake_client_sock.connect((HOST, port))
                    with fake_client_sock:
                        relay(conn, fake_client_sock, spy)
            except ConnectionRefusedError:
                print("AS: Cannot establish connection")
                exit(3)
            except (ConnectionResetError, BrokenPipeError, UnicodeDecodeError):
                print("AC: Connection lost\r\n", flush=True, end='')


def main():
    # Get the config information
    config_file = check_cmd()
    path, port, spy_port = check_file(config_file, "spy")

    try:
        # Attempt to write a tmp file to a dir to check
        path = os.path.expanduser(path)
        file_path = os.path.join(path, "thiswilltestthewritablilityofdir")
        tmp = open(file_path, "w")
        tmp.close()
        os.remove(file_path)
    except (FileNotFoundError, PermissionError, IOError):
        exit(2)

    # Set up fake server and faker client
    fake_server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    fake_server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    fake_client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    fake_client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        fake_server_sock.bind((HOST, spy_port))
        connecting(fake_server_sock, fake_client_sock, path, port)
    except socket.error:
        exit(2)


if __name__ == '__main__':
    main()
