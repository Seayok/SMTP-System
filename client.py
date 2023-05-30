import socket
from logging import send, receive, base64_decode, base64_encode
from checking import check_cmd, check_file, check_email, check_date_time
import hmac
import os
ID = '22F1F1'
SECRET = '0e56aad7a7a4a24726f48e26a9ea63b5'
HOST = '127.0.0.1'


def check_mail_line(line, prefix):
    # Check if the line start with from or to and then check mail.
    line = line[(len(prefix) + 1):]
    if prefix == "From:":
        return check_email(line)
    else:
        return all(check_email(mail) for mail in line.split(","))


def check_prefix(line, prefix):
    return line.startswith(prefix + " ")


def process_email(email):
    valid = True
    try:
        # Go through first 4 lines for sender, recipients, date and subject
        sender_line = email.readline().rstrip("\n")
        valid = (valid and check_prefix(sender_line, "From:") and
                 check_mail_line(sender_line, "From:"))
        sender = sender_line[6:]

        recipients_line = email.readline().rstrip("\n")
        valid = (valid and check_prefix(recipients_line, "To:") and
                 check_mail_line(recipients_line, "To:"))
        recipient_ls = recipients_line[4:].split(",")

        data = email.readlines()

        date_line = data[0].rstrip("\n")
        valid = (valid and check_prefix(date_line, "Date:") and
                 check_date_time(date_line))

        subject_line = data[1].rstrip("\n")
        valid = (valid and check_prefix(subject_line, "Subject:") and
                 len(subject_line) > 9)

        # Check ascii chars
        for data_line in data:
            data_line = data_line.encode("ascii").decode("ascii")

        if not valid:
            raise ValueError
    except (ValueError, IndexError, UnicodeDecodeError):
        return ('', [], [])
    return sender, recipient_ls, data


def send_email(sock, sender, recipient_ls, data, auth):
    # EHLO state
    receive(sock, "S")
    send(sock, f"EHLO {HOST}", "C")
    receive(sock, "S")
    if auth:
        send(sock, "AUTH CRAM-MD5", "C")

        # Create digest
        data_challenge = receive(sock, "S").rstrip("\r\n").split(" ")[1]
        data_challenge = base64_decode(data_challenge)
        h = hmac.new(SECRET.encode("ascii"), data_challenge, "md5")

        # Create answer
        answer = ID + " " + h.hexdigest()
        answer_base64_string = base64_encode(answer)

        send(sock, answer_base64_string, "C")

        receive(sock, "S")

    # Start mail transaction
    send(sock, "MAIL FROM:{}".format(sender), "C")
    receive(sock, "S")
    for recipient in recipient_ls:
        send(sock, "RCPT TO:{}".format(recipient), "C")
        receive(sock, "S")
    send(sock, "DATA", "C")
    receive(sock, "S")
    for content in data:
        send(sock, content.rstrip("\n"), "C")
        receive(sock, "S")

    # End mail transaction
    send(sock, ".", "C")
    receive(sock, "S")

    # Exit
    send(sock, "QUIT", "C")
    receive(sock, "S")


def make_email(sock, sender, recipient_ls, data, auth):
    try:
        send_email(sock, sender, recipient_ls, data, auth)
    except (BrokenPipeError, ConnectionResetError):
        print("C: Connection lost\r\n", flush=True, end='')
        exit(3)


def main():
    # Check command line for config file
    config_file = check_cmd()

    # Get port, path from config file
    path, port = check_file(config_file, "client")

    # Create list of email file to send
    file_ls = []
    try:
        # Getting all the file in dir and check if they are readable
        for file_name in os.listdir(path):
            file_path = os.path.join(path, file_name)
            if os.path.isfile(file_path):
                file_ls.append(open(file_path))

        file_ls.sort(key=lambda file: file.name)
    except (FileNotFoundError, PermissionError, IOError):
        exit(2)

    for file in file_ls:
        with file:
            sender, recipient_ls, data = process_email(file)
            file_path = os.path.abspath(file.name)

            # Not valid format
            if sender == '' and data == [] and recipient_ls == []:
                print(f"C: {file_path}: Bad formation", flush=True, end="\r\n")
                continue

            # Auth checking
            if "auth" in file_path:
                auth = True
            else:
                auth = False

            # Establish connection
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.connect((HOST, port))
                with sock:
                    make_email(sock, sender, recipient_ls, data, auth)
            except ConnectionRefusedError:
                print("C: Cannot establish connection\r\n", flush=True, end='')
                exit(3)


if __name__ == "__main__":
    main()
