from logging import receive, send, base64_encode, base64_decode
from checking import check_cmd, check_email, check_file
from checking import check_ip_v_4, check_date_time
import os
from datetime import datetime
import socket
import hmac
import secrets
import signal
ID = '22F1F1'
SECRET = '0e56aad7a7a4a24726f48e26a9ea63b5'
HOST = '127.0.0.1'
BACK_DOOR = ('OTNhZGZkMzA0OWE0MGEzNWUzZWRkZTRmZWFiZDgz' +
             'MDk1NGZmOGM2YjY1ZmFkZDgzNThhNjEyMzU0ZGFlNjE3ZA==')


def signal_handler_for_parent(sig, frame):
    print("S: SIGINT received, closing\r\n", flush=True, end='')
    exit(0)


# Response dictionary for server
def response(conn, num):
    response_dict = {
        500: "Syntax error, command unrecognized",
        501: "Syntax error in parameters or arguments",
        503: "Bad sequence of commands",
        504: "Unrecognized authentication type",
        535: "Authentication credentials invalid",
        235: "Authentication successful",
        421: "Service not available, closing transmission channel",
        220: "Service ready",
        221: "Service closing transmission channel",
        250: "Requested mail action okay completed",
        334: "Server BASE64-encoded challenge",
        354: "Start mail input end <CRLF>.<CRLF>"
    }
    send(conn, f"{num} {response_dict[num]}", "S")


def reset_state():
    return {
        "sender": '',
        "recipient_ls": [],
        "data": ''
    }


def save_to_file(buffer, inbox, auth):
    date = ''
    subject = ''
    data = buffer["data"].split("\n")[:-1]
    file_name = "unknown.txt"

    # Get date line
    if len(data) > 0:
        date_line = data[0]
        if check_date_time(date_line) and date_line.startswith("Date: "):
            date = date_line[5:]
            date_obj = datetime.strptime(date, " %a, %d %b %Y %X %z")
            file_name = str(int(datetime.timestamp(date_obj))) + ".txt"
            data.pop(0)

    # Get subject line
    if len(data) > 0:
        subject_line = data[0]
        if subject_line.startswith("Subject: "):
            subject = subject_line[8:]
            data.pop(0)

    if auth:
        file_name = "auth." + file_name

    # Write to file
    with open(os.path.join(inbox, file_name), "w") as w_file:
        sender = "From: " + buffer["sender"] + "\n"
        recepients = "To: " + ",".join(buffer["recipient_ls"]) + "\n"

        date = "Date:" + date
        subject = "Subject:" + subject

        w_file.write(sender)
        w_file.write(recepients)
        w_file.write(date + "\n")
        w_file.write(subject + "\n")
        w_file.writelines(line + "\n" for line in data)


def request_response_to_client(conn, inbox):
    # Initialize variable
    state = 0
    buffer = reset_state()
    auth = False
    start = True

    # Backdoor for AUTH testing
    # If ip = 1.2.3.4, then the challenge is hardcoded
    ip = ''

    while True:
        if start:
            response(conn, 220)
            start = False
        data = receive(conn, "C")

        if len(data) < 6:
            response(conn, 500)
            continue
        command = data[:4]
        # We will check order of each command first then syntax

        if command == "EHLO":
            if len(data.split(" ")) != 2 or not data.endswith("\r\n"):
                response(conn, 501)
                continue

            arg = data.split()[1].rstrip("\r\n")
            if check_ip_v_4(arg):
                send(conn, f"250 {HOST}\r\n250 AUTH CRAM-MD5", "S")
                ip = arg
                buffer = reset_state()
                state = 1

            else:
                response(conn, 501)

        elif command == "RSET":
            if len(data) != 6 or not data.endswith("\r\n"):
                response(conn, 501)
            else:
                response(conn, 250)
                buffer = reset_state()
                state = 1

        elif command == "MAIL":
            if state != 1:
                response(conn, 503)
            elif (len(data) < 11 or data[:10] != "MAIL FROM:" or
                    len(data.split(" ")) != 2 or not data.endswith("\r\n")):
                response(conn, 501)
            else:
                source = data[10:].rstrip("\r\n")
                if not check_email(source):
                    response(conn, 501)
                else:
                    buffer = reset_state()
                    buffer["sender"] = source
                    response(conn, 250)
                    state = 2

        elif command == "RCPT":
            if state != 2 and state != 3:
                response(conn, 503)
            elif (len(data) < 9 or data[:8] != "RCPT TO:" or
                    len(data.split(" ")) != 2 or not data.endswith("\r\n")):
                response(conn, 501)
            else:
                recepient = data[8:].rstrip("\r\n")
                if not check_email(recepient):
                    response(conn, 501)
                else:
                    buffer["recipient_ls"].append(recepient)
                    response(conn, 250)
                    state = 3

        elif command == "DATA":
            if state != 3:
                response(conn, 503)
            elif len(data) != 6 or not data.endswith("\r\n"):
                response(conn, 501)
            else:
                response(conn, 354)
                done = False
                while not done:
                    data = receive(conn, "C")
                    if data == ".\r\n":
                        response(conn, 250)
                        done = True
                    else:
                        response(conn, 354)
                        buffer["data"] += data.rstrip("\r\n") + "\n"
                save_to_file(buffer, inbox, auth)
                state = 1

        elif command == "NOOP":
            if len(data) != 6 or not data.endswith("\r\n"):
                response(conn, 501)
            else:
                response(conn, 250)

        elif command == "AUTH":
            if not (state == 1 and not auth):
                response(conn, 503)
            elif len(data.split(" ")) != 2 or not data.endswith("\r\n"):
                response(conn, 501)
            elif data.split(" ")[1].rstrip("\r\n") != "CRAM-MD5":
                response(conn, 504)
            else:
                # Generate challenge
                challenge = secrets.token_hex()
                base64_challenge = base64_encode(challenge)
                if ip == "1.2.3.4":
                    base64_challenge = BACK_DOOR
                    challenge = base64_decode(base64_challenge).decode("ascii")

                # Calculate answer
                h = hmac.new(SECRET.encode("ascii"),
                             challenge.encode("ascii"), "md5")
                expected_answer = ID + " " + h.hexdigest()

                send(conn, "334 " + base64_challenge, "S")
                answer = receive(conn, "C").rstrip("\r\n")

                try:
                    if answer == "*":
                        raise Exception
                    answer_str = base64_decode(answer).decode("ascii")

                # B64error
                except Exception:
                    response(conn, 501)
                    continue
                if answer_str == expected_answer:
                    response(conn, 235)
                    auth = True
                else:
                    response(conn, 535)

        elif command == "QUIT":
            if len(data) != 6 or not data.endswith("\r\n"):
                response(conn, 501)
            else:
                response(conn, 221)
                break

        else:
            response(conn, 500)


def listening(sock: socket.socket, inbox):
    with sock:
        while True:
            try:
                # Set up signal handler for SIGINT
                signal.signal(signal.SIGINT, signal_handler_for_parent)
                sock.listen()
                conn, addr = sock.accept()
                # Establish connection
                with conn:
                    request_response_to_client(conn, inbox)
            except (ConnectionResetError, BrokenPipeError, UnicodeDecodeError):
                print("S: Connection lost\r\n", flush=True, end='')


def main():
    # Get configuration information
    config_file = check_cmd()
    path, port = check_file(config_file, "server")
    try:
        # Attempt to write to a dir to check
        path = os.path.expanduser(path)
        file_path = os.path.join(path, "thiswilltestthewritablilityofdir")
        tmp = open(file_path, "w")
        tmp.close()
        os.remove(file_path)
    except (FileNotFoundError, PermissionError, IOError):
        exit(2)

    # Set up socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((HOST, port))
        listening(sock, path)
    except socket.error:
        exit(2)


if __name__ == '__main__':
    main()
