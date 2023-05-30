from logging import base64_encode, base64_decode
from checking import check_cmd, check_email, check_file, check_ip_v_4
from server import reset_state, signal_handler_for_parent
from checking import check_date_time
from datetime import datetime
import socket
import hmac
import os
import secrets
import signal
ID = '22F1F1'
SECRET = '0e56aad7a7a4a24726f48e26a9ea63b5'
HOST = '127.0.0.1'


def send(s, string, owner, process_num, pid):

    endline = "\r\n"
    data = string + endline

    # Send phase
    s.sendall(data.encode("ascii"))

    # Log phase
    data = data.split("\r\n")
    for send_data in data[:-1]:
        print(f"[{pid}][{process_num}]{owner}: {send_data}",
              end="\r\n", flush=True)


def receive(s, sender, process_num, pid):
    receive_data = s.recv(1024).decode("ascii")
    if receive_data:
        display_data = receive_data.split("\r\n")
        for data in display_data[:-1]:
            print(f"[{pid}][{process_num}]{sender}: {data}",
                  end="\r\n", flush=True)
        return receive_data
    else:
        raise BrokenPipeError


def signal_handler_for_child(sig, frame):
    exit(0)


def response(conn, num, process_num, pid):
    # Response code with their descriptions
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
    send(conn, f"{num} {response_dict[num]}", "S", process_num, pid)


def save_to_file(buffer, inbox, auth, process_num, pid):
    date = ''
    subject = ''
    data = buffer["data"].split("\n")[:-1]
    file_name = "unknown.txt"

    # Get the date line
    if len(data) > 0:
        date_line = data[0]
        if check_date_time(date_line) and date_line.startswith("Date: "):
            date = date_line[5:]
            date_obj = datetime.strptime(date, " %a, %d %b %Y %X %z")
            file_name = str(int(datetime.timestamp(date_obj))) + ".txt"
            data.pop(0)

    # Get the subject line:
    if len(data) > 0:
        subject_line = data[0]
        if subject_line.startswith("Subject: "):
            subject = subject_line[8:]
            data.pop(0)

    if auth:
        file_name = "auth." + file_name

    # Add pid and process number
    file_name = f"[{pid}][{process_num}]" + file_name

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


def request_response_to_client(conn, inbox, pid, process_num):
    # State variable is used for managing order of command
    state = 0
    buffer = reset_state()
    auth = False
    start = True
    while True:
        # Initialize connection
        if start:
            response(conn, 220, process_num, pid)
            start = False
        data = receive(conn, "C", process_num, pid)

        if len(data) < 6:
            response(conn, 500, process_num, pid)
            continue

        command = data[:4]
        # For each command, we will check order then syntax

        if command == "EHLO":
            if len(data.split(" ")) != 2 or not data.endswith("\r\n"):
                response(conn, 501, process_num, pid)
                continue

            # Arg is IPv4 from the request
            arg = data.split(" ")[1].rstrip("\r\n")
            if check_ip_v_4(arg):
                send(conn, f"250 {HOST}\r\n250 AUTH CRAM-MD5", "S",
                     process_num, pid)
                buffer = reset_state()
                state = 1

            else:
                response(conn, 501, process_num, pid)

        elif command == "RSET":
            if len(data) != 6 or not data.endswith("\r\n"):
                response(conn, 501, process_num, pid)
            else:
                response(conn, 250, process_num, pid)
                buffer = reset_state()
                state = 1

        elif command == "MAIL":
            if (len(data) < 11 or data[:10] != "MAIL FROM:" or
                    len(data.split(" ")) != 2 or not data.endswith("\r\n")):
                response(conn, 501, process_num, pid)
            else:
                source = data[10:].rstrip("\r\n")
                if not check_email(source):
                    response(conn, 501, process_num, pid)
                elif state != 1:
                    response(conn, 503, process_num, pid)
                else:
                    buffer["sender"] = source
                    response(conn, 250, process_num, pid)
                    state = 2

        elif command == "RCPT":
            if (len(data) < 9 or data[:8] != "RCPT TO:" or
                    len(data.split(" ")) != 2 or not data.endswith("\r\n")):
                response(conn, 501, process_num, pid)
            else:
                recepient = data[8:].rstrip("\r\n")
                if state != 2 and state != 3:
                    response(conn, 503, process_num, pid)
                elif not check_email(recepient):
                    response(conn, 501, process_num, pid)
                else:
                    buffer["recipient_ls"].append(recepient)
                    response(conn, 250, process_num, pid)
                    state = 3

        elif command == "DATA":
            if state != 3:
                response(conn, 503, process_num, pid)
            elif len(data) != 6 or not data.endswith("\r\n"):
                response(conn, 501, process_num, pid)
            else:
                response(conn, 354, process_num, pid)
                done = False
                while not done:
                    data = receive(conn, "C", process_num, pid)
                    if data == ".\r\n":
                        response(conn, 250, process_num, pid)
                        save_to_file(buffer, inbox, auth, process_num, pid)
                        state = 1
                        done = True
                    else:
                        response(conn, 354, process_num, pid)
                        buffer["data"] += data.rstrip("\r\n") + "\n"

        elif command == "NOOP":
            if len(data) != 6 or not data.endswith("\r\n"):
                response(conn, 501, process_num, pid)
            else:
                response(conn, 250, process_num, pid)

        elif command == "AUTH":
            if not (state == 1 and not auth):
                response(conn, 503, process_num, pid)
            elif len(data.split(" ")) != 2 or not data.endswith("\r\n"):
                response(conn, 501, process_num, pid)
            elif data.split(" ")[1].rstrip("\r\n") != "CRAM-MD5":
                response(conn, 504, process_num, pid)
            else:
                auth = True
                # Generate challenge
                challenge = secrets.token_hex()
                base64_challenge = base64_encode(challenge)
                h = hmac.new(SECRET.encode("ascii"),
                             challenge.encode("ascii"), "md5")

                # Generate answer
                expected_answer = ID + " " + h.hexdigest()
                send(conn, "334 " + base64_challenge, "S", process_num, pid)

                answer = receive(conn, "C", process_num, pid).rstrip("\r\n")
                try:
                    if answer == "*":
                        raise Exception
                    answer_str = base64_decode(answer).decode("ascii")
                    answer_str = answer_str.rstrip("\r\n")

                # B64error
                except Exception:
                    response(conn, 501, process_num, pid)
                    continue

                if answer_str == expected_answer:
                    response(conn, 235, process_num, pid)
                else:
                    response(conn, 535, process_num, pid)

        elif command == "QUIT":
            if len(data) != 6 or not data.endswith("\r\n"):
                response(conn, 501, process_num, pid)
            else:
                response(conn, 221, process_num, pid)
                exit(0)

        else:
            response(conn, 500, process_num, pid)


def listening(sock, inbox):
    with sock:
        process_num = 0
        while True:
            try:
                # Set up signal handler
                signal.signal(signal.SIGINT, signal_handler_for_parent)

                # Start listening and forking
                sock.listen()
                conn, addr = sock.accept()
                with conn:
                    process_num += 1
                    pid = os.fork()

                    # Child process
                    if pid == 0:
                        signal.signal(signal.SIGINT, signal_handler_for_child)
                        current_pid = os.getpid()
                        request_response_to_client(conn, inbox,
                                                   current_pid, process_num)

                    # Parent
                    elif pid > 0:
                        continue
            except (ConnectionResetError, BrokenPipeError, UnicodeDecodeError):
                print("S: Connection lost\r\n", flush=True, end='')
                exit(0)


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

    # Start listening
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((HOST, port))
        listening(sock, path)
    except socket.error:
        exit(2)


if __name__ == '__main__':
    main()
