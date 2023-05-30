import base64


def send(s, string, sender, endline="\r\n"):
    # Send phase
    data = string + endline
    s.sendall(data.encode("ascii"))

    # Log phase
    data = data.split("\r\n")
    for send_data in data[:-1]:
        print(f"{sender}: {send_data}", end='\r\n', flush=True)


def receive(s, sender):
    receive_data = s.recv(1024).decode("ascii")

    # Check if receive data not null
    if receive_data:
        display_data = receive_data.split("\r\n")
        for data in display_data[:-1]:
            print(f"{sender}: {data}", end='\r\n', flush=True)
        return receive_data
    else:
        raise BrokenPipeError


def base64_encode(ascii_str):
    ascii_byte = ascii_str.encode("ascii")
    base64_byte = base64.b64encode(ascii_byte)
    base64_string = base64_byte.decode("ascii")
    return base64_string


def base64_decode(ascii_str):
    return base64.b64decode(ascii_str.encode("ascii"))
