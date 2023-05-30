import sys
from datetime import datetime


def check_date_time(line):
    try:
        # Take the datetime from line and check with datetime module
        line = line[6:]
        date = datetime.strptime(line, "%a, %d %b %Y %X %z")
        # Check if the weekday match with the given date
        weekday = date.strftime("%a")
        if weekday != line[:3]:
            raise ValueError
    except (ValueError, IndexError):
        return False
    return True


def check_ip_v_4(data):
    if data.count(".") != 3:
        return False
    else:
        data = data.split(".")

        for number in data:
            if number not in [str(i) for i in range(256)]:
                return False

    return True


def check_cmd():
    try:
        config_file_path = sys.argv[1]
        config_file = open(config_file_path)
    except Exception:
        exit(1)

    return config_file


def check_atom(atom):
    if (atom == '' or not atom[0].isalnum() or
            not atom.replace("-", "a").isalnum()):
        return False

    return True


def check_subdomain(domain):
    if domain.count(".") == 0:
        return False

    for subdomain in domain.split("."):
        try:
            if (not subdomain[0].isalnum() or not subdomain[-1].isalnum() or
                    not subdomain.replace("-", "a").isalnum()):
                return False
        except IndexError:
            return False

    return True


def check_email(email):
    if not(email.startswith("<") and email.endswith(">") and
           email.count("@") == 1 and len(email) > 3):
        return False
    else:
        dot_string, domain = email[1:-1].split("@")
        for atom in dot_string.split("."):
            if not check_atom(atom):
                return False

        # Domain can be made by subdomain or IPv4
        if (not check_subdomain(domain) and not
                (domain.startswith("[") and domain.endswith("]") and
                    check_ip_v_4(domain[1:-1]))):
            return False

        return True


# Open_by parameter indicates who called the function
def check_file(config_file, open_by):

    with config_file:
        # Get the correspond keyword for the open_by
        contents = config_file.readlines()
        port_key_word = "server_port="
        path_key_word = "inbox_path="
        port_spy_key_word = "client_port="
        if open_by == "client":
            path_key_word = "send_path="
        elif open_by == "spy":
            path_key_word = "spy_path="

        path = ''
        port = ''
        spy_port = ''
        try:
            for line in contents:
                if line.startswith(path_key_word):
                    # If there are 2 paths in config file, the file is invalid
                    if path != '':
                        raise Exception
                    path = line.strip("\n").split("=", 1)[1]
                elif line.startswith(port_key_word):
                    if port != '':
                        raise Exception
                    port = int(line.strip("\n").split("=", 1)[1])
                elif line.startswith(port_spy_key_word) and open_by == "spy":
                    if spy_port != '':
                        raise Exception
                    spy_port = int(line.strip("\n").split("=", 1)[1])

            if (path == '' or port == '' or spy_port == port or
                    (open_by == "spy" and spy_port == '') or port < 1025):
                raise Exception
        except Exception:
            exit(2)
        if open_by == "spy":
            return path, port, spy_port
        else:
            return path, port
