import getpass
import os
import platform
import re
import sys

import keyring

if platform.system() == "Windows":
    import msvcrt


def windows_getpass(prompt="Password: "):
    """
    A Windows-safe replacement for getpass.getpass().
    Works around Python 3.13 EOFError issue.
    """

    # If stdin isn't a TTY (e.g., piped input), fallback to normal input
    if not sys.stdin.isatty():
        return input(prompt)

    sys.stdout.write(prompt)
    sys.stdout.flush()

    password = []
    while True:
        ch = msvcrt.getwch()  # Read a single character

        if ch in ("\r", "\n"):  # Enter key
            print()  # Move to new line
            break
        elif ch == "\003":  # Ctrl+C
            raise KeyboardInterrupt
        elif ch == "\b":  # Backspace
            if password:
                password.pop()
                sys.stdout.write("\b \b")
                sys.stdout.flush()
        else:
            password.append(ch)
            sys.stdout.write("*")  # Mask the character
            sys.stdout.flush()

    return "".join(password)


def _get_password(system, key, **kwargs):
    is_windows = False
    if platform.system() == "Windows":
        is_windows = True

    prompt = f"Enter the {system} {key}: "

    env_value = os.environ.get(f"{system}_{key}")
    if env_value is not None:
        return env_value
    store_keys = kwargs["modify"][0]
    update_keys = kwargs["modify"][1]
    if not store_keys:
        if is_windows:
            password = windows_getpass(prompt)
        else:
            password = getpass.getpass(prompt)
    else:
        password = keyring.get_password(system, key)
        if update_keys:
            if is_windows:
                password = windows_getpass(prompt)
            else:
                password = getpass.getpass(prompt)
        elif password is None or password == "":
            if is_windows:
                password = windows_getpass(prompt)
            else:
                password = getpass.getpass(prompt)
        if password is not None:
            try:
                keyring.set_password(system, key, password)
            except keyring.errors.PasswordSetError:
                print("Failed to store password")

    return password


def _format_url(url):
    if ":/" not in url:
        url = "https://" + url
    else:
        url = re.sub("^.*://?", "https://", url)
    url = url[:-1] if url.endswith("/") else url
    return url
