import getpass
import os
import re

import keyring


def _get_password(system, key, **kwargs):
    env_value = os.environ.get("VECTRA_" + key)
    if env_value is not None:
        return env_value
    store_keys = kwargs["modify"][0]
    update_keys = kwargs["modify"][1]
    password = keyring.get_password(system, key)
    if update_keys:
        password = getpass.getpass(f"Enter the {system} {key}: ")
    elif password is None or password == "":
        password = getpass.getpass(f"Enter the {system} {key}: ")
    if store_keys:
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
