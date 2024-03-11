import ast
import os
import re
import shutil
import sys
from glob import glob
from pathlib import Path

import questionary

if not Path("config.py").is_file():
    shutil.copy("config_template.py", "config.py")

file = "config.py"
# Grab all the variables in the config.py
confs = {}
with open(file, "r") as f:
    for line in f:
        if line[0] not in ["#", "\n"]:
            val = line.strip().split(" = ")
            if val[1] == "None":
                val[1] = ""
            confs[val[0]] = val[1]

# Create the list of third party options
# Display each variable in config.py for configuration
try:
    for conf in confs:
        if conf == "third_party_clients".upper():
            choices = [
                client
                for client in os.listdir("third_party_clients")
                if client
                not in [
                    "__init__.py",
                    "__pycache__",
                    ".DS_Store",
                    "README.md",
                    "third_party_interface.py",
                ]
            ]
            clients = questionary.checkbox(
                f"Choose {conf} (current: {confs[conf]}): ", choices=sorted(choices)
            ).unsafe_ask()
            if clients != []:
                confs[conf] = clients
            else:
                clients = ast.literal_eval(confs[conf])

        else:
            if conf in ["LOG_FILE"] and confs["LOG_TO_FILE"] == "False":
                continue
            if (
                conf
                in ["SMTP_SERVER", "SMTP_PORT", "SRC_EMAIL", "DST_EMAIL", "SMTP_AUTH"]
                and confs["SEND_EMAIL"] == "False"
            ):
                continue
            elif conf in ["SMTP_USER"] and confs["SMTP_AUTH"] == "False":
                continue
            if (
                conf
                in ["SYSLOG_SERVER", "SYSLOG_PORT", "SYSLOG_PROTO", "SYSLOG_FORMAT"]
                and confs["SEND_SYSLOG"] == "False"
            ):
                continue
            arg = questionary.text(
                f"Configure {conf} (current: {confs[conf]}): "
            ).unsafe_ask()
            if arg != "":
                confs[conf] = arg
except KeyboardInterrupt:
    sys.exit()

with open(file, "r") as f:
    data = f.readlines()

try:
    with open(file, "w") as f:
        for line in data:
            variable = line.split(" = ")[0]
            if variable in confs:
                f.write(f"{variable} = {confs[variable]}\n")
            else:
                f.write(line)
except Exception:
    pass

# Display variables from each third party client for configuration
for client in clients:
    confs = {}
    client = client.strip('"')
    try:
        file = glob(f"third_party_clients/{client}/*_config.py")
        file = file[0]
    except IndexError:
        continue
    # for conf in tpc_conf:
    print(f"\nConfigure {client.upper()}:")
    with open(file, "r") as f:
        for line in f:
            if line == "# STOP\n":
                break
            else:
                val = line.strip().split(" = ")
                if line[0] not in ["#", "\n"]:
                    arg = questionary.text(
                        f"Configure {val[0]} (current: {val[1]}): "
                    ).unsafe_ask()
                    if arg != "":
                        confs[val[0]] = arg
                    else:
                        confs[val[0]] = val[1]

    with open(file, "r") as f:
        data = f.readlines()

    with open(file, "w") as f:
        for line in data:
            variable = line.split(" = ")[0]
            if variable in confs:
                f.write(f"{variable} = {confs[variable]}\n")
            else:
                f.write(line)
