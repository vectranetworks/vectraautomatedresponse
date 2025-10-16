import json
import os
import shutil
import sys
from glob import glob
from pathlib import Path

import questionary

file = "config.py"

if not Path(file).is_file():
    shutil.copy("config_template.py", file)

import config

mylist = [x for x in dir(config) if not x.startswith("__")]
confs = {x: getattr(config, x) for x in mylist}

# print(mylist)
# print(confs)
# sys.exit()


def set_value(conf):
    arg = questionary.text(f"Configure {conf} (current: {confs[conf]}): ").unsafe_ask()
    if arg != "":
        confs[conf] = arg


def config_main():
    # Create the list of third party options
    # Display each variable in config.py for configuration
    try:
        # Configure Cognito URLs
        more = True
        urls = []
        while more:
            arg = questionary.text(
                f"Configure {"COGNITO_URL"} (current: {confs["COGNITO_URL"]}): "
            ).unsafe_ask()
            if arg != "":
                urls.append(arg)
                confs["COGNITO_URL"] = urls
            more = questionary.confirm(
                "Do you have additional Brains? ", default=False
            ).ask()

        # if questionary.confirm(
        #     "Do you want to log to the file 'var.log'?"
        # ).unsafe_ask():
        #     confs["LOG_TO_FILE"] = True
        
        # Configure Sleep Minutes
        conf = "SLEEP_MINUTES"
        set_value(conf)

        # Configure Third Party Clients
        conf = "THIRD_PARTY_CLIENTS"
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

        conf = "AUTH"
        if questionary.confirm(
            "Are you using Vectra API v2.5 or lower?", default=False
        ).unsafe_ask():
            choices = ["OAUTH", "TOKEN"]
            auth = questionary.select(
                "Select the AUTH mechanism you are using: ", choices=sorted(choices)
            ).unsafe_ask()
            confs[conf] = auth

        # Configure Block Days, Block Start Time, Block End Time, and Explicit Unblock
        if block := questionary.confirm(
            "Do you want to set specific timeframes that the VAR can take action?",
            default=False,
        ).unsafe_ask():
            for val in [
                "BLOCK_DAYS",
                "BLOCK_START_TIME",
                "BLOCK_END_TIME",
                "EXPLICIT_UNBLOCK",
            ]:
                conf = val
                if conf in confs:
                    if isinstance(confs[conf], list):
                        arg = questionary.text(
                            f"Configure {conf} (current: {confs[conf]}): "
                        ).unsafe_ask()
                        if arg != "":
                            confs[conf] = [x.strip() for x in arg.split(",")]
                    else:
                        set_value(conf)

        if send := questionary.confirm(
            "Do you want to receive email alerts?", default=False
        ).unsafe_ask():
            for conf in ["SMTP_SERVER", "SMTP_PORT", "SRC_EMAIL", "DST_EMAIL"]:
                set_value(conf)
            confs["SMTP_AUTH"] = questionary.confirm(
                "Does the SMTP server require authentication?", default=False
            ).unsafe_ask()
        confs["SEND_EMAIL"] = send

        if send := questionary.confirm(
            "Do you want to receive syslog alerts?", default=False
        ).unsafe_ask():
            for conf in [
                "SYSLOG_SERVER",
                "SYSLOG_PORT",
                "SYSLOG_PROTO",
                "SYSLOG_FORMAT",
            ]:
                set_value(conf)
        confs["SEND_SYSLOG"] = send
        return confs
    except KeyboardInterrupt:
        sys.exit()


def write_config(file, config):
    try:
        with open(file, "w") as f:
            for k, v in config.items():
                if isinstance(v, str):
                    f.write(f"{k}='{v}'\n")
                elif (
                    isinstance(v, tuple)
                    or isinstance(v, list)
                    or isinstance(v, int)
                    or isinstance(v, bool)
                ):
                    f.write(f"{k}={v}\n")
                else:
                    f.write(f"{k}=''\n")
    except Exception:
        pass


def config_clients(clients):
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


def main():
    configs = config_main()
    write_config("config.py", configs)
    config_clients(configs["THIRD_PARTY_CLIENTS"])


if __name__ == "__main__":
    main()
