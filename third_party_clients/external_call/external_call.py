import logging
import subprocess
import uuid

from third_party_clients.external_call.external_call_config import (
    ACCOUNT_BLOCK_CMD,
    ACCOUNT_UNBLOCK_CMD,
    DETECTION_BLOCK_CMD,
    DETECTION_UNBLOCK_CMD,
    HOST_BLOCK_CMD,
    HOST_UNBLOCK_CMD,
)
from third_party_clients.third_party_interface import (
    ThirdPartyInterface,
    VectraAccount,
    VectraDetection,
    VectraHost,
    VectraStaticIP,
)


class Client(ThirdPartyInterface):
    def __init__(self, **kwargs):
        self.name = "External Call Client"
        self.module = "external_call"
        # Instantiate parent class
        self.init_log(kwargs)
        ThirdPartyInterface.__init__(self)

    def init_log(self, kwargs):
        dict_config = kwargs.get("dict_config", {})
        dict_config["loggers"].update({self.name: dict_config["loggers"]["VAR"]})
        logging.config.dictConfig(dict_config)
        self.logger = logging.getLogger(self.name)

    def block_host(self, host: VectraHost):
        if HOST_BLOCK_CMD:
            self.logger.debug(f"Blocking host {host.id}, {host.name}, {host.ip}")
            id = uuid.uuid4()
            cmd = HOST_BLOCK_CMD
            cmd.append(host.ip)
            r = subprocess.run(cmd)
            if r.returncode == 0:
                return [id]
            else:
                self.logger.error(
                    "Execution of block_host command: {} was not successful".format(
                        r.args
                    )
                )
                return []
        else:
            self.logger.warning("external_call block_host not configured.")
            return []

    def unblock_host(self, host: VectraHost):
        if HOST_UNBLOCK_CMD:
            self.logger.debug(f"Unblocking host {host.id}, {host.name}, {host.ip}")
            cmd = HOST_UNBLOCK_CMD
            cmd.append(host.ip)
            r = subprocess.run(cmd)
            if r.returncode == 0:
                return host.blocked_elements.get(self.name, [])
            else:
                self.logger.error(
                    "Execution of unblock_host command: {} was not successful".format(
                        r.args
                    )
                )
                return []
        else:
            self.logger.warning("external_call unblock_host not configured.")
            return []

    def groom_host(self, host: VectraHost) -> dict:
        self.logger.warning("external_call groom_host not configured.")
        return []

    def block_account(self, account: VectraAccount) -> list:
        if ACCOUNT_BLOCK_CMD:
            self.logger.debug(f"Blocking account {account.id}, {account.name}")
            id = uuid.uuid4()
            cmd = ACCOUNT_BLOCK_CMD
            cmd.append(
                account.ldap.get("sam_account_name")
                if account.ldap.get("sam_account_name")
                else account.fake_sam
            )
            cmd.append(account.context)
            r = subprocess.run(cmd)
            if r.returncode == 0:
                return [id]
            else:
                self.logger.error(
                    "Execution of block_account command: {} was not successful".format(
                        r.args
                    )
                )
                return []
        else:
            self.logger.warning("external_call block_account not configured.")
            return []

    def unblock_account(self, account: VectraAccount):
        if ACCOUNT_UNBLOCK_CMD:
            self.logger.debug(f"Unblocking account {account.id}, {account.name}")
            cmd = ACCOUNT_UNBLOCK_CMD
            cmd.append(
                account.ldap.get("sam_account_name")
                if account.ldap.get("sam_account_name")
                else account.fake_sam
            )
            cmd.append(account.context)
            r = subprocess.run(cmd)
            if r.returncode == 0:
                return account.blocked_elements.get(self.name, [])
            else:
                self.logger.error(
                    "Execution of block_account command: {} was not successful".format(
                        r.args
                    )
                )
                return []
        else:
            self.logger.warning("external_call unblock_account not configured.")
            return []

    def block_detection(self, detection: VectraDetection):
        if DETECTION_BLOCK_CMD:
            self.logger.debug(f"Blocking detection {detection.id}")
            id = uuid.uuid4()
            cmd = DETECTION_BLOCK_CMD
            cmd.append(detection.dst_ips)
            r = subprocess.run(cmd)
            if r.returncode == 0:
                return [id]
            else:
                self.logger.error(
                    "Execution of block_detection command: {} was not successful".format(
                        r.args
                    )
                )
                return []
        else:
            self.logger.warning("external_call block_detection not configured.")
            return []

    def unblock_detection(self, detection: VectraDetection):
        if DETECTION_UNBLOCK_CMD:
            self.logger.debug(f"Unblocking detection {detection.id}")
            cmd = DETECTION_UNBLOCK_CMD
            cmd.append(detection.dst_ips)
            r = subprocess.run(cmd)
            if r.returncode == 0:
                return detection.blocked_elements.get(self.name, [])
            else:
                self.logger.error(
                    "Execution of unblock_detection command: {} was not successful".format(
                        r.args
                    )
                )
                return []
        else:
            self.logger.warning("external_call unblock_detection not configured.")
            return []

    def block_static_dst_ips(self, ips: VectraStaticIP) -> list:
        self.logger.warning("external_call block static destination IP not configured.")
        return []

    def unblock_static_dst_ips(self, ips: VectraStaticIP) -> list:
        self.logger.warning("external_call block static destination IP not configured.")
        return []
