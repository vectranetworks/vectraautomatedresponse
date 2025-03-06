import logging
import os

from third_party_clients.third_party_interface import (
    ThirdPartyInterface,
    VectraAccount,
    VectraDetection,
    VectraHost,
    VectraStaticIP,
)


class Client(ThirdPartyInterface):
    def __init__(self, **kwargs):
        self.name = "Windows Shutdown Client"
        self.module = "windows_shutdown"
        self.init_log(kwargs)
        # Instantiate parent class
        ThirdPartyInterface.__init__(self)

    def init_log(self, kwargs):
        dict_config = kwargs.get("dict_config", {})
        dict_config["loggers"].update({self.name: dict_config["loggers"]["VAR"]})
        logging.config.dictConfig(dict_config)
        self.logger = logging.getLogger(self.name)

    def block_host(self, host: VectraHost):
        host_name = host.name
        os.system(
            "c:\windows\system32\shutdown.exe /s /f /m {} /t 0 /d p:0:0 /c 'Vectra Automated Response - Shutdown'".format(
                host_name
            )
        )
        return [host_name]

    def unblock_host(self, host: VectraHost):
        self.logger.warning("Client cannot restart a machine automatically")
        return host.blocked_elements.get(self.name)

    def groom_host(self, host: VectraHost) -> dict:
        self.logger.warning("Windows Shutdown client does not implement host grooming")
        return []

    def block_detection(self, detection: VectraDetection):
        # this client only implements Host-based blocking
        self.logger.warning("Client does not implement detection-based blocking")
        return []

    def unblock_detection(self, detection: VectraDetection):
        self.logger.warning("Client does not implement detection-based blocking")
        return []

    def block_account(self, account: VectraAccount) -> list:
        self.logger.warning("Client does not implement account-based blocking")
        return []

    def unblock_account(self, account: VectraAccount) -> list:
        self.logger.warning("Client does not implement account-based blocking")
        return []

    def block_static_dst_ips(self, ips: VectraStaticIP) -> list:
        self.logger.warning("Client does not implement StaticIP blocking")
        return []

    def unblock_static_dst_ips(self, ips: VectraStaticIP) -> list:
        self.logger.warning("Client does not implement StaticIP blocking")
        return []
