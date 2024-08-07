import logging
import os
import uuid

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
        # Instantiate parent class
        self.logger = logging.getLogger()
        ThirdPartyInterface.__init__(self)

    def block_host(self, host):
        host_name = host.name
        os.system(
            "c:\windows\system32\shutdown.exe /s /f /m {} /t 0 /d p:0:0 /c 'Vectra Security Shutdown'".format(
                host_name
            )
        )
        return [host_name]

    def unblock_host(self, host):
        self.logger.warn("Client cannot restart a machine automatically")
        return host.blocked_elements.get(self.name)

    def groom_host(self, host) -> dict:
        self.logger.warning("Windows Shutdown client does not implement host grooming")
        return []

    def block_detection(self, detection):
        # this client only implements Host-based blocking
        self.logger.warn("Client does not implement detection-based blocking")
        return []

    def unblock_detection(self, detection):
        return []

    def block_account(self, account: VectraAccount) -> list:
        return []

    def unblock_account(self, account: VectraAccount) -> list:
        return []

    def block_static_dst_ips(self, ips: VectraStaticIP) -> list:
        return []

    def unblock_static_dst_ips(self, ips: VectraStaticIP) -> list:
        return []
