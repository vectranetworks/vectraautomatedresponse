import logging
import uuid

import requests
from third_party_clients.third_party_interface import ThirdPartyInterface


# class TestClient(ThirdPartyInterface):
class Client(ThirdPartyInterface):
    def __init__(self, **kwargs):
        # Instantiate parent class
        self.name = "Test Client"
        self.logger = logging.getLogger()
        ThirdPartyInterface.__init__(self)

    def block_host(self, host):
        id = uuid.uuid4()
        return [id]

    def block_account(self, account) -> list:
        id = uuid.uuid4()
        return [id]

    def unblock_host(self, host):
        return host.blocked_elements.get(self.name)

    def unblock_account(self, account):
        return account.blocked_elements.get(self.name)

    def groom_host(self, host) -> dict:
        return {"block": [], "unblock": []}

    def block_detection(self, detection):
        id = uuid.uuid4()
        return [id]

    def unblock_detection(self, detection):
        return detection.blocked_elements.get(self.name)

    def block_static_dst_ips(self, dst_ips):
        self.logger.info(
            "Test client received {} static IPs to block".format(dst_ips.dst_ips)
        )

    def unblock_static_dst_ips(self, dst_ips):
        self.logger.info(
            "Test client received {} static IPs to unblock".format(dst_ips.dst_ips)
        )
