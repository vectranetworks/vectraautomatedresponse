import logging
import uuid

from common import _get_password
from third_party_clients.third_party_interface import (
    ThirdPartyInterface,
    VectraAccount,
    VectraDetection,
    VectraHost,
    VectraStaticIP,
)


# class TestClient(ThirdPartyInterface):
class Client(ThirdPartyInterface):
    def __init__(self, **kwargs):
        # Instantiate parent class
        self.name = "Test Client"
        self.module = "test_client"
        self.init_log(kwargs)
        ThirdPartyInterface.__init__(self)

    def init_log(self, kwargs):
        dict_config = kwargs.get("dict_config", {})
        dict_config["loggers"].update({self.name: dict_config["loggers"]["VAR"]})
        logging.config.dictConfig(dict_config)
        self.logger = logging.getLogger(self.name)

    def block_host(self, host: VectraHost):
        id = uuid.uuid4()
        self.logger.debug(f"Blocking host {id}")
        return [id]

    def unblock_host(self, host: VectraHost):
        self.logger.debug(f"Unblocking host {host.blocked_elements.get(self.name)}")
        return host.blocked_elements.get(self.name)

    def groom_host(self, host: VectraHost) -> dict:
        self.logger.debug(f"Grooming host {host}")
        return {"block": [], "unblock": []}

    def block_account(self, account: VectraAccount) -> list:
        id = uuid.uuid4()
        self.logger.debug(f"Blocking account {id}")
        return [id]

    def unblock_account(self, account: VectraAccount):
        self.logger.debug(
            f"Unblocking account {account.blocked_elements.get(self.name)}"
        )
        return account.blocked_elements.get(self.name)

    def block_detection(self, detection: VectraDetection):
        id = uuid.uuid4()
        self.logger.debug(f"Blocking detection {id}")
        return [id]

    def unblock_detection(self, detection: VectraDetection):
        self.logger.debug(
            f"Unblocking detection {detection.blocked_elements.get(self.name)}"
        )
        return detection.blocked_elements.get(self.name)

    def block_static_dst_ips(self, dst_ips: VectraStaticIP):
        self.logger.debug(
            "Test client received {} static IPs to block".format(dst_ips.dst_ips)
        )

    def unblock_static_dst_ips(self, dst_ips: VectraStaticIP):
        self.logger.debug(
            "Test client received {} static IPs to unblock".format(dst_ips.dst_ips)
        )
