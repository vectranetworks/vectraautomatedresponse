import logging

import requests
from common import _get_password
from third_party_clients.fortimanager.fortimanager_config import (
    ADOM,
    BLOCK_GROUP,
    CHECK_SSL,
    EXTERNAL_BLOCK_TAG,
    FMG_USER,
    INTERNAL_BLOCK_TAG,
    POLICY_PKG,
    URLS,
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
        self.name = "FMG Client"
        self.module = "fortimanager"
        self.init_log(**kwargs)
        self.firewalls = []
        self.verify = CHECK_SSL

        for url in URLS:
            self.firewalls.append({"url": url, "session": self._get_api_session(url)})

        self.internal_block_tag = INTERNAL_BLOCK_TAG
        self.external_block_tag = EXTERNAL_BLOCK_TAG
        ThirdPartyInterface.__init__(self)

    def init_log(self, kwargs):
        dict_config = kwargs.get("dict_config", {})
        dict_config["loggers"].update({self.name: dict_config["loggers"]["VAR"]})
        logging.config.dictConfig(dict_config)
        self.logger = logging.getLogger(self.name)

    def _get_api_session(self, fmg_url, **kwargs):
        password = _get_password(fmg_url, "password", modify=kwargs["modify"])
        payload = {
            "method": "exec",
            "params": [
                {
                    "url": "/sys/login/user",
                    "data": {"user": FMG_USER, "passwd": password},
                }
            ],
            "id": 1,
        }
        r = requests.post(f"{fmg_url}/jsonrpc", json=payload, verify=self.verify)
        return r.json().get("session")

    def _add_address_object(self, firewall, ip, tag):
        name = f"{tag}_{ip.replace('.', '_')}"
        payload = {
            "method": "add",
            "params": [
                {
                    "url": f"/pm/config/adom/{ADOM}/obj/firewall/address",
                    "data": [
                        {
                            "name": name,
                            "type": "ipmask",
                            "subnet": f"{ip} 255.255.255.255",
                            "tagging": [{"category": "Vectra", "name": tag}],
                        }
                    ],
                }
            ],
            "session": firewall["session"],
            "id": 2,
        }
        requests.post(f"{firewall['url']}/jsonrpc", json=payload, verify=self.verify)

    def _delete_address_object(self, firewall, ip, tag):
        name = f"{tag}_{ip.replace('.', '_')}"
        payload = {
            "method": "delete",
            "params": [{"url": f"/pm/config/adom/{ADOM}/obj/firewall/address/{name}"}],
            "session": firewall["session"],
            "id": 5,
        }
        requests.post(f"{firewall['url']}/jsonrpc", json=payload, verify=self.verify)

    def _update_block_group(self, firewall, ip, tag):
        name = f"{tag}_{ip.replace('.', '_')}"
        payload = {
            "method": "update",
            "params": [
                {
                    "url": f"/pm/config/adom/{ADOM}/obj/firewall/addrgrp/{BLOCK_GROUP}",
                    "data": {"member": [{"name": name}]},
                }
            ],
            "session": firewall["session"],
            "id": 3,
        }
        requests.post(f"{firewall['url']}/jsonrpc", json=payload, verify=self.verify)

    def _install_policy(self, firewall):
        payload = {
            "method": "exec",
            "params": [
                {
                    "url": "/securityconsole/install/package",
                    "data": {
                        "adom": ADOM,
                        "pkg": POLICY_PKG,
                        "scope": [{"name": "<fgt-name>", "vdom": "root"}],
                    },
                }
            ],
            "session": firewall["session"],
            "id": 4,
        }
        requests.post(f"{firewall['url']}/jsonrpc", json=payload, verify=self.verify)

    def block_host(self, host: VectraHost) -> list:
        ip_address = host.ip
        for firewall in self.firewalls:
            self._add_address_object(firewall, ip_address, self.internal_block_tag)
            self._update_block_group(firewall, ip_address, self.internal_block_tag)
            self._install_policy(firewall)
        return [ip_address]

    def unblock_host(self, host: VectraHost) -> list:
        ip_addresses = host.blocked_elements.get(self.name, [])
        for firewall in self.firewalls:
            for ip in ip_addresses:
                self._delete_address_object(firewall, ip, self.internal_block_tag)
            self._install_policy(firewall)
        return ip_addresses

    def block_account(self, account: VectraAccount) -> list:
        self.logger.warning("FMG does not implement account blocking")
        return []

    def unblock_account(self, account: VectraAccount) -> list:
        self.logger.warning("FMG does not implement account blocking")
        return []

    def groom_host(self, host) -> dict:
        self.logger.warning("FMG does not implement host grooming")
        return {}

    def block_detection(self, detection: VectraDetection) -> list:
        ip_addresses = detection.dst_ips
        for firewall in self.firewalls:
            for ip in ip_addresses:
                self._add_address_object(firewall, ip, self.external_block_tag)
                self._update_block_group(firewall, ip, self.external_block_tag)
            self._install_policy(firewall)
        return ip_addresses

    def unblock_detection(self, detection: VectraDetection) -> list:
        ip_addresses = detection.blocked_elements.get(self.name, [])
        for firewall in self.firewalls:
            for ip in ip_addresses:
                self._delete_address_object(firewall, ip, self.external_block_tag)
            self._install_policy(firewall)
        return ip_addresses

    def block_static_dst_ips(self, ips: VectraStaticIP) -> list:
        ip_addresses = ips.dst_ips
        for firewall in self.firewalls:
            for ip in ip_addresses:
                self._add_address_object(firewall, ip, self.external_block_tag)
                self._update_block_group(firewall, ip, self.external_block_tag)
            self._install_policy(firewall)
        return ip_addresses

    def unblock_static_dst_ips(self, ips: VectraStaticIP) -> list:
        ip_addresses = ips.dst_ips
        for firewall in self.firewalls:
            for ip in ip_addresses:
                self._delete_address_object(firewall, ip, self.external_block_tag)
            self._install_policy(firewall)
        return ip_addresses
