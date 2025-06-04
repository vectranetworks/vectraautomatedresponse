import json
import logging
import urllib.parse

import requests
from common import _get_password
from third_party_clients.cisco_asa_http.asa_http_config import (
    BLOCK_GROUP,
    URL,
    USER_AGENT,
)
from third_party_clients.third_party_interface import (
    ThirdPartyInterface,
    VectraAccount,
    VectraDetection,
    VectraHost,
    VectraStaticIP,
)
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


class Client(ThirdPartyInterface):
    def __init__(self, **kwargs):
        self.name = "ASA HTTP Client"
        self.module = "cisco_asa_http"
        self.init_log(kwargs)
        self.url = URL
        self.auth = (
            _get_password("Cisco_ASA_HTTP", "Username", modify=kwargs["modify"]),
            _get_password("Cisco_ASA_HTTP", "Password", modify=kwargs["modify"]),
        )
        self.headers = {"User-Agent": USER_AGENT}
        self._check_connection()
        self.block_group = BLOCK_GROUP
        # Instantiate parent class
        ThirdPartyInterface.__init__(self)

    def init_log(self, kwargs):
        dict_config = kwargs.get("dict_config", {})
        dict_config["loggers"].update({self.name: dict_config["loggers"]["VAR"]})
        logging.config.dictConfig(dict_config)
        self.logger = logging.getLogger(self.name)

    def block_host(self, host: VectraHost) -> list[str]:
        self.logger.info(f"Processing block request for host with IP: {host.ip}")
        try:
            # if self._check_isolation(host.ip):
            #     self.logger.debug(f"Host {host.ip} is already isolated.")
            #     return []
            # else:
            self.logger.debug(f"Adding {host.ip} to block group.")
            self._add_ip_to_group(host.ip)
            return [host.ip]
        except requests.HTTPError as e:
            self.logger.error(e)
            self.logger.error(f"Skipping IP {host.ip}.")
            return []

    def unblock_host(self, host: VectraHost) -> list[str]:
        host_ip = host.blocked_elements.get(self.name, [])[0]
        self.logger.info(f"Processing unblock request for IP: {host_ip}")
        try:
            # if not self._check_isolation(host.ip):
            #     self.logger.debug(f"Host {host.ip} is not isolated.")
            #     return []
            # else:
            self.logger.debug(f"Removing {host_ip} from block group.")
            self._remove_ip_from_group(host_ip)
            return [host_ip]
        except requests.HTTPError as e:
            self.logger.error(e)
            self.logger.error(f"Skipping IP {host_ip}.")
            return []

    def groom_host(self, host: VectraHost) -> dict:
        self.logger.warning("Cisco ASA HTTP client does not implement host grooming")
        return []

    def block_detection(self, detection: VectraDetection):
        # this client only implements Host-based blocking
        self.logger.warning(
            "Cisco ASA HTTP client does not implement detection-based blocking"
        )
        return []

    def unblock_detection(self, detection: VectraDetection):
        # this client only implements Host-based blocking
        self.logger.warning(
            "Cisco ASA HTTP client does not implement detection-based blocking"
        )
        return []

    def block_account(self, account: VectraAccount) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "Cisco ASA HTTP client does not implement account-based blocking"
        )
        return []

    def unblock_account(self, account: VectraAccount) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "Cisco ASA HTTP client does not implement account-based blocking"
        )
        return []

    def block_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "Cisco ASA HTTP client does not implement static IP-based blocking"
        )
        return []

    def unblock_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "Cisco ASA HTTP client does not implement static IP-based blocking"
        )
        return []

    def _check_connection(self):
        try:
            self.logger.debug("Performing Cisco ASA HTTP connection check.")
            self._authenticate()
            self.logger.debug("Connection check successful.")
        except requests.HTTPError as e:
            self.logger.error(
                "Connection check failed. Please check credentials in config file and see detailed error below."
            )
            self.logger.error(e)

    def _authenticate(self):
        endpoint = "/admin/exec/show version"
        response = requests.get(
            urllib.parse.quote(self.url + endpoint),
            verify=False,
            auth=self.auth,
        )
        if not response.status_code == 200:
            raise requests.HTTPError(
                f"Authentication failed - Status: {response.status_code} - Response: {response.text}",
                response=response,
            )

    def _check_isolation(self, host_ip):
        self.logger.debug(f"Checking isolation status for host with IP: {host_ip}")
        endpoint = f"/admin/exec/show running-config object-group id {self.block_group}"
        response = requests.get(
            urllib.parse.quote(self.url + endpoint),
            headers=self.headers,
            verify=False,
            auth=self.auth,
        )
        if not response.status_code == 200:
            raise requests.HTTPError(
                f"Isolation check failed - Status: {response.status_code} - Response: {response.text}",
                response=response,
            )
        response_json = json.loads(response.text)
        if "network-object" in response_json:
            for obj in response_json["network-object"]:
                if obj["host"] == host_ip:
                    self.logger.debug(f"Host {host_ip} is already isolated.")
                    return True
        return False

    def _add_ip_to_group(self, host_ip):
        self.logger.debug(f"Adding host_ip {host_ip} to {self.block_group}")
        endpoint = f"/admin/config/object-group network {self.block_group}/network-object host {host_ip}"
        response = requests.get(
            urllib.parse.quote(self.url + endpoint),
            headers=self.headers,
            verify=False,
            auth=self.auth,
        )
        if not response.status_code == 200:
            raise requests.HTTPError(
                f"Isolation failed - Status: {response.status_code} - Response: {response.text}",
                response=response,
            )

    def _remove_ip_from_group(self, host_ip):
        self.logger.debug(f"Removing host_ip {host_ip} from {self.block_group}")
        endpoint = f"/admin/config/object-group network {self.block_group}/no network-object host {host_ip}"
        response = requests.get(
            urllib.parse.quote(self.url + endpoint),
            headers=self.headers,
            verify=False,
            auth=self.auth,
        )
        if not response.status_code == 200:
            raise requests.HTTPError(
                f"Unisolation failed - Status: {response.status_code} - Response: {response.text}",
                response=response,
            )
