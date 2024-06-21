import json
import logging
from enum import Enum, auto, unique

import requests
from requests import HTTPError
from third_party_clients.clearpass.clearpass_config import (
    CHECK_SSL,
    HOSTNAME,
)

# PASSWORD,
# USERNAME,
from third_party_clients.third_party_interface import (
    ThirdPartyInterface,
    VectraAccount,
    VectraDetection,
    VectraHost,
    VectraStaticIP,
)

from common import _get_password


class Client(ThirdPartyInterface):
    def __init__(self, **kwargs):
        self.name = "ClearPass Client"
        self.logger = logging.getLogger()
        self.url = "https://" + HOSTNAME + "/api"
        self.verify = CHECK_SSL
        try:
            url_oauth = "{url}/oauth".format(url=self.url)
            params_oauth = {
                "grant_type": "password",
                "client_id": _get_password(
                    "Clearpass", "Client_ID", modify=kwargs["modify"]
                ),
                "client_secret": _get_password(
                    "Clearpass", "Client_Secret", modify=kwargs["modify"]
                ),
                "username": _get_password(
                    "Clearpass", "Username", modify=kwargs["modify"]
                ),
                "password": _get_password(
                    "Clearpass", "Password", modify=kwargs["modify"]
                ),
            }
            post_oauth = requests.post(
                url=url_oauth, json=params_oauth, verify=self.verify
            )
            post_oauth.raise_for_status()
            self.logger.info("Login to ClearPass successful.")
            self.bearer = {
                "Authorization": "Bearer " + post_oauth.json()["access_token"]
            }
        except HTTPError as http_err:
            self.logger.error("Clearpass connection issue")
            raise http_err
        except Exception as err:
            self.logger.error("Clearpass connection issue")
            raise err

        # Instantiate parent class
        ThirdPartyInterface.__init__(self)

    def block_host(self, host):
        mac_addresses = host.mac_addresses
        if len(mac_addresses) == 0:
            self.logger("No MACs supplied from Detect, searching ClearPass.")
            mac_addresses = self._get_macs(host.ip)

        for mac_address in mac_addresses:
            self._patch_endpoint(mac_address, isolated=True)
            self._disconnect_session(mac_address)

        return mac_addresses

    def unblock_host(self, host):
        mac_addresses = host.blocked_elements.get(self.name, [])
        for mac_address in mac_addresses:
            self._patch_endpoint(mac_address, isolated=False)
            self._disconnect_session(mac_address)
        return mac_addresses

    def groom_host(self, host) -> dict:
        self.logger.warning("Clear Pass client does not implement host grooming")
        return []

    def block_detection(self, detection):
        # this client only implements Host-based blocking
        self.logger.warn("VMWare client does not implement detection-based blocking")
        return []

    def unblock_detection(self, detection):
        # this client only implements Host-based blocking
        return []

    def block_account(self, account: VectraAccount) -> list:
        # this client only implements Host-based blocking
        return []

    def unblock_account(self, account: VectraAccount) -> list:
        # this client only implements Host-based blocking
        return []

    def block_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        return []

    def unblock_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        return []

    def _get_macs(self, ip):
        mac_list = []
        sessions = requests.get(
            url="{url}/session?filter=%7B%22framedipaddress%22%3A%20%22{ip}%22%7D".format(
                url=self.url, ip=ip
            ),
            headers=self.bearer,
            verify=self.verify,
        )
        if sessions.ok and len(sessions.json()["_embedded"]["items"] > 0):
            for session in sessions.json().get("_embedded").get("items"):
                mac_list.append(session.get("mac_address").replace("-", ":"))
            return list(set(mac_list))
        else:
            return mac_list

    def _patch_endpoint(self, mac_address, isolated=False):
        patch_endpoint_url = "{url}/endpoint/mac-address/{mac_address}".format(
            url=self.url, mac_address=mac_address
        )
        params_patch_endpoint = {
            "mac_address": mac_address,
            "attributes": {"isolated": isolated},
        }
        r = requests.patch(
            url=patch_endpoint_url,
            headers=self.bearer,
            verify=self.verify,
            json=params_patch_endpoint,
        )
        r.raise_for_status()

    def _disconnect_session(self, mac_address):
        """
        Disconnects host session
        """
        disconnect_url = (
            "{url}/session-action/disconnect/mac/{mac_address}?async=false".format(
                url=self.url, mac_address=mac_address
            )
        )
        disconnect = requests.post(
            url=disconnect_url, headers=self.bearer, verify=self.verify
        )
        disconnect.raise_for_status()
