import logging
import json
import re

import requests
from common import _get_password
from third_party_clients.clearpass.clearpass_config import (
    CHECK_SSL,
    URL,
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
        self.name = "ClearPass Client"
        self.module = "clearpass"
        self.init_log(kwargs)
        self.url = URL + "/api"
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
            self.logger.debug("Login to ClearPass successful.")
            self.bearer = {
                "Authorization": "Bearer " + post_oauth.json()["access_token"]
            }
        except requests.HTTPError as http_err:
            self.logger.error("Clearpass connection issue")
            raise http_err
        except Exception as err:
            self.logger.error("Clearpass connection issue")
            raise err

        # Instantiate parent class
        ThirdPartyInterface.__init__(self)

    def init_log(self, kwargs):
        dict_config = kwargs.get("dict_config", {})
        dict_config["loggers"].update({self.name: dict_config["loggers"]["VAR"]})
        logging.config.dictConfig(dict_config)
        self.logger = logging.getLogger(self.name)

    def block_host(self, host: VectraHost):
        mac_addresses = host.mac_addresses
        if len(mac_addresses) == 0:
            self.logger("No MACs supplied from Detect, searching ClearPass.")
            mac_addresses = self._get_macs(host.ip)

        for mac_address in mac_addresses:
            patch_status = self._patch_endpoint(mac_address, isolated=True)
            disconnect_status = self._disconnect_session(mac_address)

            if patch_status is not None and disconnect_status is not None:
                return []

        return mac_addresses

    def unblock_host(self, host: VectraHost):
        mac_addresses = host.blocked_elements.get(self.name, [])
        for mac_address in mac_addresses:
            self._patch_endpoint(mac_address, isolated=False)
            self._disconnect_session(mac_address)
        return mac_addresses

    def groom_host(self, host: VectraHost) -> dict:
        self.logger.warning("Clear Pass client does not implement host grooming")
        return []

    def block_detection(self, detection: VectraDetection):
        # this client only implements Host-based blocking
        self.logger.warning("VMWare client does not implement detection-based blocking")
        return []

    def unblock_detection(self, detection: VectraDetection):
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

    def get_sessions(self, mac):
        querystring = {'filter': json.dumps({"acctstoptime": {"$exists": False}, "mac_address": mac}),
                       'calculate_count': 'true'}

        mac = re.sub('[.:-]', '', mac).lower()
        r = requests.get(
            url=f'{self.url}/session',
            headers=self.bearer,
            params=querystring,
            verify=self.verify
        )

        response = r.json()

        if response.get('result', {}).get('error', False) == 1:
            self.logger.error(f"Error fetching sessions for MAC {mac}: {response.get('result').get('message')}")
            return False

        if response['count'] > 0:
            sessionid = [(i['id']) for i in response['_embedded']['items'] if not i['acctstoptime']]
            return sessionid[0]

        elif response['count'] == 0:
            self.logger.warning("No active sessions found for MAC {mac}. Disconnect not requested.")
        else:
            self.logger.warning(f"Active sessions could not be retrieved for MAC {mac}")

        return False

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
        sessionid = self.get_sessions(mac_address)
        if not sessionid:
            return False
        disconnect_url = f"{self.url}/session/{sessionid}/disconnect"

        payload = {"confirm_disconnect": "1"}

        self.bearer['content-type'] = "application/json"

        disconnect = requests.post(disconnect_url, data=json.dumps(payload), headers=self.bearer, verify=self.verify)

        disconnect.raise_for_status()
