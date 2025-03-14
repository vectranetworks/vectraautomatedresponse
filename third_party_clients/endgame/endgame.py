import logging

import requests
from common import _get_password
from third_party_clients.endgame.endgame_config import (
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
        self.name = "Endgame Client"
        self.module = "endgame"
        self.init_log(kwargs)
        self.url = "{url}/api/endpoint".format(url=URL)
        self.headers = {
            "Authorization": "ApiKey "
            + _get_password("Endgame", "API_Token", modify=kwargs["modify"]).strip(),
            "Content-Type": "application/json",
            "kbn-xsrf": "endgame",
        }
        self.verify = CHECK_SSL
        # Instantiate parent class
        ThirdPartyInterface.__init__(self)

    def init_log(self, kwargs):
        dict_config = kwargs.get("dict_config", {})
        dict_config["loggers"].update({self.name: dict_config["loggers"]["VAR"]})
        logging.config.dictConfig(dict_config)
        self.logger = logging.getLogger(self.name)

    def block_host(self, host: VectraHost):
        mac_addresses = host.mac_addresses
        endpoint_ids = []
        if len(mac_addresses) == 0:
            self.logger("No MACs supplied from Detect, searching Endgame.")
            endpoint_ids += self._get_endpoint_ids(host.ip, "ip")

        for mac_address in mac_addresses:
            endpoint_ids += self._get_endpoint_ids(mac_address, "mac")

        for endpoint_id in endpoint_ids:
            self._isolate_endpoint(endpoint_id)

        return endpoint_ids

    def unblock_host(self, host: VectraHost):
        endpoint_ids = host.blocked_elements.get(self.name, [])
        unisolated_list = []
        for endpoint_id in endpoint_ids:
            unisolated = self._unisolate_endpoint(endpoint_id)
            if unisolated != "":
                unisolated_list.append(unisolated)

        return list(set(unisolated_list))

    def groom_host(self, host: VectraHost) -> dict:
        self.logger.warning("Endgame client does not implement host grooming")
        return []

    def block_detection(self, detection: VectraDetection):
        self.logger.warning("Endgame client does not implement detection blocking")
        return []

    def unblock_detection(self, detection: VectraDetection):
        self.logger.warning("Endgame client does not implement detection blocking")
        return []

    def block_account(self, account: VectraAccount) -> list:
        self.logger.warning("Endgame client does not implement account blocking")
        return []

    def unblock_account(self, account: VectraAccount) -> list:
        self.logger.warning("Endgame client does not implement account blocking")
        return []

    def block_static_dst_ips(self, ips: VectraStaticIP) -> list:
        self.logger.warning("Endgame client does not implement static IP-blocking")
        return []

    def unblock_static_dst_ips(self, ips: VectraStaticIP) -> list:
        self.logger.warning("Endgame client does not implement static IP-blocking")
        return []

    def _get_endpoint_ids(self, value, type):
        url = self.url + f"/metadata?kuery=\"united.endpoint.host.{type} : '{value}'\""
        endpoint_ids = []
        try:
            resp = requests.get(
                url=url,
                headers=self.headers,
                verify=self.verify,
            )
            for host in resp.json().get("data", []):
                endpoint_ids.append(
                    host.get("metadata", []).get("host", []).get("id", "")
                )
            return endpoint_ids
        except requests.HTTPError as err:
            self.logger.error(str(err))

        return []

    def _isolate_endpoint(self, endpoint_id):
        self.logger.debug(f"Isolating endpoint_id {endpoint_id}")
        url = self.url + "/action/isolate"
        body = {
            "endpoint_ids": [endpoint_id],
            "comment": "Vectra Automated Response Isolation",
        }
        try:
            resp = requests.post(
                url=url, headers=self.headers, verify=self.verify, json=body
            )
            return endpoint_id
        except requests.HTTPError as err:
            if resp.status_code == 403:
                self.logger.error(
                    "API Key has insufficient privileges. Host Isolation required."
                )
            else:
                self.logger.error(str(err))
            return ""

    def _unisolate_endpoint(self, endpoint_id):
        self.logger.debug(f"Unisolating endpoint_id {endpoint_id}")
        url = self.url + "/action/unisolate"
        body = {
            "endpoint_ids": [endpoint_id],
            "comment": "Vectra Automated Response Unisolation",
        }
        try:
            resp = requests.post(
                url=url, headers=self.headers, verify=self.verify, json=body
            )
            return endpoint_id
        except requests.HTTPError as err:
            if resp.status_code == 403:
                self.logger.error(
                    "API Key has insufficient privileges. Host Isolation required."
                )
            else:
                self.logger.error(str(err))
            return ""
