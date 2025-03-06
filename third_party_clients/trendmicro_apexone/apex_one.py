import base64
import hashlib
import json
import logging
import time

import jwt
import requests
from common import _get_password
from third_party_clients.third_party_interface import (
    ThirdPartyInterface,
    VectraAccount,
    VectraDetection,
    VectraHost,
    VectraStaticIP,
)
from third_party_clients.trendmicro_apexone.apex_one_config import (
    API_PATH,
    BASE_URL,
)


class Client(ThirdPartyInterface):
    def __init__(self, **kwargs):
        self.name = "ApexOne Client"
        self.module = "trendmicro_apexone"
        self.init_log(kwargs)
        self.app_id = _get_password(
            "ApexOne", "Application_ID", modify=kwargs["modify"]
        )
        self.api_key = _get_password("ApexOne", "API_Key", modify=kwargs["modify"])
        # Instantiate parent class
        ThirdPartyInterface.__init__(self)

    def init_log(self, kwargs):
        dict_config = kwargs.get("dict_config", {})
        dict_config["loggers"].update({self.name: dict_config["loggers"]["VAR"]})
        logging.config.dictConfig(dict_config)
        self.logger = logging.getLogger(self.name)

    def block_host(self, host: VectraHost):
        mac_addresses = host.mac_addresses
        mac_addresses = [mac.replace(":", "-") for mac in mac_addresses]
        ip_address = host.ip
        if len(mac_addresses) < 1:
            # No MAC Address found, block IP
            self._patch_endpoint(ip_address=ip_address, act="cmd_isolate_agent")
            return [ip_address]
        else:
            for mac_address in mac_addresses:
                self._patch_endpoint(mac_address=mac_address, act="cmd_isolate_agent")
            return mac_addresses

    def unblock_host(self, host: VectraHost):
        mac_addresses = host.mac_addresses
        mac_addresses = [mac.replace(":", "-") for mac in mac_addresses]
        ip_address = host.ip
        if len(mac_addresses) < 1:
            # No MAC Address found, block IP
            self._patch_endpoint(
                ip_address=ip_address, act="cmd_restore_isolated_agent"
            )
            return [ip_address]
        else:
            for mac_address in mac_addresses:
                self._patch_endpoint(
                    mac_address=mac_address, act="cmd_restore_isolated_agent"
                )
            return mac_addresses

    def groom_host(self, host: VectraHost) -> dict:
        self.logger.warning("ApexOne client does not implement host grooming")
        return []

    def block_detection(self, detection: VectraDetection):
        # this client only implements Host-based blocking
        self.logger.warning(
            "ApexOne client does not implement detection-based blocking"
        )
        return []

    def unblock_detection(self, detection: VectraDetection):
        # this client only implements Host-based blocking
        self.logger.warning(
            "ApexOne client does not implement detection-based blocking"
        )
        return []

    def block_account(self, account: VectraAccount) -> list:
        # this client only implements Host-based blocking
        self.logger.warning("ApexOne client does not implement account-based blocking")
        return []

    def unblock_account(self, account: VectraAccount) -> list:
        # this client only implements Host-based blocking
        self.logger.warning("ApexOne client does not implement account-based blocking")
        return []

    def block_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "ApexOne client does not implement static IP-based blocking"
        )
        return []

    def unblock_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "ApexOne client does not implement static IP-based blocking"
        )
        return []

    def _patch_endpoint(self, act, mac_address="", ip_address="", **kwargs):
        payload = {"act": act, "allow_multiple_match": False}

        if ip_address:
            payload["ip_address"] = ip_address
        else:
            payload["mac_address"] = mac_address

        useRequestBody = json.dumps(payload)

        jwt_token = self.create_jwt_token(useRequestBody, kwargs)

        headers = {
            "Authorization": "Bearer " + jwt_token,
            "Content-Type": "application/json;charset=utf-8",
        }

        r = requests.post(
            BASE_URL + API_PATH, headers=headers, data=useRequestBody, verify=False
        )
        r.raise_for_status()

    @staticmethod
    def create_checksum(http_method, raw_url, headers, request_body):
        string_to_hash = (
            http_method.upper()
            + "|"
            + raw_url.lower()
            + "|"
            + headers
            + "|"
            + request_body
        )
        base64_string = base64.b64encode(
            hashlib.sha256(str.encode(string_to_hash)).digest()
        ).decode("utf-8")
        return base64_string

    def create_jwt_token(self, request_body):
        payload = {
            "appid": self.app_id,
            "iat": time.time(),
            "version": "V1",
            "checksum": self.create_checksum("POST", API_PATH, "", request_body),
        }
        # token = jwt.encode(payload, API_KEY, algorithm='HS256').decode('utf-8')
        token = jwt.encode(
            payload,
            self.api_key,
            algorithm="HS256",
        )
        return token
