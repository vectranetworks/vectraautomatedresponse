import hashlib
import logging
import secrets
import string
from datetime import datetime

import requests
from third_party_clients.pan_cortex.cortex_config import (
    # CORTEX_API_TOKEN,
    CORTEX_API_TYPE,
    # CORTEX_KEY_ID,
    CORTEX_URL,
)
from third_party_clients.third_party_interface import (
    ThirdPartyInterface,
    VectraAccount,
    VectraDetection,
    VectraHost,
    VectraStaticIP,
)

from vectra_automated_response import _get_password


def request_error_handler(func):
    """
    Decorator to handle request results and raise if not HTTP success
    :rtype: Requests.Reponse or Exception
    """

    def request_handler(self, *args, **kwargs):
        response = func(self, *args, **kwargs)
        if response.status_code in [200, 201, 204]:
            return response
        else:
            raise HTTPException(response.status_code, response.content)

    return request_handler


class HTTPException(Exception):
    pass


class Client(ThirdPartyInterface):
    @staticmethod
    def _generate_url_params(param_dict):
        """
        Generate url parameters based on a dict
        :param params: dict of keys to generate query params
        :rtype: dict
        """

        url_param = ""

        for k, v in param_dict.items():
            if v is not None and v != "":
                url_param += "{key}={value}&".format(key=k, value=v)

        # Remove the last ampersand and return
        return url_param[:-1]

    def __init__(self, **kwargs):
        self.name = "Cortex Client"
        """
        Initialize PAN Cortex client
        :param cortex_url: FQDN or IP of Cortex appliance - required
        :param cortex_api_token:  - required
        :param cortex_key_id: - required
        :param verify: Verify SSL (default: False) - optional
        """
        self.logger = logging.getLogger()
        self.cortex_url = CORTEX_URL
        self.cortex_api_token = _get_password(
            "Cortex", "API_Token", modify=kwargs["modify"]
        )
        self.cortex_key_id = _get_password("Cortex", "Key_ID", modify=kwargs["modify"])
        self.headers = ""

        # Instantiate parent class
        ThirdPartyInterface.__init__(self)

    def get_headers(self):
        if CORTEX_API_TYPE == "standard":
            self.headers = {
                "x-xdr-auth-id": self.cortex_key_id,
                "Authorization": self.cortex_api_token,
                "Content-Type": "application/json",
            }
        elif CORTEX_API_TYPE == "advanced":
            # Generate a 64 bytes random string
            nonce = "".join(
                [
                    secrets.choice(string.ascii_letters + string.digits)
                    for _ in range(64)
                ]
            )
            # Get the current timestamp as milliseconds.
            timestamp = int(datetime.utcnow().timestamp()) * 1000
            # Generate the auth key:
            auth_key = self.cortex_key_id + nonce + timestamp
            # Convert to bytes object
            auth_key = auth_key.encode("utf-8")
            # Calculate sha256:
            api_key_hash = hashlib.sha256(auth_key).hexdigest()
            # Generate HTTP call headers
            self.headers = {
                "x-xdr-timestamp": str(timestamp),
                "x-xdr-nonce": nonce,
                "x-xdr-auth-id": self.cortex_key_id,
                "Authorization": api_key_hash,
            }

    def block_host(self, host):
        endpoint_id, isolation_status = self.get_endpoint_id(host["ip"])
        if isolation_status == "AGENT_UNISOLATED":
            self._quarantaine_endpoint(endpoint_id)
        return host["ip"]

    def unblock_host(self, host):
        endpoint_id, isolation_status = self.get_endpoint_id(host["ip"])
        if isolation_status == "AGENT_ISOLATED":
            self._unquarantaine_endpoint(endpoint_id)
        return host["ip"]

    def groom_host(self, host) -> dict:
        self.logger.warning("Cortex client does not implement host grooming")
        return []

    def block_detection(self, detection):
        # this client only implements Host-based blocking
        self.logger.warn("Cortex client does not implement detection-based blocking")
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

    @request_error_handler
    def _request(self, method, suffix, payload):
        return requests(
            method=method,
            url=self.cortex_url + suffix,
            headers=self.headers,
            json=payload,
            verify=False,
        )

    def _quarantaine_endpoint(self, endpoint_id):
        """
        Put an endpoint in the Quarantaine policy based on its MAC address
        :param mac_address: MAC address of the endpoint to quarantaine - required
        :rtype: None
        """
        # We need first to put the endpoint in a temporary policy to make the port bounce
        suffix = "/public_api/v1/endpoints/isolate/"
        payload = {"request_data": {"endpoint_id": endpoint_id}}
        self._request(
            method="post",
            suffix=suffix,
            json=payload,
        )

    def _unquarantaine_endpoint(self, endpoint_id):
        """
        Remove an endpoint from the Quarantaine policy based on its MAC address
        :param mac_address: MAC address of the endpoint to unquarantaine - required
        :rtype: Requests.Response
        """
        suffix = "/public_api/v1/endpoints/unisolate/"
        payload = {"request_data": {"endpoint_id": endpoint_id}}
        self._request(
            method="post",
            suffix=suffix,
            json=payload,
        )

    def get_endpoint_id(self, ip_address):
        suffix = "/public_api/v1/endpoints/get_endpoint/"
        payload = {
            "request_data": {
                "search_from": 0,
                "search_to": 100,
                "sort": {"field": "endpoint_id", "keyword": "ASC"},
                "filters": [
                    {"field": "ip_list", "operator": "in", "value": [ip_address]}
                ],
            }
        }

        r = self._request(
            method="post",
            url=self.cortex_url + suffix,
            headers=self.headers,
            json=payload,
            verify=False,
        )
        response = r.json()["reply"]
        try:
            endpoint_id = response["endpoints"][0]["endpoint_id"]
            isolation_status = response["endpoints"][0]["is_isolated"]
            return endpoint_id, isolation_status
        except IndexError:
            return False
