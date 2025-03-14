import hashlib
import logging
import secrets
import string
from datetime import datetime

import requests
from third_party_clients.pan_cortex.cortex_config import (
    CORTEX_API_TYPE,
    CORTEX_URL,
)
from third_party_clients.third_party_interface import (
    ThirdPartyInterface,
    VectraAccount,
    VectraDetection,
    VectraHost,
    VectraStaticIP,
)

from common import _get_password


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
    def __init__(self, status_code, content):
        super().__init__(status_code, content)


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
        """
        Initialize PAN Cortex client
        """
        self.name = "Cortex Client"
        self.logger = logging.getLogger()
        if CORTEX_URL:
            self.cortex_url = CORTEX_URL
        else:
            raise ValueError("Missing Cortex EDR URL")
        self.cortex_api_token = _get_password(
            "Cortex", "API_Token", modify=kwargs["modify"]
        )
        self.cortex_key_id = _get_password("Cortex", "Key_ID", modify=kwargs["modify"])
        self.headers = None
        # Instantiate parent class
        ThirdPartyInterface.__init__(self)

    def block_host(self, host: VectraHost) -> list:
        try:
            endpoint_id = self._get_endpoint_id(host.ip)
            if endpoint_id:
                self._quarantaine_endpoint(endpoint_id)
                return [endpoint_id]
            else:
                raise HTTPException(status_code=404, content=f'No online Cortex XDR Agent found for IP {host.ip}')
        except HTTPException as e:
            self.logger.error(f'Lookup for ip {host.ip} in Cortex EDR failed - {e}')
            return []
        
    def unblock_host(self, host:VectraHost) -> list:
        # Get all Endpoint IDs blocked by this client
        blocked_elements = host.blocked_elements[self.name]
        unblocked_elements = []
        for endpoint_id in blocked_elements:
            try:
                self._unquarantaine_endpoint(endpoint_id)
                unblocked_elements.append(endpoint_id)
            except HTTPException as e:
                self.logger.error(f"Unable to unblock endpoint ID {endpoint_id}: {e} - Continuing")
                continue
        return unblocked_elements

    def groom_host(self, host:VectraHost) -> dict:
        self.logger.warning("Cortex client does not implement host grooming")
        return []

    def block_detection(self, detection:VectraDetection) -> list:
        # this client only implements Host-based blocking
        self.logger.warn("Cortex client does not implement detection-based blocking")
        return []

    def unblock_detection(self, detection:VectraDetection) -> list :
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
    
    def _get_headers(self) -> None:
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

    @request_error_handler
    def _request(self, method:str, url:str, **kwargs) -> requests.request:
        
        if method not in ["get", "patch", "put", "post", "delete"]:
            raise ValueError("Invalid requests method provided")
        
        if not self.headers:
            self._get_headers()
        
        return requests.request(
            method=method, url=url, headers=self.headers, **kwargs
        )

    def _quarantaine_endpoint(self, endpoint_id:str) -> requests.request:
        """
        Put an endpoint in the Quarantaine policy based on its MAC address
        :param mac_address: MAC address of the endpoint to quarantaine - required
        :rtype: None
        """
        # We need first to put the endpoint in a temporary policy to make the port bounce
        url = f"{self.cortex_url}/public_api/v1/endpoints/isolate/"
        payload = {"request_data": {"endpoint_id": endpoint_id}}
        return self._request(
            method="post",
            url=url,
            json=payload,
        )

    def _unquarantaine_endpoint(self, endpoint_id:str) -> requests.request:
        """
        Remove an endpoint from the Quarantaine policy based on its MAC address
        :param mac_address: MAC address of the endpoint to unquarantaine - required
        :rtype: Requests.Response
        """
        url = f"{self.cortex_url}/public_api/v1/endpoints/unisolate/"
        payload = {"request_data":{"filters": [{"field": "endpoint_id_list", "operator": "in", "value": [endpoint_id]}]}}
        return self._request(
            method="post",
            url=url,
            json=payload,
        )

    def _get_endpoint_id(self, ip_address:str):
        url = f"{self.cortex_url}/public_api/v1/endpoints/get_endpoint/"
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
            url=url,
            json=payload,
        )
        response = r.json()["reply"]
        for endpoint in response["endpoints"]:
            # We assume the endpoint is online if it was detected, and this avoids the issue of pending actions (see README)
            if endpoint['endpoint_status'] == "CONNECTED":
                if endpoint["is_isolated"] == 'AGENT_UNISOLATED':
                    return endpoint["endpoint_id"]
        return None