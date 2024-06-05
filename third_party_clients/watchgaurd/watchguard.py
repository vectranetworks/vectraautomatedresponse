import logging

import requests
from third_party_clients.third_party_interface import (
    ThirdPartyInterface,
    VectraAccount,
    VectraDetection,
    VectraHost,
    VectraStaticIP,
)
from third_party_clients.ubiquiti.ubiquiti_config import (
    WATCHGUARD_URL,
)

from common import _get_password


def request_error_handler(func):
    """
    Decorator to handle request results and raise if not HTTP success
    :rtype: Requests.Response or Exception
    """

    def request_handler(self, *args, **kwargs):
        response = func(self, *args, **kwargs)
        if response.status_code in [200, 201, 204]:
            return response
        # 401 error is provided if token has expired
        # tokens expire after an hour
        elif response.status_code == 401:
            self.get_token()
        # Handle the weird Cisco 500 error code that is actually a success
        elif response.status_code == 500:
            try:
                # Might raise an error
                r = response.json()
                # Might raise a KeyError
                if r["ERSResponse"]["messages"][0]["title"] == "Radius Failure":
                    # If we're in the weird case, we consider it a success
                    response.status_code = 200
                    return response
                else:
                    raise HTTPException(response.status_code, response.content)
            except HTTPException:
                raise HTTPException(response.status_code, response.content)
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
        self.name = "WatchGuard Client"
        """
        Initialize Watchguard client
        :param url: FQDN or IP of WatchGuard appliance - required
        :param user: Username to authenticate to ISR - required
        :param password: Password to authenticate to WatchGuard - required
        :param verify: Verify SSL (default: False) - optional
        """
        self.watchguard_account_id = _get_password(
            "WatchGuard", "Account_ID", modify=kwargs["modify"]
        )
        self.watchguard_api_key = _get_password(
            "WatchGuard", "API_Key", modify=kwargs["modify"]
        )
        self.watchguard_password = _get_password(
            "WatchGuard", "Password", modify=kwargs["modify"]
        )
        self.watchguard_url = WATCHGUARD_URL
        self.watchguard_user = _get_password(
            "WatchGuard", "Username", modify=kwargs["modify"]
        )
        self.auth = (self.watchguard_user, self.watchguard_password)
        self.verify = False

        self.headers = (
            {
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )

        @request_error_handler
        def get_token(self):
            url = self.watchguard_url + "/oauth/token"
            payload = "grant_type=client_credentials&scope=api-access"

            response = requests.post(
                url=url,
                headers=self.headers,
                auth=self.auth,
                data=payload,
            )

            token = response.json()["access_token"]
            self.headers["Authorization"] = f"Bearer {token}"
            self.headers["Content-Type"] = "application/json"
            self.headers["WatchGuard-API-Key"] = self.watchdog_api_key

        self.get_token()

        # Instantiate parent class
        ThirdPartyInterface.__init__(self)

    @request_error_handler
    def _request(
        self,
        method,
        suffix,
        payload={},
    ):
        """
        Do a get request on the provided URL
        :rtype: requests.Response
        """
        if method not in ["get", "put", "post"]:
            raise ValueError("Invalid requests method provided")

        else:
            url = self.watchguard_url + suffix
            return requests.request(
                method=method,
                url=url,
                headers=self.headers,
                json=payload,
                verify=self.verify,
            )

    def block_host(self, host):
        device_id = self._get_device_id(host)
        self._quarantine_endpoint(device_id)
        return device_id

    def unblock_host(self, host):
        device_ids = host.blocked_elements.get(self.name, [])
        for device_id in device_ids:
            self._unquarantaine_endpoint(device_id)
        return device_id

    def groom_host(self, host) -> dict:
        self.logger.warning("This client does not implement host grooming")
        return []

    def block_detection(self, detection):
        # this client only implements Host-based blocking
        self.logger.warn("This client does not implement detection-based blocking")
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

    def _quarantine_endpoint(self, device_id):
        """
        Isolate an endpoint based on the device_id
        :param device_id: Device ID of the endpoint to quarantaine - required
        :rtype: None
        """
        suffix = f"/rest/endpoint-security/management/api/v1/accounts/{self.watchguard_account_id}/devices/isolation"
        payload = {
            "device_ids": [device_id],
            # "exclusion_programs": ["Chrome.exe"],
            "customized_message": "VAE Blocked",
            "hide_customized_alert": "false",
        }

        self._request(
            method="post",
            suffix=suffix,
            payload=payload,
        )

    def _unquarantine_endpoint(self, device_id):
        """
        Unisolate an endpoint based on the device_id
        :param device_id: Device ID of the endpoint to quarantaine - required
        :rtype: None
        """
        suffix = f"/rest/endpoint-security/management/api/v1/accounts/{self.watchguard_account_id}/devices/noisolation"
        payload = {"device_ids": [device_id]}

        self._request(
            method="post",
            suffix=suffix,
            payload=payload,
        )

    def _get_device_id(self, host):
        suffix = f"/rest/endpoint-security/management/api/v1/accounts/{self.watchguard_account_id}/devices?$search={host.ip}"
        response = self._request(
            method="get",
            suffix=suffix,
        )
        return response.json()["data"[0]["device_id"]]
