import logging
from datetime import datetime

import requests
from common import _get_password
from third_party_clients.third_party_interface import (
    ThirdPartyInterface,
    VectraAccount,
    VectraDetection,
    VectraHost,
    VectraStaticIP,
)
from third_party_clients.ubiquiti.ubiquiti_config import (
    CHECK_SSL,
    URL,
)

import keyring


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
    def __init__(self, **kwargs):
        """
        Initialize Watchguard client
        :param url: FQDN or IP of WatchGuard appliance - required
        :param user: Username to authenticate to ISR - required
        :param password: Password to authenticate to WatchGuard - required
        :param verify: Verify SSL (default: False) - optional
        """
        self.name = "WatchGuard Client"
        self.module = "watchguard"
        self.init_log(kwargs)
        self.account_id = _get_password(
            "WatchGuard", "Account_ID", modify=kwargs["modify"]
        )
        self.password = _get_password("WatchGuard", "Password", modify=kwargs["modify"])
        self.url = "https://" + URL
        self.access_id = _get_password(
            "WatchGuard", "Access_ID", modify=kwargs["modify"]
        )
        self.auth = (self.access_id, self.password)
        self.verify = CHECK_SSL

        self.access_token = ""
        self.headers["Authorization"] = f"Bearer {self.access_token}"
        self.headers["Content-Type"] = "application/json"
        self.headers["WatchGuard-API-Key"] = self.api_key

        # Instantiate parent class
        ThirdPartyInterface.__init__(self)

    def init_log(self, kwargs):
        dict_config = kwargs.get("dict_config", {})
        dict_config["loggers"].update({self.name: dict_config["loggers"]["VAR"]})
        logging.config.dictConfig(dict_config)
        self.logger = logging.getLogger(self.name)

    @request_error_handler
    def get_token(self):
        url = self.url + "/oauth/token"
        payload = "grant_type=client_credentials&scope=api-access"

        headers = (
            {
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        response = requests.post(
            url=url,
            headers=headers,
            auth=self.auth,
            data=payload,
        )

        self.access_token = response.json()["access_token"]
        token_dict = {
            "access_token": self.access_token,
            "expiry": datetime.now().strftime("%Y%m%d-%H:%M"),
        }
        keyring.set_password("WatchGuard", "Token_Dict", token_dict)

    def check_token(self):
        token_dict = keyring.get_password("WatchGuard", "Token_Dict")
        if token_dict is not None:
            old_time = datetime.strptime(token_dict["expiry"], "%Y%m%d-%H:%M")
            delta = datetime.now() - old_time
            if delta < 3600:
                self.access_token = token_dict["access_token"]
            else:
                self.get_token()
        else:
            self.get_token()

    def block_host(self, host: VectraHost):
        device_id = self._get_device_id(host)
        self._quarantine_endpoint(device_id)
        return device_id

    def unblock_host(self, host: VectraHost):
        device_ids = host.blocked_elements.get(self.name, [])
        for device_id in device_ids:
            self._unquarantaine_endpoint(device_id)
        return device_id

    def groom_host(self, host: VectraHost) -> dict:
        self.logger.warning("This client does not implement host grooming")
        return []

    def block_account(self, account: VectraAccount) -> list:
        # this client only implements Host-based blocking
        self.logger.warning("This client does not implement account-based blocking")
        return []

    def unblock_account(self, account: VectraAccount) -> list:
        # this client only implements Host-based blocking
        self.logger.warning("This client does not implement account-based blocking")
        return []

    def block_detection(self, detection: VectraDetection):
        # this client only implements Host-based blocking
        self.logger.warning("This client does not implement detection-based blocking")
        return []

    def unblock_detection(self, detection: VectraDetection):
        # this client only implements Host-based blocking
        self.logger.warning("This client does not implement detection-based blocking")
        return []

    def block_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        self.logger.warning("This client does not implement static IP-based blocking")
        return []

    def unblock_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        self.logger.warning("This client does not implement static IP-based blocking")
        return []

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
            self.check_token()
            url = self.url + suffix
            return requests.request(
                method=method,
                url=url,
                headers=self.headers,
                json=payload,
                verify=self.verify,
            )

    def _quarantine_endpoint(self, device_id):
        """
        Isolate an endpoint based on the device_id
        :param device_id: Device ID of the endpoint to quarantaine - required
        :rtype: None
        """
        suffix = f"/rest/endpoint-security/management/api/v1/accounts/{self.account_id}/devices/isolation"
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
        suffix = f"/rest/endpoint-security/management/api/v1/accounts/{self.account_id}/devices/noisolation"
        payload = {"device_ids": [device_id]}

        self._request(
            method="post",
            suffix=suffix,
            payload=payload,
        )

    def _get_device_id(self, host):
        suffix = f"/rest/endpoint-security/management/api/v1/accounts/{self.account_id}/devices?$search={host.ip}"
        response = self._request(
            method="get",
            suffix=suffix,
        )
        return response.json()["data"[0]["device_id"]]
