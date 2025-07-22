import logging
import sys

import backoff
import requests
from common import _format_url, _get_password
from third_party_clients.harmony.harmony_config import (
    AUTH_URL,
    BASE_URL,
    CHECK_SSL,
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


class HTTPException(Exception):
    def __init__(self, response):
        """
        Custom exception class to report possible API errors
        The body is constructed by extracting the API error code from the requests.Response object
        """
        try:
            r = response.json()
            if "detail" in r:
                detail = r["detail"]
            elif "errors" in r:
                detail = r["errors"][0]["title"]
            elif "tree_structure" in r:
                detail = "\n".join(r["tree_structure"])
            elif "_meta" in r:
                detail = f'{r["_meta"]["message"]} - {r.content}'
            else:
                detail = response.content
        except Exception:
            detail = response.content
        body = f"Status code: {str(response.status_code)} - {detail}"
        super().__init__(body)


class HTTPUnauthorizedException(HTTPException):
    def __init__(self, response):
        super().__init__(response)


class HTTPForbidden(HTTPException):
    def __init__(self, response):
        super().__init__(response)


class HTTPUnprocessableContentException(HTTPException):
    def __init__(self, response):
        super().__init__(response)


class HTTPTooManyRequestsException(HTTPException):
    def __init__(self, response):
        super().__init__(response)


def request_error_handler(func):
    def request_handler(self, *args, **kwargs):
        response = func(self, *args, **kwargs)
        if response.status_code in [200, 201, 204]:
            return response
        elif response.status_code == 401:
            raise HTTPUnauthorizedException(response)
        elif response.status_code == 403:
            raise HTTPForbidden(response)
        elif response.status_code == 422:
            raise HTTPUnprocessableContentException(response)
        elif response.status_code == 429:
            raise HTTPTooManyRequestsException(response)
        else:
            if self._debug:
                print(response.request.url)
                print(response.request.headers)
                try:
                    print(response.request.data)
                except AttributeError:
                    print(response.request.body)
            raise HTTPException(response)

    return request_handler


class Client(ThirdPartyInterface):
    def __init__(self, **kwargs):
        self.name = "Harmony Client"
        self.module = "harmony"
        self.init_log(kwargs)
        self.auth_url = AUTH_URL
        self.base_url = (
            _format_url(BASE_URL) + "/app/endpoint-web-mgmt/harmony/endpoint/api"
        )
        self.api_key = _get_password("Harmony", "API_Key", modify=kwargs["modify"])
        self.verify = CHECK_SSL
        # Instantiate parent class
        ThirdPartyInterface.__init__(self)

    def init_log(self, kwargs):
        dict_config = kwargs.get("dict_config", {})
        dict_config["loggers"].update({self.name: dict_config["loggers"]["VAR"]})
        logging.config.dictConfig(dict_config)
        self.logger = logging.getLogger(self.name)

    def block_host(self, host: VectraHost):
        self._login()
        endpoint_id = self.get_host_id(host)
        endpoint_ids = self._isolate_endpoint(host, endpoint_id)

        return endpoint_ids

    def unblock_host(self, host: VectraHost):
        self._login()
        endpoint_ids = host.blocked_elements.get(self.name, [])
        unisolated_list = []
        for endpoint_id in endpoint_ids:
            unisolated = self._unisolate_endpoint(endpoint_id)
            if unisolated != "":
                unisolated_list.append(unisolated)

        return list(set(unisolated_list))

    def groom_host(self, host: VectraHost) -> dict:
        self.logger.warning("Harmony client does not implement host grooming")
        return []

    def block_detection(self, detection: VectraDetection):
        self.logger.warning("Harmony client does not implement detection blocking")
        return []

    def unblock_detection(self, detection: VectraDetection):
        self.logger.warning("Harmony client does not implement detection blocking")
        return []

    def block_account(self, account: VectraAccount) -> list:
        self.logger.warning("Harmony client does not implement account blocking")
        return []

    def unblock_account(self, account: VectraAccount) -> list:
        self.logger.warning("Harmony client does not implement account blocking")
        return []

    def block_static_dst_ips(self, ips: VectraStaticIP) -> list:
        self.logger.warning("Harmony client does not implement static IP-blocking")
        return []

    def unblock_static_dst_ips(self, ips: VectraStaticIP) -> list:
        self.logger.warning("Harmony client does not implement static IP-blocking")
        return []

    @backoff.on_exception(
        backoff.expo,
        (HTTPTooManyRequestsException),
        max_tries=5,
        max_time=60,
    )
    @request_error_handler
    def _request(self, method=None, url=None, headers=None, body=None):
        if method not in ["get", "patch", "put", "post", "delete"]:
            raise ValueError("Invalid requests method provided")
        return requests.request(method=method, url=url, headers=headers, json=body)

    def _get_bearer_token(self):
        self.headers = {
            "accept": "application/json",
            "content-type": "application/json",
        }
        data = {"clientID": self.api_key, "accessKey": self.api_key}
        self.bearer_token = self._request(
            method="post",
            url=self.auth_url,
            headers=self.headers,
            json=data,
            verify=self.verify,
        )

    def _login(self):
        self.get_bearer_token()
        # Only good for 6 minutes
        if not self.headers.get("Authorization", False):
            self.headers["Authorization"] = f"Bearer {self.bearer_token}"
        url = self.url + "/v1/session/login/cloud"
        headers = self.headers
        mgmt_token_dict = self._request(method="post", url=url, headers=headers).json()
        self.headers["x-mgmt-api-token"] = mgmt_token_dict["apiToken"]
        self.headers["x-mgmt-run-as-job"] = "ON"

    @request_error_handler
    def _isolate_endpoint(self, host, endpoint_id):
        url = self.url + "/v1/remediation/isolate"
        body = {
            "comment": "Vectra Automated Response - Isolated",
            "targets": {
                "include": {"computers": [{"id": endpoint_id}]},
            },
        }

        job_id = self._request(method="post", url=url, headers=self.headers, body=body)
        while True:
            resp = self.get_data_from_job(job_id)
            if resp.json()["status"] == "NOT_FOUND":
                self.logger.debug(f"Unable to find host {host.name}/{host.ip}.")
                return []
            elif resp.json()["status"] == "FAILED":
                self.logger.error(f"Failed to isolate host {host.name}/{host.ip}.")
                return []
            elif resp.json()["status"] == "DONE":
                self.logger.debug(f"Successfully isolated host {host.name}/{host.ip}.")
                return endpoint_id

    def _unisolate_endpoint(self, host, endpoint_id):
        url = self.url + "/v1/remediation/de-isolate"
        body = {
            "comment": "Vectra Automated Response - Unisolated",
            "targets": {
                "include": {"computers": [{"id": endpoint_id}]},
            },
        }
        job_id = self._request(method="post", url=url, headers=self.headers, body=body)

        while True:
            resp = self.get_data_from_job(job_id)
            if resp.json()["status"] == "NOT_FOUND":
                self.logger.debug(f"Unable to find host {host.name}/{host.ip}.")
                return []
            elif resp.json()["status"] == "FAILED":
                self.logger.error(f"Failed to unisolate host {host.name}/{host.ip}.")
                return []
            elif resp.json()["status"] == "DONE":
                self.logger.debug(
                    f"Successfully unisolated host {host.name}/{host.ip}."
                )
                return endpoint_id

    def get_host_id(self, host):
        url = self.url + "/v1/asset-management/computers/filtered"
        # by computer name
        body = {
            "filters": [
                {
                    "columnName": "computerName",
                    "filterValues": [host.name],
                    "filterType": "Contains",
                }
            ],
            "paging": {"pageSize": 10, "offset": 0},
        }
        job_id = self._request(method="post", url=url, headers=self.headers, body=body)

        while True:
            resp = self.get_data_from_job(job_id)
            if resp.json()["status"] == "NOT_FOUND":
                self.logger.debug("No computers found.")
                return []
            elif resp.json()["status"] == "FAILED":
                self.logger.error(
                    f"Failed to retrieve host ID for host {host.name}/{host.ip}."
                )
                return []
            elif resp.json()["status"] == "DONE":
                data = resp.json["data"]
                if len(data["computers"]) > 1:
                    self.logger.error(
                        f"Too many computers found for host {host.name}/{host.ip}."
                    )
                    return []
                elif len(data["computers"]) == 1:
                    return [data["computers"][0]["computerId"]]
                elif len(data["computers"]) < 1:
                    self.logger.error(
                        f"No computers found for host {host.name}/{host.ip}."
                    )
                    return []

    def get_data_from_job(self, job_id):
        url = self.url + f"/v1/jobs/{job_id}"
        return self._request(method="get", url=url, headers=self.headers)
