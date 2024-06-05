import json
import logging

import requests
from third_party_clients.mcafee_epo.mcafee_config import (
    MCAFEE_HOSTNAME,
    MCAFEE_PORT,
    MCAFEE_TAGID,
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


class Client:
    """Communicate with an ePO server.
    Instances are callable, pass a command name and parameters to make
    API calls.
    """

    def __init__(self, **kwargs):
        self.name = "McAfee EPO Client"
        """Create a client for the given ePO server.

        :param url: Location of ePO server.
        :param username: Username to authenticate.
        :param password: Password to authenticate.
        
        """
        self.hostname = MCAFEE_HOSTNAME
        self.port = MCAFEE_PORT
        self.url = f"https://{self.hostname}:{self.port}"
        self.username = _get_password("McAfee", "Username", modify=kwargs["modify"])
        self.password = _get_password("McAfee", "Password", modify=kwargs["modify"])
        self.tagID = MCAFEE_TAGID
        self._token = None
        self.logger = logging.getLogger("McAfee")

    def _get_token(self, _skip=False):
        """Get the security token if it's not already cached.
        :param bool _skip: Used internally when making the initial
            request to get the token.
        """
        if self._token is None and not _skip:
            self._token = self._request("core.getSecurityToken")
        return self._token

    @request_error_handler
    def _request(self, command, **kwargs):
        """Format the request and interpret the response.
        :param command: ePO command name to call.
        :param kwargs: Arguments passed to :meth:`requests.request`.
        :return: Deserialized JSON data.
        """
        kwargs.setdefault("auth", (self.username, self.password))
        params = kwargs.setdefault("params", {})
        # Check whether the response will be JSON.
        is_json = params.setdefault(":output", "json") == "json"
        # Add the security token, unless this is the request to get it.
        params.setdefault(
            "orion.user.security.token",
            self._get_token(_skip=command == "core.getSecurityToken"),
        )
        url = self.url + f"/remote/{command}"

        if any(kwargs.get(key) for key in ("data", "json", "files")):
            # Use post method if there is post data.
            response = requests.post(url, **kwargs)
        else:
            response = requests.get(url, **kwargs)

        # Strip "OK:" from response and parse JSON if needed.
        return response.json()

    def __call__(self, command, *args):
        """Make an API call by calling this instance.

        Collects arguments and calls :meth:`_request`.

        ePO commands take positional and named arguments. Positional
        arguments are internally numbered "param#" and passed as named
        arguments.

        Files can be passed to some commands. Pass a dictionary of
        ``'filename': file-like objects``, or other formats accepted by
        :meth:`requests.request`. This command will not open files, as
        it is better to manage that in a ``with`` block from the calling
        code.

        :param command: ePO command name to call.
        :param args: Positional arguments to the command.
        :param dict params: Named arguments that are not valid Python
            names can be provided here.
        :return: Deserialized JSON data.
        """
        params = {}

        for i, item in enumerate(args, start=1):
            params["param{}".format(i)] = item

        self._request(command, params=params)

    def block_host(self, host):
        if host.ip != "":
            self._quarantine_ip_endpoint(host.ip)
        return host.ip

    def unblock_host(self, host):
        self._unquarantaine_ip_endpoint(host.ip)
        return host.ip

    def groom_host(self, host) -> dict:
        self.logger.warning("McAfee client does not implement host grooming")
        return []

    def block_detection(self, detection):
        # this client only implements Host-based blocking
        self.logger.warn("McAfee client does not implement detection-based blocking")
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

    # McAfee ePO Host Isolation
    def _quarantine_ip_endpoint(self, ip_address):
        self.__call__("system.applyTag", ip_address, self.tagID)

    def _unquarantine_ip_endpoint(self, ip_address):
        self.__call__("system.clearTag", ip_address, self.tagID)
