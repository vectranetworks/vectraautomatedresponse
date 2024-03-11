import json
import logging
import re
import sys
import time

import requests
import xmltodict
from third_party_clients.cisco_ise.ise_config import (
    CHECK_SSL,
    ENHANCED,
    ISE_APPLIANCE_IP,
    PORTBOUNCE_POLICY,
    QUARANTAINE_POLICY,
)
from third_party_clients.third_party_interface import (
    ThirdPartyInterface,
    VectraAccount,
    VectraDetection,
    VectraHost,
    VectraStaticIP,
)

from vectra_automated_response import _get_password

SUCCESS_CODES = [200, 201, 202, 203, 204]


def fetch_csrf(func):
    # CSRF is only used with ERS calls
    def _fetch_csrf(self, *args, **kwargs):
        if ENHANCED:
            try:
                headers = {**self.ers_headers, **{"X-CSRF-TOKEN": "fetch"}}
                result = requests.get(
                    "{}:9060/ers/config/ancendpoint/versioninfo".format(self.url),
                    auth=self.auth,
                    headers=headers,
                    verify=self.verify,
                )
                kwargs = {
                    "headers": {"x-csrf-token": result.headers["X-CSRF-Token"]},
                    "cookies": result.cookies,
                }
                return func(self, *args, **kwargs)
            except KeyError:
                if "X-CSRF-Token" not in result.headers:
                    self.logger.warn(
                        "CSRF Token not returned. Ensure CSRF is configured for the ISE API."
                    )
                    sys.exit()
        else:
            return func(self, *args, **kwargs)

    return _fetch_csrf


class HTTPException(Exception):
    pass


def _format_url(url):
    if ":/" not in url:
        url = "https://" + url
    else:
        url = re.sub("^.*://?", "https://", url)
    url = url[:-1] if url.endswith("/") else url
    return url


class Client(ThirdPartyInterface):
    def __init__(self, **kwargs):
        self.name = "ISE Client"
        """
        Initialize Cisco ISE client
        :param url: FQDN or IP of ISE appliance - required
        :param user: Username to authenticate to ISR - required
        :param password: Password to authenticate to ISE - required
        :param verify: Verify SSL (default: False) - optional
        """
        self.logger = logging.getLogger("ISE")
        self.url = f"{_format_url(ISE_APPLIANCE_IP)}"
        self.auth = (
            _get_password("Cisco_ISE", "Username", modify=kwargs["modify"]),
            _get_password("Cisco_ISE", "Password", modify=kwargs["modify"]),
        )
        self.verify = CHECK_SSL
        self.portbounce_policy = PORTBOUNCE_POLICY
        self.quarantine_policy = QUARANTAINE_POLICY
        self.ers_headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        self.mnt_headers = {
            "Accept": "application/xml",
            "Content-Type": "application/xml",
        }
        # Instantiate parent class
        ThirdPartyInterface.__init__(self)

    def block_host(self, host):
        blocked_macs = []
        mac_addresses = set(host.mac_addresses)
        # Check if the current MAC is already known
        try:
            mac_address_list = self._get_mac_from_ip(host.ip)
            for mac_address in mac_address_list:
                mac_addresses.add(mac_address)
        except HTTPException:
            pass
        # Iterate through all known MAC addresses
        for mac_address in mac_addresses:
            mac = self._quarantaine_endpoint(mac_address)
            if mac is not None:
                blocked_macs.append(mac)
        return blocked_macs

    def unblock_host(self, host):
        unblocked_macs = []
        mac_addresses = host.blocked_elements.get(self.name, [])
        for mac_address in mac_addresses:
            mac = self._unquarantaine_endpoint(mac_address)
            if mac is not None:
                unblocked_macs.append(mac)
        return unblocked_macs

    def groom_host(self, host) -> dict:
        self.logger.warning("ISE client does not implement host grooming")
        return []

    def block_detection(self, detection):
        # this client only implements Host-based blocking
        self.logger.warn("ISE client does not implement detection-based blocking")
        return []

    def unblock_detection(self, detection):
        # this client only implements Host-based blocking
        self.logger.warn("ISE client does not implement detection-based blocking")
        return []

    def block_account(self, account: VectraAccount) -> list:
        # this client only implements Host-based blocking
        self.logger.warn("ISE client does not implement account-based blocking")
        return []

    def unblock_account(self, account: VectraAccount) -> list:
        # this client only implements Host-based blocking
        self.logger.warn("ISE client does not implement account-based blocking")
        return []

    def block_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        return []

    def unblock_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        return []

    def _quarantaine_endpoint(self, mac_address):
        """
        Put an endpoint in the Quarantaine policy based on its MAC address
        :param mac_address: MAC address of the endpoint to quarantaine - required
        :rtype: None
        """
        # We need first to put the endpoint in a temporary policy to make the port bounce
        try:
            self.logger.debug(
                "Applying portbounce policy to {mac}".format(mac=mac_address)
            )
            self._add_mac_to_policy(mac_address, self.portbounce_policy)
        except HTTPException:
            pass
        time.sleep(1)
        # Then we push the endpoint in the actual quarantaine policy
        self.logger.debug("Applying quarantine policy to {mac}".format(mac=mac_address))
        return self._add_mac_to_policy(mac_address, self.quarantine_policy)

    @fetch_csrf
    def _unquarantaine_endpoint(self, mac_address, **kwargs):
        """
        Remove an endpoint from the Quarantaine policy based on its MAC address
        :param mac_address: MAC address of the endpoint to unquarantaine - required
        :rtype: Requests.Response
        """
        payload = {
            "OperationAdditionalData": {
                "additionalData": [
                    {"name": "macAddress", "value": mac_address},
                    {"name": "policyName", "value": self.quarantine_policy},
                ]
            }
        }

        response = requests.put(
            "{url}:9060/ers/config/ancendpoint/clear".format(url=self.url),
            auth=self.auth,
            headers=(
                {**self.ers_headers, **kwargs["headers"]}
                if "headers" in kwargs
                else self.ers_headers
            ),
            json=payload,
            verify=self.verify,
            cookies=kwargs["cookies"] if "cookies" in kwargs else None,
        )
        if response.content.decode() == "":
            msg = response
        else:
            msg = response.content
        self.logger.debug(f"Unblock response: {msg}")
        if response.status_code in SUCCESS_CODES:
            return mac_address
        elif response.status_code == 403 and ENHANCED is False:
            self.logger.warn(
                "{msg}. ISE is CSRF enabled but script is not. Validate ise_config.py.".format(
                    msg=response.content.decode().split("<")[0]
                )
            )
        elif response.json()["ERSResponse"]["messages"][0]["title"] == "Radius Failure":
            return mac_address
        else:
            self.logger.warn(
                f'Unable to unblock {mac_address}: {response.json()["ERSResponse"]["messages"][0]["title"]}'
            )

    @fetch_csrf
    def _add_mac_to_policy(self, mac_address, policy_name, **kwargs):
        """
        Put an endpoint in a temporary policy based on its MAC address
        :param mac_address: the MAC address of the endpoint - required
        :param policy_name: name of the policy to add the endpoint to
        :rtype: Requests.Response
        """
        payload = {
            "OperationAdditionalData": {
                "additionalData": [
                    {"name": "macAddress", "value": mac_address},
                    {"name": "policyName", "value": policy_name},
                ]
            }
        }

        response = requests.put(
            "{url}:9060/ers/config/ancendpoint/apply".format(url=self.url),
            auth=self.auth,
            headers=(
                {**self.ers_headers, **kwargs["headers"]}
                if "headers" in kwargs
                else self.ers_headers
            ),
            json=payload,
            verify=self.verify,
            cookies=kwargs["cookies"] if "cookies" in kwargs else None,
        )

        self.logger.debug(f"Block response: {response.content}")
        if response.status_code in SUCCESS_CODES:
            return mac_address
        elif response.status_code == 403 and ENHANCED is False:
            self.logger.warn(
                "{msg}. ISE is CSRF enabled but script is not. Validate ise_config.py.".format(
                    msg=response.content.decode().split("<")[0]
                )
            )
        elif response.json()["ERSResponse"]["messages"][0]["title"] == "Radius Failure":
            return mac_address
        else:
            self.logger.warn(
                f'Unable to block {mac_address}: {response.json()["ERSResponse"]["messages"][0]["title"]}'
            )

    def _get_mac_from_ip(self, ip_address, **kwargs):
        """
        Get the MAC address of an endpoint based on its last IP
        :param ip_address: IP Address to get the MAC address for
        :rtype: string
        """
        mac_address_list = []
        r = requests.get(
            "{url}/admin/API/mnt/Session/ActiveList".format(
                url=self.url,
            ),
            auth=self.auth,
            verify=False,
            headers=(
                {**self.mnt_headers, **kwargs["headers"]}
                if "headers" in kwargs
                else self.mnt_headers
            ),
            cookies=kwargs["cookies"] if "cookies" in kwargs else None,
        )

        self.logger.debug(f"Get Mac from IP response: {r.content}")
        if r.status_code not in SUCCESS_CODES:
            raise HTTPException("No Session on ISE for IP {}".format(ip_address))
        else:
            xml = json.loads(json.dumps(xmltodict.parse(r.text)))
            for session in xml["activeList"]["activeSession"]:
                try:
                    if ip_address in session["ipAddresses"]:
                        mac_address_list.append(session["calling_station_id"])
                except KeyError:
                    pass

            return mac_address_list
