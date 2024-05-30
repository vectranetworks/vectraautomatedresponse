import base64
import json
import logging
import ssl
import time
import urllib

import requests
import urllib3
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from third_party_clients.cisco_pxgrid.pxgrid_config import (
    PXGRID_APPLIANCE_LIST,
    PXGRID_CA_BUNDLE,
    PXGRID_CERT,
    PXGRID_KEY,
    PXGRID_PORT,
    PXGRID_VERIFY,
    QUARANTAINE_POLICY,
)
from third_party_clients.third_party_interface import (
    ThirdPartyInterface,
    VectraAccount,
    VectraDetection,
    VectraHost,
    VectraStaticIP,
)

from common import _get_password

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def request_error_handler(func):
    """
    Decorator to handle request results and raise if not HTTP success
    :rtype: Requests.Response or Exception
    """

    def request_handler(self, *args, **kwargs):
        response = func(self, *args, **kwargs)
        if response.status_code in [200, 204]:
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


class Config:
    def __init__(self, **kwargs):
        self.__ssl_context = None
        self.pxgrid_appliance_list = PXGRID_APPLIANCE_LIST
        self.pxgrid_port = PXGRID_PORT
        self.username = _get_password(
            "Cisco_PxGrid", "Username", modify=kwargs["modify"]
        )
        self.password = _get_password(
            "Cisco_PxGrid", "Password", modify=kwargs["modify"]
        )
        self.clientcert = PXGRID_CERT
        self.clientkey = PXGRID_KEY
        if self.clientkey != "":
            self.clientkey_password = _get_password(
                "Cisco_PxGrid", "Priv_Key_Pass", modify=kwargs["modify"]
            )
        self.ca_bundle = PXGRID_CA_BUNDLE
        self.verify = PXGRID_VERIFY
        self.quarantine_policy = QUARANTAINE_POLICY
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def get_pxgrid_appliance_list(self):
        return self.pxgrid_appliance_list

    def get_pxgrid_port(self):
        return self.pxgrid_port

    def get_auth(self):
        return (self.username, self.password)

    def get_password(self):
        if self.password is not None:
            return self.password
        else:
            return ""

    def get_quarantine_policy(self):
        return self.quarantine_policy

    def get_headers(self):
        return self.headers

    def get_cert(self):
        return (self.clientcert, self.clientkey)

    def get_verify(self):
        if self.verify.lower() == "true":
            return True
        else:
            return False

    def get_description(self):
        return "Vectra Automated Response"

    def ssl_context(self):
        if self.__ssl_context is None:
            self.__ssl_context = ssl.create_default_context()
            if self.clientcert != "":
                self.__ssl_context.load_cert_chain(
                    certfile=self.clientcert,
                    keyfile=self.clientkey,
                    password=self.clientkey_password,
                )
            if self.ca_bundle != "":
                self.__ssl_context.load_verify_locations(cafile=self.ca_bundle)
            # elif not self.verify:
            elif not self.get_verify():
                self.__ssl_context.check_hostname = False
                self.__ssl_context.verify_mode = ssl.CERT_NONE
        return self.__ssl_context
        # return None


class PxgridControl:
    def __init__(self, config):
        self.config = config

    # Does not respond with a 200
    def send_rest_request(self, appliance, url_suffix, payload):
        url = f"https://{appliance}:{self.config.get_pxgrid_port()}/pxgrid/control/{url_suffix}"
        # full_url = f"https://{url}:{self.config.get_pxgrid_port()}/pxgrid/control/{url_suffix}"

        json_string = json.dumps(payload)
        handler = urllib.request.HTTPSHandler(context=self.config.ssl_context())
        opener = urllib.request.build_opener(handler)
        rest_request = urllib.request.Request(url=url, data=str.encode(json_string))
        # rest_request = urllib.request.Request(url=full_url, data=str.encode(json_string))
        rest_request.add_header("Content-Type", "application/json")
        rest_request.add_header("Accept", "application/json")
        username_password = "%s:%s" % (self.config.username, self.config.password)
        b64 = base64.b64encode(username_password.encode()).decode()
        rest_request.add_header("Authorization", "Basic " + b64)
        rest_response = opener.open(rest_request)
        response = rest_response.read().decode()
        return json.loads(response)

    def account_activate(self, appliance):
        payload = {}
        # Does not like a description
        if self.config.get_description() is not None:
            payload = {"description": self.config.get_description()}
        return self.send_rest_request(appliance, "AccountActivate", payload)

    def service_lookup(self, appliance, service_name):
        payload = {"name": service_name}
        return self.send_rest_request(appliance, "ServiceLookup", payload)

    def service_register(self, appliance, service_name, properties):
        payload = {"name": service_name, "properties": properties}
        return self.send_rest_request(appliance, "ServiceRegister", payload)

    def get_access_secret(self, appliance, peer_node_name):
        payload = {"peerNodeName": peer_node_name}
        return self.send_rest_request(appliance, "AccessSecret", payload)


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
        self.name = "PxGrid Client"
        """
        Initialize Cisco PXGRID client
        :param url: FQDN or IP of PXGRID appliance - required
        :param user: Username to authenticate to ISR - required
        :param password: Password to authenticate to PXGRID - required
        :param verify: Verify SSL (default: False) - optional
        """
        self.logger = logging.getLogger("PxGrid")
        self.config = Config(modify=kwargs["modify"])
        self.pxgrid = PxgridControl(config=self.config)
        self.enabled = False
        self.appliance_list = self.config.get_pxgrid_appliance_list()

        while not self.enabled:
            for appliance in self.appliance_list:
                if self.pxgrid.account_activate(appliance)["accountState"] == "ENABLED":
                    self.enabled = True
                    self.appliance = appliance
                    break
                else:
                    time.sleep(60 / len(self.appliance_list))

        # Instantiate parent class
        ThirdPartyInterface.__init__(self)

    @request_error_handler
    def _request(
        self,
        method,
        url,
        auth,
        payload,
    ):
        """
        Do a get request on the provided URL
        :rtype: requests.Response
        """
        if method not in ["get", "put", "post"]:
            raise ValueError("Invalid requests method provided")

        else:
            return requests.request(
                method=method,
                url=url,
                headers=self.config.get_headers(),
                auth=auth,
                json=payload,
                verify=self.config.get_verify(),
            )

    def block_host(self, host):
        if host.mac_addresses != []:
            mac_addresses = set(host.mac_addresses)
            # Check if the current MAC is already known
            try:
                mac_address = self._get_mac_from_ip(host.ip)
                for mac in mac_address:
                    mac_addresses.add(mac)
            except HTTPException:
                pass
        elif host.ip != "":
            try:
                mac_addresses = set(self._get_mac_from_ip(host.ip))
            except HTTPException:
                pass

        # Iterate through all known MAC addresses
        macs = []
        for mac_address in mac_addresses:
            result = self._quarantaine_endpoint(mac_address)
            if result:
                macs.append(mac_address)
        return macs

    def unblock_host(self, host):
        macs = []
        mac_addresses = host.blocked_elements.get(self.name, [])
        for mac_address in mac_addresses:
            result = self._unquarantaine_endpoint(mac_address)
            if result:
                macs.append(mac_address)
        return macs

    def groom_host(self, host) -> dict:
        self.logger.warning("PXGRID client does not implement host grooming")
        return []

    def block_detection(self, detection):
        # this client only implements Host-based blocking
        self.logger.warn("PXGRID client does not implement detection-based blocking")
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

    def _quarantaine_endpoint(self, mac_address):
        """
        Put an endpoint in the Quarantaine policy based on its MAC
        :param address: address of the endpoint to quarantaine - required
        :param key: type of address; "mac" or "ip" - required
        :rtype: None
        """
        return self._add_mac_to_policy(mac_address, self.config.quarantine_policy)

    def _unquarantaine_endpoint(self, mac_address):
        """
        Put an endpoint in the Quarantaine policy based on its MAC or IP address
        :param address: address of the endpoint to quarantaine - required
        :rtype: None
        """
        return self._rem_mac_from_policy(mac_address)

    def _add_mac_to_policy(self, mac_address, policy_name):
        """
        Put an endpoint in a temporary policy based on its MAC address
        :param mac_address: the MAC address of the endpoint - required
        :param policy_name: name of the policy to add the endpoint to
        :rtype: Requests.Response
        """
        service_lookup_response = self.pxgrid.service_lookup(
            self.appliance, "com.cisco.ise.config.anc"
        )
        services = service_lookup_response["services"]
        for service in services:
            node_name = service["nodeName"]
            url = service["properties"]["restBaseUrl"] + "/applyEndpointByMacAddress"

            payload = {"macAddress": mac_address, "policyName": policy_name}

            secret = self.pxgrid.get_access_secret(self.appliance, node_name)["secret"]

            response = self._request(
                method="post",
                url=url,
                auth=(self.config.username, secret),
                payload=payload,
            )

            self.logger.debug(f"Block response: {response.json()}")
            if response.status_code == 200:
                if response.json()["status"] != "FAILURE":
                    return True
                elif (
                    response.json()["failureReason"]
                    == "mac address is already associated with this policy"
                ):
                    return True
        self.logger.error(
            f"Failed to add host to policy {policy_name}. Reason: {response.json()['failureReason']}"
        )
        return False

    def _rem_mac_from_policy(self, mac_address):
        """
        Remove an endpoint from the Quarantaine policy based on its MAC address
        :param mac_address: MAC address of the endpoint to unquarantaine - required
        :rtype: Requests.Response
        """

        service_lookup_response = self.pxgrid.service_lookup(
            self.appliance, "com.cisco.ise.config.anc"
        )
        services = service_lookup_response["services"]
        for service in services:
            node_name = service["nodeName"]
            url = service["properties"]["restBaseUrl"] + "/clearEndpointByMacAddress"
            secret = self.pxgrid.get_access_secret(self.appliance, node_name)["secret"]

            payload = {
                "macAddress": mac_address,
            }

            response = self._request(
                method="post",
                url=url,
                auth=(self.config.username, secret),
                payload=payload,
            )

            self.logger.debug(f"Unblock response: {response.json()}")
            if response.status_code == 200 and response.json()["status"] != "FAILURE":
                return True
        self.logger.error(
            "Failed to remove host {} from blocking policy.".format(mac_address)
        )
        return False

    def _get_mac_from_ip(self, ip_address):
        """
        Get the MAC address of an endpoint based on its last IP
        :param ip_address: IP Address to get the MAC address for
        :rtype: string
        """
        mac_addresses = []
        service_lookup_response = self.pxgrid.service_lookup(
            self.appliance, "com.cisco.ise.session"
        )
        services = service_lookup_response["services"]
        for service in services:
            node_name = service["nodeName"]
            url = service["properties"]["restBaseUrl"] + "/getSessions"

            payload = {}

            secret = self.pxgrid.get_access_secret(self.appliance, node_name)["secret"]

            response = self._request(
                method="post",
                url=url,
                auth=(self.config.username, secret),
                payload=payload,
            )

            sessions = response.json()["sessions"]
            for session in sessions:
                self.logger.debug(f"_get_mac_from_ip: {session}")
                try:
                    if ip_address in session["ipAddresses"]:
                        mac_addresses.append(session["macAddress"])
                except KeyError:
                    pass

            return mac_addresses
