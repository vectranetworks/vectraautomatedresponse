import io
import logging

import requests
import xmltodict
from common import _get_password
from third_party_clients.pan.pan_config import (
    CHECK_SSL,
    EXTERNAL_BLOCK_TAG,
    INTERNAL_BLOCK_TAG,
    URLS,
)
from third_party_clients.third_party_interface import (
    ThirdPartyInterface,
    VectraAccount,
    VectraDetection,
    VectraHost,
    VectraStaticIP,
)

import keyring


class Client(ThirdPartyInterface):
    def __init__(self, **kwargs):
        self.name = "PAN Client"
        self.module = "pan"
        self.init_log(kwargs)
        self.firewalls = []
        for url in URLS:
            self.firewalls.append(
                {
                    "url": url,
                    "api_key": self._get_api_token(
                        pan_url=url, modify=kwargs["modify"]
                    ),
                }
            )
        self.verify = CHECK_SSL
        self.internal_block_tag = INTERNAL_BLOCK_TAG
        self.external_block_tag = EXTERNAL_BLOCK_TAG
        # Instantiate parent class
        ThirdPartyInterface.__init__(self)

    def init_log(self, kwargs):
        dict_config = kwargs.get("dict_config", {})
        dict_config["loggers"].update({self.name: dict_config["loggers"]["VAR"]})
        logging.config.dictConfig(dict_config)
        self.logger = logging.getLogger(self.name)

    def block_host(self, host: VectraHost) -> list:
        ip_address = host.ip
        for firewall in self.firewalls:
            self._register_address(firewall, [ip_address], self.internal_block_tag)
        return [ip_address]

    def block_account(self, account: VectraAccount) -> list:
        self.logger.warning("PAN client does not implement account blocking")
        return []

    def unblock_host(self, host: VectraHost) -> list:
        ip_addresses = host.blocked_elements.get(self.name, [])
        if len(ip_addresses) < 1:
            self.logger.error("No IP address found for host {}".format(host.name))
        for firewall in self.firewalls:
            self._unregister_address(firewall, ip_addresses, self.internal_block_tag)
        return ip_addresses

    def unblock_account(self, account: VectraAccount) -> list:
        self.logger.warning("PAN client does not implement account blocking")
        return []

    def groom_host(self, host) -> dict:
        self.logger.warning("PAN client does not implement host grooming")
        return []

    def block_detection(self, detection: VectraDetection) -> list:
        ip_addresses = detection.dst_ips
        for firewall in self.firewalls:
            self.register_address(firewall, ip_addresses, self.external_block_tag)
        return ip_addresses

    def unblock_detection(self, detection: VectraDetection) -> list:
        ip_addresses = detection.blocked_elements.get(self.name, [])
        if len(ip_addresses) < 1:
            self.logger.error(
                "No IP address found for Detection ID {}".format(detection.id)
            )
        for firewall in self.firewalls:
            self.unregister_address(firewall, ip_addresses, self.external_block_tag)
        return ip_addresses

    def block_static_dst_ips(self, ips: VectraStaticIP) -> list:
        ip_addresses = ips.dst_ips
        self.logger.info(
            "Received static IPs: {} for PAN to block".format(ip_addresses)
        )
        for firewall in self.firewalls:
            self.register_address(firewall, ip_addresses, self.external_block_tag)
        return ip_addresses

    def unblock_static_dst_ips(self, ips: VectraStaticIP) -> list:
        ip_addresses = ips.dst_ips
        self.logger.info("Received IPs: {} for PAN to unblock".format(ip_addresses))
        if len(ip_addresses) < 1:
            self.logger.error("No IP addresses supplied for static destination unblock")
        for firewall in self.firewalls:
            self.unregister_address(firewall, ip_addresses, self.external_block_tag)
        return ip_addresses

    def _get_api_token(self, pan_url, modify=False):
        api_token = _get_password(pan_url, "API_Key", modify=modify)
        if not api_token or modify:
            username = _get_password(pan_url, "username", modify=modify)
            password = _get_password(pan_url, "password", modify=modify)
            payload = {"user": username, "password": password}

        self.logger.info(
            f"Attemmpting connection to PAN endpoint: {pan_url}"
        )
        r = requests.post(
            url=f"{pan_url}/api/?type=keygen",
            data=payload,
            verify=False,
            timeout=(10, None)  # Adding 10 secondes connection timeout for unreachable FWs
        )
        response = xmltodict.parse(r.content)
        api_token = response["response"]["result"]["key"]
        self.logger.info(
            f"Connection to {pan_url} and API token generation succesful!"
        )
        keyring.set_password(
            service_name=pan_url, username="API_Key", password=api_token
        )
        return api_token

    def _register_address(self, firewall, ip_addresses, tag):
        """
        Register IP addresses with firewall based on tag
        :param firewall: PAN dict {'url': 'https://1.2.3.4', 'api_key'= 'abc1234'}
        :param ip_addresses: list of IP address of the endpoint to quarantine
        :param tag: the PAN tag to register address with
        :rtype: requests.Response
        """
        command = (
            "<uid-message><version>1.0</version><type>update</type><payload><register>"
            + "".join(
                [
                    '<entry ip="{}"><tag><member>{}</member></tag></entry>'.format(
                        ip, tag
                    )
                    for ip in ip_addresses
                ]
            )
            + "</register></payload></uid-message>"
        )

        payload = {"type": "user-id", "key": firewall["api_key"], "cmd": command}
        r = requests.post(
            url="{}/api/".format(firewall["url"]),
            data=payload,
            verify=self.verify,
        )

        if r.status_code in [200, 201]:
            self.logger.info(
                "Registered IP(s):{} with firewall {}".format(
                    ip_addresses, firewall["url"]
                )
            )
            return ip_addresses
        else:
            self.logger.info(
                "Unable to registered IP(s):{} with firewall {}".format(
                    ip_addresses, firewall["url"]
                )
            )
            return []

    def _unregister_address(self, firewall, ip_addresses, tag):
        """
        Unregister IP addresses with firewall based on tag
        :param firewall: PAN dict {'url': 'https://1.2.3.4', 'api_key'= 'abc1234'}
        :param ip_addresses: list of IP address of the endpoint to quarantine
        :param tag: the PAN tag to register address with
        :rtype: requests.Response
        """
        command = (
            "<uid-message><version>1.0</version><type>update</type><payload><unregister>"
            + "".join(
                [
                    '<entry ip="{}"><tag><member>{}</member></tag></entry>'.format(
                        ip, tag
                    )
                    for ip in ip_addresses
                ]
            )
            + "</unregister></payload></uid-message>"
        )

        payload = {"type": "user-id", "key": firewall["api_key"], "cmd": command}

        r = requests.post(
            url="{}/api/".format(firewall["url"]),
            data=payload,
            verify=self.verify,
        )
        if r.status_code in [200, 201]:
            self.logger.info(
                "Unregistered IP(s):{} with firewall {}".format(
                    ip_addresses, firewall["url"]
                )
            )
            return ip_addresses
        else:
            self.logger.info(
                "Unable to unregistered IP(s):{} with firewall {}".format(
                    ip_addresses, firewall["url"]
                )
            )
            return []
