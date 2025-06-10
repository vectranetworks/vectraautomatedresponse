import logging
import requests

from common import _get_password
from third_party_clients.deepinstinct_edr.deepinstinct_edr_config import (
    BASE_URL,
    VERIFY,
)
from third_party_clients.third_party_interface import (
    ThirdPartyInterface,
    VectraAccount,
    VectraDetection,
    VectraHost,
    VectraStaticIP,
)


class Client(ThirdPartyInterface):
    def __init__(self, **kwargs):
        self.name = "DeepInstinctEDR Client"
        self.module = "deepinstinct_edr"
        self.init_log(kwargs)
        self.url = BASE_URL
        self.verify = VERIFY
        self.apikey = _get_password("DeepInstinctEDR", "apikey", modify=kwargs["modify"])
        self.headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.apikey
        }
        ThirdPartyInterface.__init__(self)

    def init_log(self, kwargs):
        dict_config = kwargs.get("dict_config", {})
        dict_config["loggers"].update({self.name: dict_config["loggers"]["VAR"]})
        logging.config.dictConfig(dict_config)
        self.logger = logging.getLogger(self.name)

    def search_device(self, host: VectraHost) -> list:
        """
        Searches for computer first by IP addresses
        :param host:VectraHost: vectra host object to search for
        :return: list of endpoint IDs
        """
        # Search via IP
        request_url = f'https://{self.url}/api/v1/devices/search'
        payload = {"ip_address": host.ip,  "connectivity_status": ["ONLINE"]}
        response = requests.post(request_url, headers=self.headers, json=payload)

        if response.status_code == 200:
            devices = response.json().get("devices", [])
            if len(devices) != 1:
                self.logger.error(
                    "Found no device or multiple devices with same IP. Aborting!"
                )
                return False
            else:
                device = devices[0]
                # check device name(including domainname) vs hostname
                if not f"{device.get('hostname')}.{device.get('domain')}".lower().startswith(
                    host.name.lower()
                ):
                    self.logger.error(
                        f"Device name {device.get('name')}.{device.get('domainDnsName')} \
                            does not match Vectra hostname {host.name}!"
                    )
                    return False
                else:
                    self.logger.info("Device name matches Vectra host name")
                    return device

    def block_host(self, host: VectraHost) -> list:
        device = self.search_device(host)
        if not device:
            return []
        log_string = f"{host.name} with id {device['id']} and IP {host.ip}"

        self.logger.info(f"Requesting DeepInstinctEDR isolation for {log_string}")
        request_url = f'https://{self.url}/api/v1/devices/actions/isolate-from-network'
        payload = {'ids': [device['id']]}

        try:
            response = requests.post(request_url, headers=self.headers, json=payload)
        except Exception as e:
            self.logger.debug(f"DeepInstinctEDR isolation failed with status: {e}")
            response = False

        if response:
            self.logger.info(f"Successfully isolated {log_string}")
            return [device["id"]]
        else:
            self.logger.info(f"Unable to isolate {log_string}")
            return []

    def unblock_host(self, host: VectraHost) -> list:
        device_ids = host.blocked_elements.get(self.name, [])
        un_isolated = []
        request_url = f'https://{self.url}/api/v1/devices/actions/release-from-isolation'
        if device_ids:
            for device_id in device_ids:
                log_string = f"{host.name} with id {device_id} and IP {host.ip}"
                payload = {'ids': [int(device_id)]}

                try:
                    response = requests.post(request_url, headers=self.headers, json=payload)
                except Exception as e:
                    self.logger.debug(f"DeepInstinctEDR isolation failed with status: {e}")
                    response = False

                self.logger.info(f"Requesting DeepInstinctEDR un-isolation for {log_string}")

                if response and response.status_code == 200:
                    self.logger.info(f"Successfully un-isolation {log_string}")
                    un_isolated.append(device_id)
                else:
                    self.logger.info(f"Unable to un-isolation {log_string}")
            return un_isolated

    def groom_host(self, host) -> list:
        self.logger.warning("DeepInstinctEDR client does not implement host grooming")
        return []

    def block_detection(self, detection: VectraDetection) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "DeepInstinctEDR client does not implement detection-based blocking"
        )
        return []

    def unblock_detection(self, detection: VectraDetection) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "DeepInstinctEDR client does not implement detection-based blocking"
        )
        return []

    def block_account(self, account: VectraAccount) -> list:
        # this client only implements Host-based blocking
        self.logger.warning("DeepInstinctEDR client does not implement account-based blocking")
        return []

    def unblock_account(self, account: VectraAccount) -> list:
        # this client only implements Host-based blocking
        self.logger.warning("DeepInstinctEDR client does not implement account-based blocking")
        return []

    def block_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "DeepInstinctEDR client does not implement destination IP blocking"
        )
        return []

    def unblock_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "DeepInstinctEDR client does not implement destination IP blocking"
        )
        return []
