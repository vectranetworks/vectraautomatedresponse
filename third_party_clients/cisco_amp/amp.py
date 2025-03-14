import logging

import requests
from common import _get_password
from third_party_clients.cisco_amp.amp_config import URL
from third_party_clients.third_party_interface import (
    ThirdPartyInterface,
    VectraAccount,
    VectraDetection,
    VectraHost,
    VectraStaticIP,
)
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


class Client(ThirdPartyInterface):
    def __init__(self, **kwargs):
        self.name = "AMP Client"
        self.module = "cisco_amp"
        self.init_log(kwargs)
        self.auth = (
            _get_password("Cisco_Amp", "Client_ID", modify=kwargs["modify"]),
            _get_password("Cisco_Amp", "API_Key", modify=kwargs["modify"]),
        )
        self._check_connection()
        # Instantiate parent class
        ThirdPartyInterface.__init__(self)

    def init_log(self, kwargs):
        dict_config = kwargs.get("dict_config", {})
        dict_config["loggers"].update({self.name: dict_config["loggers"]["VAR"]})
        logging.config.dictConfig(dict_config)
        self.logger = logging.getLogger(self.name)

    def block_host(self, host: VectraHost) -> list[str]:
        self.logger.info(f"Processing block request for host with IP: {host.ip}")
        cguid = self._get_connector_guid(host.ip, host.get_full_name())
        if cguid is None:
            self.logger.error(
                "Could not identify unique connector_guid. Skipping host."
            )
            return []
        self.logger.debug(f"This host is identified by the unique cguid: {cguid}")
        isolation_state = self._get_block_state(cguid)
        if isolation_state in ["not_isolated", "pending_stop"]:
            self._block_host_by_connector_guid(cguid)
            isolation_state = self._get_block_state(cguid)
            if isolation_state not in ["pending_start", "isolated"]:
                self.logger.warning(
                    "Expected isolation state to be 'pending_start' or 'isolated'.  Manually verify isolation."
                )
                return [cguid]
        elif isolation_state is None:
            self.logger.error("Has invalid isolation state. Skipping host.")
            return []
        else:
            self.logger.info("Host already blocked.")
            return [cguid]
        self.logger.info("Host successfully blocked.")
        return [cguid]

    def unblock_host(self, host: VectraHost) -> list[str]:
        cguid = host.blocked_elements.get(self.name, [])[0]
        if cguid is None:
            self.logger.error(
                "Could not identify unique connector_guid. Skipping host."
            )
            return []
        self.logger.info(
            f"Processing unblock request for host with IP: {host.ip} / cguid: {cguid}"
        )
        isolation_state = self._get_block_state(cguid)
        if isolation_state in ["isolated", "pending_start"]:
            self._unblock_host_by_connector_guid(cguid)
            isolation_state = self._get_block_state(cguid)
            if isolation_state not in ["pending_stop", "not_isolated"]:
                self.logger.warning(
                    "Expected unisolation state to be 'pending_stop' or 'not_isolated'. Manually verify unisolation."
                )
                return [cguid]
        elif isolation_state is None:
            self.logger.error("Has invalid isolation state. Skipping host.")
            return []
        else:
            self.logger.info("Host already unblocked.")
            return [cguid]
        self.logger.info("Host successfully unblocked.")
        return [cguid]

    def groom_host(self, host: VectraHost) -> dict:
        self.logger.warning("AMP client does not implement host grooming")
        return []

    def block_detection(self, detection: VectraDetection):
        # this client only implements Host-based blocking
        self.logger.warning(
            "Cisco AMP client does not implement detection-based blocking"
        )
        return []

    def unblock_detection(self, detection: VectraDetection):
        # this client only implements Host-based blocking
        self.logger.warning(
            "Cisco AMP client does not implement detection-based blocking"
        )
        return []

    def block_account(self, account: VectraAccount) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "Cisco AMP client does not implement account-based blocking"
        )
        return []

    def unblock_account(self, account: VectraAccount) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "Cisco AMP client does not implement account-based blocking"
        )
        return []

    def block_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "Cisco AMP client does not implement static IP-based blocking"
        )
        return []

    def unblock_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "Cisco AMP client does not implement static IP-based blocking"
        )
        return []

    def _check_connection(self):
        try:
            self.logger.debug("Performing Cisco AMP connection check.")
            api_endpoint = "version"
            response = requests.get(
                url=f"{URL}/v1/{api_endpoint}", verify=False, auth=self.auth
            )
            self.logger.debug("Connection check successful.")
        except requests.HTTPError:
            self.logger.error("Cisco AMP connection check failed.")

    def _get_connector_guid(self, ip, hostname):
        self.logger.info(
            f"Querying unique connector guid for host {hostname} with IP: {ip}"
        )
        api_endpoint = f"computers?internal_ip={ip}"
        try:
            response = requests.get(
                url=f"{URL}/v1/{api_endpoint}", verify=False, auth=self.auth
            )
        except requests.HTTPError as e:
            self.logger.error(f"Connector guid query returned error: {e}.")
            return None
        data = response.json()

        if data["metadata"]["results"]["total"] == 1:
            cguid = data["data"][0]["connector_guid"]
            self.logger.info(f"Connector guid received: {cguid}")
            return cguid
        else:
            if data["metadata"]["results"]["total"] > 1:
                msg = f"Found more than 1 host with IP {ip}"
            else:
                msg = f"Found no host with IP {ip}"
            self.logger.info(f"{msg} - Searching by hostname instead.")

            api_endpoint = f"computers?hostname={hostname}"
            response = requests.get(
                url=f"{URL}/v1/{api_endpoint}", verify=False, auth=self.auth
            )
            response.raise_for_status()
            data = response.json()

            if data["metadata"]["results"]["total"] == 1:
                cguid = data["data"][0]["connector_guid"]
                self.logger.info(f"Connector guid received: {cguid}")
                return cguid
            else:
                if data["metadata"]["results"]["total"] > 1:
                    error_msg = f"Found more than 1 host with hostname {hostname}"
                else:
                    error_msg = f"Found no host with hostname {hostname}"
                self.logger.error(f"{error_msg} - Aborting.")
                return None

    def _get_block_state(self, connector_guid):
        self.logger.debug(
            f"Querying isolation state for host identified by connector guid {connector_guid}."
        )
        api_endpoint = f"computers/{connector_guid}/isolation"
        try:
            response = requests.get(
                url=f"{URL}/v1/{api_endpoint}", verify=False, auth=self.auth
            )
        except requests.HTTPError as e:
            self.logger.error(f"Isolation state query returned {e}.")
            return None
        data = response.json()

        if not data["data"]["available"]:
            self.logger.error(
                f"Isolation unavailable for host identified by connector guid {connector_guid}."
            )
            return None
        else:
            # isolation_states: 'isolated', 'pending_start', 'pending_stop', 'not_isolated'
            isolation_state = data["data"]["status"]
            self.logger.debug(f"Isolation state received: {isolation_state}")
            return isolation_state

    def _block_host_by_connector_guid(self, connector_guid):
        self.logger.info(
            f"Requesting isolation of host identified by connector guid {connector_guid}."
        )
        api_endpoint = f"computers/{connector_guid}/isolation"
        try:
            response = requests.put(
                url=f"{URL}/v1/{api_endpoint}", verify=False, auth=self.auth
            )
        except requests.HTTPError as e:
            if response.status_code == 409:
                pass
            else:
                self.logger.error(f"Isolation returned {e}; Manually verify isolation.")

    def _unblock_host_by_connector_guid(self, connector_guid):
        self.logger.info(
            f"Requesting to stop isolation of host identified by connector guid {connector_guid}."
        )
        api_endpoint = f"computers/{connector_guid}/isolation"
        try:
            response = requests.delete(
                url=f"{URL}/v1/{api_endpoint}", verify=False, auth=self.auth
            )
        except requests.HTTPError as e:
            if response.status_code == 409:
                pass
            else:
                self.logger.error(
                    f"Unisolation returned {e}; Manually verify unisolation."
                )
