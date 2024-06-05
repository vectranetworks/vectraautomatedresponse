import logging

import requests
from third_party_clients.cisco_amp.amp_config import URL
from third_party_clients.third_party_interface import (
    ThirdPartyInterface,
    VectraAccount,
    VectraDetection,
    VectraHost,
    VectraStaticIP,
)
from common import _get_password
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


class Client(ThirdPartyInterface):
    def __init__(self, **kwargs):
        self.name = "AMP Client"
        self.logger = logging.getLogger()
        self._check_connection()
        self.auth = (_get_password("Cisco_Amp","Client_ID", modify=kwargs["modify"]), _get_password("Cisco_Amp","API_Key",modify=kwargs["modify"]))
        # Instantiate parent class
        ThirdPartyInterface.__init__(self)

    def block_host(self, host) -> list[str]:
        self.logger.info(f"Processing block request for host with IP: {host.ip}")
        cguid = self._get_connector_guid(host.ip, host.get_full_name())
        if cguid is None:
            self.logger.error("Could not identify unique connector_guid. Skipping host.")
            return []
        self.logger.info(f"This host is identified by the unique cguid: {cguid}")
        isolation_state = self._get_block_state(cguid)
        if isolation_state is not None and (isolation_state == 'not_isolated' or isolation_state == 'pending_stop'):
            self._block_host_by_connector_guid(cguid)
            isolation_state = self._get_block_state(cguid)
            if not isolation_state == 'pending_start' or isolation_state == 'isolated':
                self.logger.error("Expected isolation status to be 'pending_start' or 'isolated'.  Skipping host.")
                return []
        elif isolation_state is None:
            self.logger.error("Has invalid isolation state. Skipping host.")
            return []
        else:
            self.logger.info("Host already blocked. Skipping host.")
        self.logger.info("Host successfully blocked.")
        return [cguid]

    def unblock_host(self, host) -> list[str]:
        cguid = host.blocked_elements.get(self.__class__.__name__, [])[0]
        if cguid is None:
            self.logger.error("Could not identify unique connector_guid. Skipping host.")
            return []
        self.logger.info(f"Processing unblock request for host with IP: {host.ip} / cguid: {cguid}")
        isolation_state = self._get_block_state(cguid)
        if isolation_state is not None and (isolation_state == 'isolated' or isolation_state == 'pending_start'):
            self._unblock_host_by_connector_guid(cguid)
            isolation_state = self._get_block_state(cguid)
            if not isolation_state == 'pending_stop' or isolation_state == 'not_isolated':
                self.logger.error("Expected isolation status to be 'pending_stop' or 'not_isolated'. Skipping host.")
                return []
        elif isolation_state is None:
            self.logger.error("Has invalid isolation state. Skipping host.")
            return []
        else:
            self.logger.info("Host already unblocked. Skipping host.")
        self.logger.info("Host successfully unblocked.")
        return [cguid]

    def groom_host(self, host) -> dict:
        self.logger.warning('AMP client does not implement host grooming')
        return []
    
    def block_detection(self, detection):
        # this client only implements Host-based blocking
        self.logger.warn("Cisco AMP client does not implement detection-based blocking")
        return []

    def unblock_detection(self, detection):
        # this client only implements Host-based blocking
        self.logger.warn("Cisco AMP client does not implement detection-based blocking")
        return []

    def block_account(self, account: VectraAccount) -> list:
        # this client only implements Host-based blocking
        self.logger.warn("Cisco AMP client does not implement account-based blocking")
        return []

    def unblock_account(self, account: VectraAccount) -> list:
        # this client only implements Host-based blocking
        self.logger.warn("Cisco AMP client does not implement account-based blocking")
        return []

    def block_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        self.logger.warn("Cisco AMP client does not implement static IP-based blocking")
        return []

    def unblock_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        self.logger.warn("Cisco AMP client does not implement static IP-based blocking")
        return []

    def _check_connection(self):
        try:
            self.logger.info("Performing Cisco AMP connection check.")
            api_endpoint = 'version'
            response = requests.get(
                url=f'{URL}/v1/{api_endpoint}',
                verify=False,
                auth=self.auth
                )
            response.raise_for_status()
            self.logger.info("Connection check successful.")
        except:
            self.logger.info("Cisco AMP connection check failed.")

    def _get_connector_guid(self, ip, hostname):
        self.logger.info(f"Querying unique connector guid for host {hostname} with IP: {ip}")
        api_endpoint = f'computers?internal_ip={ip}'
        response = requests.get(
            url=f'{URL}/v1/{api_endpoint}',
            verify=False,
            auth=self.auth
            )
        response.raise_for_status()
        data = response.json()
        
        if data['metadata']['results']['total'] == 1:
            cguid = data['data'][0]['connector_guid']
            self.logger.info(f"Connector guid received: {cguid}")
            return cguid
        else:
            if data['metadata']['results']['total'] > 1:
                msg = f'Found more than 1 host with IP {ip}'
            else:
                msg = f'Found no host with IP {ip}'
            self.logger.info(f'{msg} - Searching by hostname instead.')
            
            api_endpoint = f'computers?hostname={hostname}'
            response = requests.get(
                url=f'{URL}/v1/{api_endpoint}',
                verify=False,
                auth=self.auth
                )
            response.raise_for_status()
            data = response.json()
            
            if data['metadata']['results']['total'] == 1:
                cguid = data['data'][0]['connector_guid']
                self.logger.info(f"Connector guid received: {cguid}")
                return cguid
            else:
                if data['metadata']['results']['total'] > 1:
                    error_msg = f'Found more than 1 host with hostname {hostname}'
                else:
                    error_msg = f'Found no host with hostname {hostname}'
                self.logger.error(f'{error_msg} - Aborting.')
                return None

    def _get_block_state(self, connector_guid):
        self.logger.info(f"Querying isolation state for host identified by connector guid {connector_guid}.")
        api_endpoint = f'computers/{connector_guid}/isolation'
        response = requests.get(
            url=f'{URL}/v1/{api_endpoint}',
            verify=False,
            auth=self.auth
            )
        response.raise_for_status()
        data = response.json()
        
        if not data['data']['available']:
            self.logger.error(f"Isolation unavailable for host identified by connector guid {connector_guid}.")
            return None
        else:
            isolation_state = data['data']['status']
            self.logger.info(f"Isolation available. Isolation state received: {isolation_state}")
            return isolation_state

    def _block_host_by_connector_guid(self, connector_guid):
        self.logger.info(f"Requesting isolation of host identified by connector guid {connector_guid}.")
        api_endpoint = f'computers/{connector_guid}/isolation'
        response = requests.put(
            url=f'{URL}/v1/{api_endpoint}',
            verify=False,
            auth=self.auth
            )
        response.raise_for_status()

    def _unblock_host_by_connector_guid(self, connector_guid):
        self.logger.info(f"Requesting to stop isolation of host identified by connector guid {connector_guid}.")
        api_endpoint = f'computers/{connector_guid}/isolation'
        response = requests.delete(
            url=f'{URL}/v1/{api_endpoint}',
            verify=False,
            auth=self.auth
            )
        response.raise_for_status()        response = requests.delete(
            url=f'{URL}/v1/{api_endpoint}',
            verify=False,
            auth=self.auth
            )
        response.raise_for_status()