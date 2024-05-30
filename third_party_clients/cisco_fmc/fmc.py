import json
import logging

import requests
from requests.auth import HTTPBasicAuth
from third_party_clients.cisco_fmc.fmc_config import (
    URL,
)

from third_party_clients.third_party_interface import (
    ThirdPartyInterface,
    VectraAccount,
    VectraDetection,
    VectraHost,
    VectraStaticIP,
)
from urllib3.exceptions import InsecureRequestWarning

from common import _get_password

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


class Client(ThirdPartyInterface):
    def __init__(self, **kwargs):
        self.name = "FMC Client"
        self.logger = logging.getLogger()
        self._check_connection()
        self.group_id = _get_password("Cisco_FMC", "Group_ID", modify=kwargs["modify"])
        self.auth = (
            _get_password("Cisco_FMC", "Username", modify=kwargs["modify"]),
            _get_password("Cisco_FMC", "Password", modify=kwargs["modify"]),
        )
        # Instantiate parent class
        ThirdPartyInterface.__init__(self)

    def block_host(self, host) -> list[str]:
        self.logger.info(f"Processing block request for host with IP {host.ip}")
        try:
            if host_fmc_id := self._get_host_id_by_object_name(host.ip):
                self.logger.debug(
                    f"Host object for IP {host.ip} found (ID: {host_fmc_id})."
                )
            else:
                self.logger.debug(
                    f"Host object for IP {host.ip} not found. Creating..."
                )
                host_fmc_id = self._create_host(
                    host.ip, "Host object created by Vectra Integration.", host.ip
                )
                self.logger.debug(
                    f"Host object created successfully (ID: {host_fmc_id})."
                )

            block_group = self._get_group(self.group_id)
            if host_fmc_id in [host["id"] for host in block_group["objects"]]:
                self.logger.error(
                    f"{host.ip} / {host_fmc_id} is already blocked. Skipping"
                )
                return []
            else:
                self.logger.debug(f"Adding {host.ip} / {host_fmc_id} to block group.")
                self._add_host_to_group(host_fmc_id, block_group["id"])
                return [host_fmc_id]
        except requests.HTTPError as e:
            self.logger.error(e)
            self.logger.error(f"Skipping IP {host.ip}.")
            return []

    def unblock_host(self, host) -> list[str]:
        host_fmc_id = host.blocked_elements.get(self.__class__.__name__, [])[0]
        self.logger.info(
            f"Processing unblock request for IP: {host.ip} / ID: {host_fmc_id}"
        )
        try:
            block_group = self._get_group(self.group_id)
            if host_fmc_id not in [host["id"] for host in block_group["objects"]]:
                self.logger.error(f"{host.ip} / {host_fmc_id} is not blocked. Skipping")
                return []
            else:
                self.logger.debug(
                    f"Removing {host.ip} / {host_fmc_id} from block group."
                )
                self._remove_host_from_group(host_fmc_id, block_group["id"])
                return [host_fmc_id]
        except requests.HTTPError as e:
            self.logger.error(e)
            self.logger.error(f"Skipping IP {host.ip}.")
            return []

    def groom_host(self, host) -> dict:
        self.logger.warning("Cisco FMC client does not implement host grooming")
        return []

    def block_detection(self, detection):
        # this client only implements Host-based blocking
        self.logger.warn("Cisco FMC client does not implement detection-based blocking")
        return []

    def unblock_detection(self, detection):
        # this client only implements Host-based blocking
        self.logger.warn("Cisco FMC client does not implement detection-based blocking")
        return []

    def block_account(self, account: VectraAccount) -> list:
        # this client only implements Host-based blocking
        self.logger.warn("Cisco FMC client does not implement account-based blocking")
        return []

    def unblock_account(self, account: VectraAccount) -> list:
        # this client only implements Host-based blocking
        self.logger.warn("Cisco FMC client does not implement account-based blocking")
        return []

    def block_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        self.logger.warn("Cisco FMC client does not implement static IP-based blocking")
        return []

    def unblock_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        self.logger.warn("Cisco FMC client does not implement static IP-based blocking")
        return []

    def _check_connection(self):
        try:
            self.logger.info("Performing Cisco FTP connection check.")
            self._authenticate()
            self.logger.info("Connection check successful.")
        except requests.HTTPError as e:
            self.logger.error(
                "Connection check failed. Please check credentials in config file and see detailed error below."
            )
            self.logger.error(e)

    def _authenticate(self):
        auth_endpoint = "api/fmc_platform/v1/auth/generatetoken"
        response = requests.post(
            URL + auth_endpoint,
            verify=False,
            auth=self.auth,
        )
        if not response.status_code == 204:
            raise requests.HTTPError(
                f"Authentication failed - Status: {response.status_code} - Response: {response.text}",
                response=response,
            )
        accesstoken = response.headers["X-auth-access-token"]
        domain_uuid = response.headers["DOMAIN_UUID"]
        return accesstoken, domain_uuid

    def _create_host(self, name, desciption, ip):
        accesstoken, domain_uuid = self._authenticate()
        host_endpoint = f"api/fmc_config/v1/domain/{domain_uuid}/object/hosts"
        headers = {
            "Content-Type": "application/json",
            "X-auth-access-token": accesstoken,
        }
        host_payload = json.dumps(
            {
                "type": "Host",
                "name": name,
                "description": desciption,
                "value": ip,
            }
        )
        response = requests.post(
            URL + host_endpoint,
            headers=headers,
            data=host_payload,
            verify=False,
        )
        if not (response.status_code == 201 or response.status_code == 202):
            raise requests.HTTPError(
                f"Failed to create host object - Status: {response.status_code} - Response: {response.text}",
                response=response,
            )
        return response.json()["id"]

    def _delete_host(self, id):
        accesstoken, domain_uuid = self._authenticate()
        host_endpoint = f"api/fmc_config/v1/domain/{domain_uuid}/object/hosts/{id}"
        headers = {
            "X-auth-access-token": accesstoken,
        }
        response = requests.delete(
            URL + host_endpoint,
            headers=headers,
            verify=False,
        )
        if not response.status_code == 200:
            raise requests.HTTPError(
                f"Failed to delete host object - Status: {response.status_code} - Response: {response.text}",
                response=response,
            )

    def _get_all_hosts(self):
        accesstoken, domain_uuid = self._authenticate()
        host_endpoint = f"api/fmc_config/v1/domain/{domain_uuid}/object/hosts"
        headers = {
            "X-auth-access-token": accesstoken,
        }
        response = requests.get(
            URL + host_endpoint,
            headers=headers,
            verify=False,
        )
        if not response.status_code == 200:
            raise requests.HTTPError(
                f"Failed to retrieve all host objects - Status: {response.status_code} - Response: {response.text}",
                response=response,
            )
        body = response.json()
        data = body["items"]

        while "next" in body["paging"]:
            response = requests.get(
                body["paging"]["next"][0],
                headers=headers,
                verify=False,
            )
            if not response.status_code == 200:
                raise requests.HTTPError(
                    f"Failed to retrieve all host objects - Status: {response.status_code} - Response: {response.text}",
                    response=response,
                )
            body = response.json()
            data += body["items"]
        return data

    def _get_host(self, id):
        accesstoken, domain_uuid = self._authenticate()
        host_endpoint = f"api/fmc_config/v1/domain/{domain_uuid}/object/hosts/{id}"
        headers = {"X-auth-access-token": accesstoken}
        response = requests.get(
            URL + host_endpoint,
            headers=headers,
            verify=False,
        )
        if not response.status_code == 200:
            raise requests.HTTPError(
                f"Failed to retrieve host object with id {id} - Status: {response.status_code} - Response: {response.text}",
                response=response,
            )
        return response.json()

    def _get_host_id_by_object_name(self, host_name):
        hosts = self._get_all_hosts()
        for host in hosts:
            if host["name"] == host_name:
                return host["id"]
        return None

    def _get_all_groups(self):
        accesstoken, domain_uuid = self._authenticate()
        group_endpoint = f"api/fmc_config/v1/domain/{domain_uuid}/object/networkgroups"
        headers = {
            "X-auth-access-token": accesstoken,
        }
        response = requests.get(
            URL + group_endpoint,
            headers=headers,
            verify=False,
        )
        if not response.status_code == 200:
            raise requests.HTTPError(
                f"Failed to retrieve all groups - Status: {response.status_code} - Response: {response.text}",
                response=response,
            )
        body = response.json()
        data = body["items"]

        while "next" in body["paging"]:
            response = requests.get(
                body["paging"]["next"][0],
                headers=headers,
                verify=False,
            )
            if not response.status_code == 200:
                raise requests.HTTPError(
                    f"Failed to retrieve all groups - Status: {response.status_code} - Response: {response.text}",
                    response=response,
                )
            body = response.json()
            data += body["items"]
        return data

    def _get_group(self, id):
        accesstoken, domain_uuid = self._authenticate()
        group_endpoint = (
            f"api/fmc_config/v1/domain/{domain_uuid}/object/networkgroups/{id}"
        )
        headers = {"X-auth-access-token": accesstoken}
        response = requests.get(
            URL + group_endpoint,
            headers=headers,
            verify=False,
        )
        if not response.status_code == 200:
            raise requests.HTTPError(
                f"Failed to retrieve group with id {id} - Status: {response.status_code} - Response: {response.text}",
                response=response,
            )
        return response.json()

    def _update_group(self, id, new_group_definition):
        accesstoken, domain_uuid = self._authenticate()
        group_endpoint = (
            f"api/fmc_config/v1/domain/{domain_uuid}/object/networkgroups/{id}"
        )
        headers = {
            "Content-Type": "application/json",
            "X-auth-access-token": accesstoken,
        }
        group_payload = json.dumps(new_group_definition)
        response = requests.put(
            URL + group_endpoint,
            headers=headers,
            data=group_payload,
            verify=False,
        )
        if not response.status_code in [200, 201, 202]:
            raise requests.HTTPError(
                f"Failed to update group with id {id} - Status: {response.status_code} - Response: {response.text}",
                response=response,
            )

    def _get_group_id_by_objcet_name(self, group_name):
        groups = self._get_all_groups()
        for group in groups:
            if group["name"] == group_name:
                return group["id"]
        return None

    def _add_host_to_group(self, host_id, group_id):
        group = self._get_group(group_id)
        host = self._get_host(host_id)
        group["objects"].append(
            {
                "type": host["type"],
                "name": host["name"],
                "id": host["id"],
            }
        )
        self._update_group(group_id, group)

    def _remove_host_from_group(self, host_id, group_id):
        group = self._get_group(group_id)
        for obj in group["objects"]:
            if obj["id"] == host_id:
                group["objects"].remove(obj)
        self._update_group(group_id, group)
        self._update_group(group_id, group)
