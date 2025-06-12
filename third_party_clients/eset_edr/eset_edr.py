import logging
import requests
from datetime import datetime, timezone

from common import _get_password
from third_party_clients.eset_edr.eset_edr_config import (
    CHECK_SSL,
    REGION,
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
        self.name = "EsetEDR Client"
        self.module = "eset_edr"
        self.init_log(kwargs)
        self.region = REGION
        self.verify = CHECK_SSL
        self.user = _get_password("EsetEDR", "user", modify=kwargs["modify"])
        self.password = _get_password("EsetEDR", "password", modify=kwargs["modify"])
        self.headers = {
                "accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded"
            }
        try:
            auth_url = f"https://{self.region}.business-account.iam.eset.systems/oauth/token"
            data = {
                "grant_type": "password",
                "username": self.user,
                "password": self.password
            }
            response = requests.post(auth_url, headers=self.headers, data=data, verify=self.verify)
            if response.status_code == 200:
                self.logger.info("Succesfully authenticated to ESET")
                self.access_token = response.json().get('access_token')
                self.refresh_token = response.json().get('refresh_token')
                self.headers = {
                    "accept": "application/json",
                    "Authorization": f"Bearer {self.access_token}"
                }
            else:
                self.logger.error(f"Request failed with status code {response.status_code}.")
                raise {response.text}

        except Exception as e:
            self.logger.error("EsetEDR connection issue")
            raise e
        # Instantiate parent class
        ThirdPartyInterface.__init__(self)

    def init_log(self, kwargs):
        dict_config = kwargs.get("dict_config", {})
        dict_config["loggers"].update({self.name: dict_config["loggers"]["VAR"]})
        logging.config.dictConfig(dict_config)
        self.logger = logging.getLogger(self.name)

    def _list_endpoints(self, host: VectraHost) -> list:
        """
        Searches for computer by name
        :param host:VectraHost: vectra host object to search for
        :return: list of endpoint IDs
        """
        # List ESET Groups and get devices in root parrent groups
        devMgmtUri = "device-management.eset.systems"
        nextPage = True
        parrentDeviceGroups = []
        esetDevices = []
        while nextPage:
            groups_url = f"https://{self.region}.{devMgmtUri}/v1/device_groups"
            response = requests.get(url=groups_url, headers=self.headers, verify=self.verify)
            nextPage = self.headers['pageToken'] = response.json().get("nextPageToken", "")
            parrentDeviceGroups += [x for x in response.json().get("deviceGroups", "") if not x["parentGroupUuid"]]

        for group in parrentDeviceGroups:
            self.headers['pageToken'] = ''
            nextPage = True
            params = {
                'recurseSubgroups': 'true',
                'pageSize': '1000'
            }
            while nextPage:
                devices_url = f'https://{self.region}.{devMgmtUri}/v1/device_groups/{group.get("uuid")}/devices'
                response = requests.get(devices_url, headers=self.headers, params=params,verify=self.verify )
                nextPage = self.headers['nextPageToken'] = response.json().get('nextPageToken', '')
                esetDevices += response.json().get('devices', [])

        # Delete pageToken key from headers
        self.headers.pop('pageToken', None)

        # Search ESET hosts by name
        match_by_name = [x for x in esetDevices if host.name.lower() == x['displayName'].lower()
                         or host.name.lower().split('.')[0] == x['displayName'].lower().split('.')[0]]

        if len(match_by_name) != 1:
            self.logger.error(
                    f"Found no ESET hosts or multiple ESET hosts with similar name: f{', '.join(match_by_name)}. Aborting!"
            )
            return False
        else:
            eset_host = match_by_name[0]
            return eset_host

    def block_host(self, host: VectraHost) -> list:
        eset_host = self._list_endpoints(host)
        log_string = f"{host.name} with id {eset_host['uuid']} and IP {host.ip}"
        if not eset_host:
            return []

        isolate_url = f"https://{self.region}.automation.eset.systems/v1/device_tasks"
        task_time = datetime.now().astimezone(timezone.utc)
        task_time = task_time.strftime("%Y-%m-%dT%H:%M:%SZ")

        payload = {
            "task": {
                "action": {"name": "StartNetworkIsolation"},
                "description": "Isolation via Vectra-ESET integration",
                "displayName": "Vectra Isolation",
                "triggers": [{"manual": {"createTime": task_time}}],
                "targets": {"devicesUuids": [eset_host['uuid']]},
            }
        }

        self.logger.info(f"Requesting EsetEDR isolation for {log_string}")
        try:
            results = requests.post(isolate_url, json=payload, headers=self.headers, verify=self.verify)
            print(results.text)
        except Exception as e:
            self.logger.debug(f"EsetEDR isolation failed with status: {e}")
            results = False

        if results:
            self.logger.info(f"Successfully isolated {log_string}")
            return [eset_host['uuid']]
        else:
            self.logger.info(f"Unable to isolate {log_string}")
            return []

    def unblock_host(self, host: VectraHost) -> list:
        host_uuids = host.blocked_elements.get(self.name, [])
        un_isolated = []
        if host_uuids:
            isolate_url = f"https://{self.region}.automation.eset.systems/v1/device_tasks"
            task_time = datetime.now().astimezone(timezone.utc)
            task_time = task_time.strftime("%Y-%m-%dT%H:%M:%SZ")

            for uuid in host_uuids:
                log_string = f"{host.name} with id {uuid} and IP {host.ip}"

                payload = {
                    "task": {
                        "action": {"name": "EndNetworkIsolation"},
                        "description": "Isolation via Vectra-ESET integration",
                        "displayName": "Vectra Isolation",
                        "triggers": [{"manual": {"createTime": task_time}}],
                        "targets": {"devicesUuids": [uuid]},
                    }
                }

                self.logger.info(f"Requesting EsetEDR un-isolation for {log_string}")
                try:
                    results = requests.post(isolate_url, json=payload, headers=self.headers, verify=self.verify)
                except Exception as e:
                    self.logger.debug(f"EsetEDR un-isolation failed with status: {e}")
                    results = False

                if results:
                    self.logger.info(f"Successfully un-isolation {log_string}")
                    un_isolated.append(uuid)
                else:
                    self.logger.info(f"Unable to un-isolation {log_string}")
            return un_isolated

    def groom_host(self, host: VectraHost) -> list:
        self.logger.warning("EsetEDR client does not implement host grooming")
        return []

    def block_detection(self, detection: VectraDetection) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "EsetEDR client does not implement detection-based blocking"
        )
        return []

    def unblock_detection(self, detection: VectraDetection) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "EsetEDR client does not implement detection-based blocking"
        )
        return []

    def block_account(self, account: VectraAccount) -> list:
        # this client only implements Host-based blocking
        self.logger.warning("EsetEDR client does not implement account-based blocking")
        return []

    def unblock_account(self, account: VectraAccount) -> list:
        # this client only implements Host-based blocking
        self.logger.warning("EsetEDR client does not implement account-based blocking")
        return []

    def block_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "EsetEDR client does not implement destination IP blocking"
        )
        return []

    def unblock_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "EsetEDR client does not implement destination IP blocking"
        )
        return []
