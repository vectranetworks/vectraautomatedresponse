from datetime import datetime, timedelta
import logging
import json
import requests

from common import _get_password
from third_party_clients.third_party_interface import (
    ThirdPartyInterface,
    VectraAccount,
    VectraDetection,
    VectraHost,
    VectraStaticIP,
)
from third_party_clients.cynet_edr.cynet_edr_config import (
    BASE_URL,
    VERIFY,
)


class Client(ThirdPartyInterface):
    def __init__(self, **kwargs):
        self.name = "CynetEdr Client"
        self.logger = logging.getLogger()
        self.url = BASE_URL
        self.headers = {
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
        self.verify = VERIFY
        self.user = _get_password(
                "CynetEdr",
                "user_name",
                modify=kwargs["modify"]
                )
        self.password = _get_password(
                "CynetEdr",
                "password",
                modify=kwargs["modify"]
                )
        self.client_id = _get_password(
                "CynetEdr",
                "client_id",
                modify=kwargs["modify"]
                )
        try:
            url = f"https://{self.url}/api/account/token"
            data = {
                "user_name": self.user,
                "password": self.password
            }
            response = requests.post(
                    url,
                    headers=self.headers,
                    json=data,
                    verify=self.verify
                    )

            if not response.json().get("access_token", False):
                raise response.text
            else:
                self.headers['access_token'] = response.json().get("access_token")
                self.headers['Accept'] = "application/json"
                self.headers['client_id'] = self.client_id

        except Exception as e:
            self.logger.error("CynetEdr connection issue")
            raise e
        # Instantiate parent class
        ThirdPartyInterface.__init__(self)

    def _list_hosts(self, host: VectraHost) -> list:
        """
        Searches for computer first by IP addresses
        :param host:VectraHost: vectra host object to search for
        :return: list of endpoint IDs
        """
        # Search hosts seen in the past hour by IP
        last_hour_date_time = datetime.now() - timedelta(hours=1)
        last_hour = last_hour_date_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        search_url = f"https://{self.url}/api/hosts?LastSeen={last_hour}"
        try:
            response = requests.get(
                    search_url,
                    headers=self.headers,
                    verify=self.verify
                    )
            entities = response.json().get('Entities', [])
            cynet_hosts = [x for x in entities if x['LastIp'] == host.ip]
        except Exception as e:
            self.logger.error(f"CynetEdr connection issue: {e}")
            raise e
        if len(cynet_hosts) != 1:
            self.logger.error(
                "Found 0 or multiple cynet hosts with same IP. Aborting!"
            )
            return False
        else:
            cynet_host = cynet_hosts[0]
            if not cynet_host['HostName'].lower().startswith(
                host.name.lower().split('.')[0]
            ):
                self.logger.error(
                    f"Cynet name {cynet_host['HostName']} \
                        does not match Vectra hostname {host.name}!"
                )
                return False
            else:
                self.logger.info("Cynet name matches Vectra host name")
                return cynet_host

    def block_host(self, host: VectraHost) -> list:
        cynet_host = self._list_hosts(host)
        if not cynet_host:
            return []
        log_string = f"{host.name} with name {cynet_host['HostName']} and IP {host.ip}"

        isolate_url = f"https://{self.url}/api/host/remediation/isolate"

        self.logger.info(f"Requesting CynetEdr isolation for {log_string}")
        payload = {'host': cynet_host['HostName']}
        try:
            results = requests.post(
                    isolate_url,
                    data=payload,
                    headers=self.headers,
                    verify=self.verify
                    )
        except Exception as e:
            self.logger.debug(f"CynetEdr isolation failed with status: {e}")
            results = False

        if results.status_code in [200, 201, 202]:
            self.logger.info(f"Successfully isolated {log_string}")
            return [cynet_host["HostName"]]
        else:
            self.logger.info(f"Unable to isolate {log_string}")
            return []

    def unblock_host(self, host: VectraHost) -> list:
        cynet_names = host.blocked_elements.get(self.name, [])
        un_isolated = []
        un_isolate_url = f"https://{self.url}/api/host/remediation/unisolate"

        if cynet_names:
            for cynet_name in cynet_names:
                log_string = f"Cynet host ID {cynet_name}"
                self.logger.info(
                        f"Requesting CynetEdr un-isolation for {log_string}"
                        )
                payload = {'host': cynet_name}
                try:
                    result = requests.post(
                                un_isolate_url,
                                data=payload,
                                headers=self.headers,
                                verify=self.verify
                                )
                except Exception as e:
                    self.logger.debug(
                            f"CynetEdr un-isolation failed with status: {e}"
                            )
                    result = False

                if result:
                    self.logger.info(f"Successfully un-isolation {log_string}")
                    un_isolated.append(cynet_name)
                else:
                    self.logger.info(f"Unable to un-isolation {log_string}")
            return un_isolated

    def groom_host(self, host) -> list:
        self.logger.warning("CynetEdr client does not implement host grooming")
        return []

    def block_detection(self, detection: VectraDetection) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "CynetEdr client does not implement detection-based blocking"
        )
        return []

    def unblock_detection(self, detection: VectraDetection) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "CynetEdr client does not implement detection-based blocking"
        )
        return []

    def block_account(self, account: VectraAccount) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
                "CynetEdr client does not implement account-based blocking"
                )
        return []

    def unblock_account(self, account: VectraAccount) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
                "CynetEdr client does not implement account-based blocking"
                )
        return []

    def block_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "CynetEdr client does not implement destination IP blocking"
        )
        return []

    def unblock_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "CynetEdr client does not implement destination IP blocking"
        )
        return []
