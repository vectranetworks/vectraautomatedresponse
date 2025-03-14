import logging

import requests
from common import _get_password
from third_party_clients.third_party_interface import (
    ThirdPartyInterface,
    VectraAccount,
    VectraDetection,
    VectraHost,
    VectraStaticIP,
)
from third_party_clients.trendmicro_cloudone.cloudone_config import (
    BASE_URL,
    CHECK_SSL,
)


class Client(ThirdPartyInterface):
    def __init__(self, **kwargs):
        self.name = "CloudOne Client"
        self.module = "trendmicro_cloudone"
        self.init_log(kwargs)
        self.url = BASE_URL + "/api"
        self.api_key = _get_password("CloudOne", "API_Key", modify=kwargs["modify"])
        self.headers = {
            "api-version": "v1",
            "Content-Type": "application/json",
            "Authorization": "ApiKey " + self.api_key,
        }
        self.verify = CHECK_SSL
        # Instantiate parent class
        ThirdPartyInterface.__init__(self)

    def init_log(self, kwargs):
        dict_config = kwargs.get("dict_config", {})
        dict_config["loggers"].update({self.name: dict_config["loggers"]["VAR"]})
        logging.config.dictConfig(dict_config)
        self.logger = logging.getLogger(self.name)

    def _search_computer(self, ip):
        """
        Searches for computer by lastIPUsed
        :param ip:
        :return:
        """
        body = {
            "searchCriteria": [
                {"fieldName": "lastIPUsed", "stringTest": "equal", "stringValue": ip}
            ]
        }
        params = {"expand": "computerSettings"}
        results = requests.post(
            self.url + "/computers/search",
            headers=self.headers,
            params=params,
            json=body,
            verify=self.verify,
        )
        if results.ok:
            return results.json().get("computers")
        else:
            self.logger.error(
                "Error searching for computer: {}".format(results.content)
            )
            return []

    def _set_isolation(self, comp_id, value):
        """
        Sets the computer's firewall isolation status to provided value
        :param comp_id:
        :param value:
        :return:
        """
        body = {"value": value}
        results = requests.post(
            self.url
            + "/computers/{}/settings/firewallSettingInterfaceIsolationEnabled".format(
                comp_id
            ),
            headers=self.headers,
            json=body,
            verify=self.verify,
        )
        return results

    def block_host(self, host: VectraHost) -> list:
        ip_address = host.ip
        computers = self._search_computer(ip_address)
        if len(computers) == 1:
            self.logger.info(
                "Requesting CloudOne isolation of computer with ID {} and IP {}".format(
                    computers[0].get("ID"), ip_address
                )
            )
            results = self._set_isolation(computers[0].get("ID"), "true")
            if results.ok:
                self.logger.info(
                    "Successfully  isolation of computer with ID {} and IP {}".format(
                        computers[0].get("ID"), ip_address
                    )
                )
                return [computers[0].get("ID")]
            else:
                self.logger.info(
                    "Unable to isolate computer with ID {} and IP {}. {}".format(
                        computers[0].get("ID"), ip_address, results.content
                    )
                )
                return []
        elif len(computers) == 0:
            self.logger.info(
                "No computers ({}) were found with IP: {}".format(
                    len(computers), ip_address
                )
            )
            return []
        else:
            self.logger.info(
                "More than 1 computer ({}) was found with IP: {}".format(
                    len(computers), ip_address
                )
            )
            return []

    def unblock_host(self, host: VectraHost) -> list:
        comp_ids = host.blocked_elements.get(self.name, [])
        un_isolated = []
        if len(comp_ids) >= 1:
            for comp_id in comp_ids:
                self.logger.info(
                    "Requesting CloudOne un-isolation of computer with ID {} and IP {}".format(
                        comp_id, host.ip
                    )
                )
                results = self._set_isolation(comp_id, value=None)

                if results.ok:
                    self.logger.info(
                        "Successfully  un-isolation of computer with ID {} and IP {}".format(
                            comp_id, host.ip
                        )
                    )
                    un_isolated.append(comp_id)
                else:
                    self.logger.info(
                        "Unable to un-isolate computer with ID {} and IP {}. {}".format(
                            comp_id, host.ip, results.content
                        )
                    )
            return un_isolated

    def groom_host(self, host) -> list:
        self.logger.warning("CloudOne client does not implement host grooming")
        return []

    def block_detection(self, detection: VectraDetection) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "CloudOne client does not implement detection-based blocking"
        )
        return []

    def unblock_detection(self, detection: VectraDetection) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "CloudOne client does not implement detection-based blocking"
        )
        return []

    def block_account(self, account: VectraAccount) -> list:
        # this client only implements Host-based blocking
        self.logger.warning("CloudOne client does not implement account-based blocking")
        return []

    def unblock_account(self, account: VectraAccount) -> list:
        # this client only implements Host-based blocking
        self.logger.warning("CloudOne client does not implement account-based blocking")
        return []

    def block_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        self.logger.warning("CloudOne client does not implement static-based blocking")
        return []

    def unblock_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "CloudOne client does not implement static-based unblocking"
        )
        return []
