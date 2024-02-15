import logging

import requests
from third_party_clients.third_party_interface import (
    ThirdPartyInterface,
    VectraAccount,
    VectraDetection,
    VectraHost,
    VectraStaticIP,
)
from third_party_clients.trendmicro_visionone.vision_one_config import (
    API_KEY,
    BASE_URL,
    VERIFY,
)


class Client(ThirdPartyInterface):
    def __init__(self):
        self.name = " VisionOne Client"
        self.logger = logging.getLogger()
        self.url = BASE_URL + "/v3.0/"
        self.verify = VERIFY
        self.api_key = API_KEY
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + self.api_key,
        }
        # Instantiate parent class
        ThirdPartyInterface.__init__(self)

    def _search_computer(self, host: VectraHost) -> list:
        """
        Searches for computer first by hostname, then IP, lastly MAC addresses
        :param host:VectraHost: vectra host object to search for
        :return: list of endpoint IDs
        """

        def host_search(search_header):
            self.logger.debug(
                "host search headers:{}".format({**self.headers, **search_header})
            )
            return requests.get(
                self.url + "eiqs/endpoints",
                headers={**self.headers, **search_header},
                verify=self.verify,
            )

        # Search via hostname first minus any realm
        hostname = host.name.split(".")[0]
        search_headers = {"TMV1-Query": "endpointName eq '{}'".format(hostname)}
        self.logger.debug("Search headers:{}".format(search_headers))
        results = host_search(search_headers)
        if results.ok:
            if len(results.json()["items"]) == 1:
                return [results.json()["items"][0].get("agentGuid")]
        else:
            self.logger.debug("Search failed on hostname:{}".format(hostname))
        # Search via IP
        search_headers = {"TMV1-Query": "ip eq '{}'".format(host.ip)}
        self.logger.debug("Search headers:{}".format(search_headers))
        results = host_search(search_headers)
        if results.ok:
            if len(results.json()["items"]) == 1:
                return [results.json()["items"][0].get("agentGuid")]
        else:
            self.logger.debug("Search failed on IP:{}".format(host.ip))
        # Search via MACs
        for mac in host.mac_addresses:
            search_headers = {"TMV1-Query": "macAddress eq '{}'".format(mac)}
            self.logger.debug("Search headers:{}".format(search_headers))
            results = host_search(search_headers)
            if results.ok:
                if len(results.json()["items"]) == 1:
                    return [results.json()["items"][0].get("agentGuid")]
            else:
                self.logger.debug("Search failed on mac:{}".format(mac))
        self.logger.info(
            "Unable to find host: {} via hostname, IP, or MAC address".format(host.name)
        )
        return []

    def _set_isolation(self, comp_id, action, hostname):
        """
        Sets the computer's firewall isolation status to provided value
        :param comp_id:
        :param value:
        :return:
        """
        body = [
            {
                "description": "Vectra {} host {}".format(action, hostname),
                "agentGuid": comp_id,
            }
        ]
        try:
            results = requests.post(
                self.url + "response/endpoints/{}".format(action),
                headers=self.headers,
                json=body,
                verify=self.verify,
            )
            self.logger.debug("isolation response:{}".format(results.content))
        except requests.exceptions.Timeout:
            self.logger.debug(
                "VisionOne isolation API response timeout, trying second attempt."
            )
            results = requests.post(
                self.url + "response/endpoints/{}".format(action),
                headers=self.headers,
                json=body,
                verify=self.verify,
            )
            self.logger.debug("isolation response:{}".format(results.content))
        return results

    def block_host(self, host: VectraHost) -> list:
        ip_address = host.ip
        computers = self._search_computer(host)
        if len(computers) == 1:
            self.logger.info(
                "Requesting VisionOne isolation of computer with agentGuid {} and IP {}".format(
                    computers[0], ip_address
                )
            )
            results = self._set_isolation(computers[0], "isolate", host.name)
            if results.ok:
                self.logger.info(
                    "Successfully  isolation of computer with agentGuid {} and IP {}".format(
                        computers[0], ip_address
                    )
                )
                return [computers[0]]
            else:
                self.logger.info(
                    "Unable to isolate computer with ID {} and IP {}. {}".format(
                        computers[0], ip_address, results.content
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
        comp_ids = host.blocked_elements.get(self.__class__.__name__, [])
        un_isolated = []
        if len(comp_ids) >= 1:
            for comp_id in comp_ids:
                self.logger.info(
                    "Requesting VisionOne un-isolation of computer with ID {} and IP {}".format(
                        comp_id, host.ip
                    )
                )
                results = self._set_isolation(comp_id, "restore", host.name)

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
        self.logger.warning(
            "CloudOne client does not implement destination IP blocking"
        )
        return []

    def unblock_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "CloudOne client does not implement destination IP blocking"
        )
        return []
        # this client only implements Host-based blocking
        self.logger.warning(
            "CloudOne client does not implement destination IP blocking"
        )
        return []

    def unblock_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "CloudOne client does not implement destination IP blocking"
        )
        return []
