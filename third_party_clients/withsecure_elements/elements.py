import base64
import logging
from datetime import datetime, timedelta

import requests
from cachetools import TTLCache, cached
from third_party_clients.third_party_interface import (
    ThirdPartyInterface,
    VectraAccount,
    VectraDetection,
    VectraHost,
    VectraStaticIP,
)
from third_party_clients.withsecure_elements.elements_config import (
    BASE_URL,
    VERIFY,
)

from common import _get_password


class Client(ThirdPartyInterface):
    def __init__(self, **kwargs):
        self.name = "WithSecureElements Client"
        self.logger = logging.getLogger()
        self.url = BASE_URL
        self.verify = VERIFY
        self.auth = (
            _get_password("Elements", "Client_ID", modify=kwargs["modify"]),
            _get_password("Elements", "API_Key", modify=kwargs["modify"]),
        )
        self.organization_id = _get_password(
            "Elements", "Org_UUID", modify=kwargs["modify"]
        )

        self.oauth_expiry = datetime.fromtimestamp(0)
        self.oauth_token = ""
        self.headers = {}
        # Instantiate parent class
        ThirdPartyInterface.__init__(self)

    def _check_timeout(self):
        if self.oauth_expiry > datetime.now():
            return
        else:
            self._oauth()

    def _oauth(self):
        self.logger.debug("auth_string:{}".format(self.auth))
        self.auth_headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "VectraActiveEnforcement2.0",
        }
        self.logger.debug("{}".format(self.auth_headers))
        body = "grant_type=client_credentials&scope=connect.api.write&scope=connect.api.read"
        r = requests.post(
            self.url + "/as/token.oauth2",
            headers=self.auth_headers,
            data=body,
            auth=self.auth,
            verify=self.verify,
        )
        if r.ok:
            self.oauth_expiry = datetime.now() + timedelta(
                seconds=r.json()["expires_in"] - 60
            )
            self.oauth_token = r.json()["access_token"]
            self.headers = {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + self.oauth_token,
            }
        else:
            self.logger.error("Unable to obtain OAuth token: {}".format(r.content))

    def _host_search(self, search_params={}):
        host_list = []
        next_anchor = False
        params = {
            **search_params,
            **{"organizationId": self.organization_id, "type": "computer"},
        }
        r = requests.get(
            self.url + "/devices/v1/devices",
            headers=self.headers,
            params=params,
            verify=self.verify,
        )
        if r.ok:
            host_list += r.json().get("items", [])
            anchor = r.json().get("nextAnchor", False)
            params["anchor"] = anchor
        else:
            anchor = False
            self.logger.error(
                "Unable to retrieve host, query: {}, error:{}".format(anchor, r.content)
            )
        # self.logger.debug('host search headers:{}'.format({**self.headers, **search_header}))
        while anchor:
            r = requests.get(
                self.url + "/devices/v1/devices",
                headers=self.headers,
                params=params,
                verify=self.verify,
            )
            if r.ok:
                host_list += r.json().get("items", [])
                anchor = r.json().get("nextAnchor")
                params["anchor"] = anchor
            else:
                anchor = False
                self.logger.error(
                    "Unable to retrieve host, query: {}, error:{}".format(
                        anchor, r.content
                    )
                )
        return host_list

    @cached(cache=TTLCache(maxsize=4480000, ttl=1200))
    def _get_all_hosts(self):
        return self._host_search()

    def _search_computer(self, host: VectraHost) -> list:
        """
        Searches for computer first by hostname, then IP, lastly MAC addresses
        :param host:VectraHost: vectra host object to search for
        :return: list of endpoint IDs
        """
        self._check_timeout()
        # Search via hostname first minus any realm
        hostname = host.name.split(".")[0]
        self.logger.debug("Search for host by hostname:{}".format(hostname))
        results = self._host_search({"name": hostname})
        if len(results) == 1:
            return [results[0].get("id")]
        else:
            self.logger.info("Search failed on hostname:{}".format(hostname))

        self.logger.info("Retrieving all hosts")
        results = self._get_all_hosts()
        if len(results) > 0:
            host_ip_list = []
            host_mac_list = []
            host_ip_mac_list = []
            for item in results:
                #  Search via IP
                ipaddresses = item.get("ipAddresses", "").split()
                if host.ip in [ip.split("/")[0] for ip in ipaddresses]:
                    host_ip_list.append(item)
                # Search via MACs
                mac_addresses = [
                    mac.lower().replace("-", "")
                    for mac in item.get("macAddresses", "").split()
                ]
                if set(host.mac_addresses) & set(mac_addresses):
                    host_mac_list.append(item)
            if host_ip_list:
                for i in host_ip_list:
                    if i.get("id") in [x.get("id") for x in host_mac_list]:
                        host_ip_mac_list.append(i)
                if host_ip_mac_list:
                    return [i.get("id") for i in host_ip_mac_list]
                else:
                    return (
                        [i.get("id") for i in host_mac_list]
                        if host_mac_list
                        else [i.get("id") for i in host_ip_list]
                    )
            else:
                return [i.get("id") for i in host_mac_list]

    def _set_isolation(self, comp_id, action, host: VectraHost):
        """
        Sets the computer's isolation status to provided value
        :param comp_id:
        :param value:
        :return:
        """
        self._check_timeout()
        body = {"operation": action, "targets": [comp_id]}
        if action == "isolateFromNetwork":
            body["parameters"] = {
                "message": "Your device will be isolated by Vectra, Host ID: {}".format(
                    host.id
                )
            }

        results = requests.post(
            self.url + "/devices/v1/operations",
            headers=self.headers,
            json=body,
            verify=self.verify,
        )
        if results.ok:
            self.logger.debug("isolation request {} successful".format(action))
        else:
            self.logger.error(
                "isolation request {} failed, response:{}".format(
                    action, results.content
                )
            )
        return results

    def block_host(self, host: VectraHost) -> list:
        ip_address = host.ip
        computers = self._search_computer(host)
        self.logger.info("WithSecure block host, computers: {}".format(computers))
        if len(computers) == 1:
            self.logger.info(
                "Requesting WithSecure isolation of computer with ID {} and IP {}".format(
                    computers[0], ip_address
                )
            )
            results = self._set_isolation(computers[0], "isolateFromNetwork", host)
            if results.ok:
                self.logger.info(
                    "Successfully  isolation of computer with agent ID {} name {}and IP {}".format(
                        computers[0], host.name, ip_address
                    )
                )
                return [computers[0]]
            else:
                self.logger.error(
                    "Unable to isolate computer with ID {} and IP {}. {}".format(
                        computers[0], ip_address, results.content
                    )
                )
                return []
        elif len(computers) == 0:
            self.logger.info(
                "No computers ({}) were found with IP: {}, name: {}, MACs: {}".format(
                    len(computers), ip_address, host.name, host.mac_addresses
                )
            )
            return []
        else:
            self.logger.info(
                "More than 1 computers ({}) were found with IP: {}, name: {}, MACs: {}".format(
                    len(computers), ip_address, host.name, host.mac_addresses
                )
            )
            return []

    def unblock_host(self, host: VectraHost) -> list:
        comp_ids = host.blocked_elements.get(self.name, [])
        un_isolated = []
        if len(comp_ids) >= 1:
            for comp_id in comp_ids:
                self.logger.info(
                    "Requesting WithSecure un-isolation of computer with ID {} and IP {}".format(
                        comp_id, host.ip
                    )
                )
                results = self._set_isolation(
                    comp_id, "releaseFromNetworkIsolation", host
                )

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
        self.logger.warning("WithSecure client does not implement host grooming")
        return []

    def block_detection(self, detection: VectraDetection) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "WithSecure client does not implement detection-based blocking"
        )
        return []

    def unblock_detection(self, detection: VectraDetection) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "WithSecure client does not implement detection-based blocking"
        )
        return []

    def block_account(self, account: VectraAccount) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "WithSecure client does not implement account-based blocking"
        )
        return []

    def unblock_account(self, account: VectraAccount) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "WithSecure client does not implement account-based blocking"
        )
        return []

    def block_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "WithSecure client does not implement destination IP blocking"
        )
        return []

    def unblock_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "WithSecure client does not implement destination IP blocking"
        )
        return []
