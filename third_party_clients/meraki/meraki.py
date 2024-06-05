import json
import logging

import keyring
import requests
import urllib3
from third_party_clients.meraki.meraki_config import (
    BLOCK_GROUP_POLICY,
    BLOCK_INACTIVE_CLIENTS,
    BLOCK_MULTIPLE_IP,
    BLOCK_MULTIPLE_MAC,
    MERAKI_URL,
    PORT_SCHEDULE,
    VERIFY,
)
from third_party_clients.third_party_interface import (
    ThirdPartyInterface,
    VectraAccount,
    VectraDetection,
    VectraHost,
    VectraStaticIP,
)

from common import _get_password

urllib3.disable_warnings()


class HTTPException(Exception):
    pass


class Client(ThirdPartyInterface):
    @staticmethod
    def get_orgs(urlbase, headers, verify, logger) -> list:
        """
        Obtains list of organization IDs from Meraki API
        :return: list of organization IDs
        """
        results = requests.get(
            urlbase + "/organizations", headers=headers, verify=verify
        )
        if results.ok:
            return [org.get("id") for org in results.json()]
        else:
            logger.error(
                "Unable to retrieve organizations for Meraki API.  Error message:{}".format(
                    results.reason
                )
            )
            return []

    def get_network_devices(self) -> dict:
        network_inv_list = []
        for org in self.orgs:
            r = requests.get(
                self.urlbase + "/organizations/{}/devices/availabilities".format(org),
                headers=self.headers,
                verify=self.verify,
            )
            if r.ok:
                network_inv_list += r.json()
        self.logger.debug("network_inv_list: {}".format(network_inv_list))
        if len(network_inv_list) > 0:
            network_inv_dict = {}
            for i in network_inv_list:
                network_inv_dict[i.get("mac")] = {
                    "name": i.get("name"),
                    "product_type": i.get("productType"),
                    "serial": i.get("serial"),
                }
            return network_inv_dict
        else:
            return {}

    def __init__(self, **kwargs):
        self.name("Meraki Client")
        self.urlbase = MERAKI_URL.strip("/")
        self.token = _get_password("Meraki", "API_Key", modify=kwargs["modify"])
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + self.token,
        }
        self.logger = logging.getLogger("Meraki")
        self.verify = VERIFY
        self.multi_ip = BLOCK_MULTIPLE_IP
        self.multi_mac = BLOCK_MULTIPLE_MAC
        self.orgs = self.get_orgs(self.urlbase, self.headers, self.verify, self.logger)
        self.block_policy = (
            BLOCK_GROUP_POLICY if bool(BLOCK_GROUP_POLICY) else "Blocked"
        )
        self.network_device_inventory = self.get_network_devices()
        self.port_schedule_name = PORT_SCHEDULE if bool(PORT_SCHEDULE) else "Blocked"
        # Instantiate parent class
        ThirdPartyInterface.__init__(self)

    def block_host(self, host):
        # if host.ip == '192.168.0.209':
        #     host.mac_addresses = ['30:24:a9:96:b9:b4', 'a4:97:b1:5e:79:1f']
        self.logger.info(
            "Meraki host block request for:{}:{}".format(host.ip, host.mac_addresses)
        )
        # Retrieve client_id
        # [{'id': 'kcd012f', 'net_id': 'N_644014746713985158', 'mac': '30:24:a9:96:b9:b4', 'description': 'BEDENNB131'}]

        client_list = self._get_client_id(
            host.ip, host.mac_addresses, host.last_seen_ts_utc
        )
        if len(client_list) < 1:
            self.logger.info(
                "Unable to find client ID for:{}:{}, not blocking.".format(
                    host.ip, host.mac_addresses
                )
            )
            return []
        if len(client_list) > 1 and not (self.multi_mac or self.multi_mac):
            self.logger.info(
                "More than 1 client found for:{}:{}, and multi-blocking not allowed. \
                             Not blocking.".format(
                    host.ip, host.mac_addresses
                )
            )
            return []
        if len(client_list) == 1 or (
            len(client_list) > 1 and (self.multi_mac or self.multi_mac)
        ):
            blocked_list = []
            self.logger.info(
                "{} Client(s) found for:{}, iterating.".format(
                    len(client_list), host.name
                )
            )
            for client in client_list:
                self.logger.info(
                    "Client(s) found for:{}:{}, blocking.".format(host.ip, client["id"])
                )
                # Determine connection type and if host is blockable
                conn_type, blockable = self._get_block_type(client)
                if blockable:
                    if conn_type == "WLAN":
                        # Get policy to store for unblocking request
                        client_policy = self._get_client_policy(
                            client["net_id"], client["id"]
                        )
                        if client_policy.ok:
                            policy_obj = client_policy.json()
                            self.logger.debug(
                                "Retrieved clients current policy object: {}".format(
                                    policy_obj
                                )
                            )
                        else:
                            # Unable to retrieve policy object
                            self.logger.error(
                                "Unable to retrieve policy object for client: {}".format(
                                    client["id"]
                                )
                            )
                        # attempt to block
                        res = self._block_client(client)
                        if res.ok:
                            self.logger.info(
                                "Client {} with ID {} successfully blocked.".format(
                                    client["description"], client["id"]
                                )
                            )
                            blocked_list.append(
                                "WLAN:{}:{}:{}".format(
                                    client["id"],
                                    client["net_id"],
                                    policy_obj["devicePolicy"],
                                )
                            )
                        else:
                            self.logger.info(
                                "Error blocking client.  Error message: {}.".format(
                                    res.reason
                                )
                            )
                    elif conn_type == "switch":
                        # 'switch' (wired), Call method to change schedule on port
                        # orig_scheduler_id = self._get_switch_port_schedule(
                        #     switch_sn=client.get('recentDeviceSerial'),
                        #     port=client.get('switchport')
                        # )
                        # self.logger.debug('Original scheduler: {}'.format(orig_scheduler_id))
                        # new_scheduler_id = self._get_port_schedule_id(network=client['net_id'])
                        # self.logger.debug('New scheduler: {}'.format(new_scheduler_id))
                        # if orig_scheduler_id is not None and new_scheduler_id is not None:
                        #     res = self._set_switchport_scheduler(
                        #         switch_sn=client.get('recentDeviceSerial'),
                        #         port=client.get('switchport'),
                        #         scheduler_id=new_scheduler_id
                        #     )
                        #     blocked_list.append('LAN:{}:{}:{}:{}'.format(
                        #         client['id'],
                        #         client.get('recentDeviceSerial'),
                        #         client.get('switchport'),
                        #         orig_scheduler_id
                        #     ))
                        self.logger.info(
                            "Attempting to disable port {} on switch {}".format(
                                client.get("switchport"),
                                client.get("recentDeviceSerial"),
                            )
                        )
                        res = self._set_switchport_state(
                            switch_sn=client.get("recentDeviceSerial"),
                            port=client.get("switchport"),
                            state=False,
                        )
                        if res.ok:
                            self.logger.info(
                                "Disabled port {} on switch {} for client {}".format(
                                    client.get("switchport"),
                                    client.get("recentDeviceSerial"),
                                    client["id"],
                                )
                            )
                            blocked_list.append(
                                "LAN:{}:{}:{}".format(
                                    client["id"],
                                    client.get("recentDeviceSerial"),
                                    client.get("switchport"),
                                )
                            )
                        else:
                            self.logger.info(
                                "Unable to set port enable status: {}.".format(
                                    res.content
                                )
                            )
                else:
                    self.logger.info(
                        "{} attached host {} not blockable".format(
                            conn_type, client["id"]
                        )
                    )
            return blocked_list

    def unblock_host(self, host):
        blocked_elements = host.blocked_elements.get(self.__class__.__name__, [])
        unblocked_elements = []
        for client_network in blocked_elements:
            self.logger.debug("client_network from tag:{}".format(client_network))
            net_type = client_network.split(":")[0]

            if net_type == "WLAN":
                client_id = client_network.split(":")[1]
                network_id = client_network.split(":")[2]
                device_policy = client_network.split(":")[3]
                self.logger.debug(
                    "Meraki {} host unblock request for host:{} client:{}, network:{}, policy:{}".format(
                        net_type, host.name, client_id, network_id, device_policy
                    )
                )
                res = self._unblock_client(client_id, network_id, device_policy)
                if res.ok:
                    self.logger.debug(
                        "Meraki host unblock request successful for host:{} client:{}, network:{}, "
                        "policy:{}".format(
                            host.name, client_id, network_id, device_policy
                        )
                    )
                    unblocked_elements.append(client_network)
                else:
                    self.logger.debug(
                        "Meraki host unblock request unsuccessful for host:{} client:{}, network:{}, "
                        "policy:{}".format(
                            host.name, client_id, network_id, device_policy
                        )
                    )
                    unblocked_elements.append(client_network)
            else:
                client_id = client_network.split(":")[1]
                switch_sn = client_network.split(":")[2]
                switch_port = client_network.split(":")[3]
                # scheduler_id = client_network.split(':')[4] if client_network.split(':')[4] != 'No_Scheduler' \
                #     else None
                self.logger.debug(
                    "Meraki {} host unblock request for host:{} client:{}, switch_sn:{}, switch_port:{}".format(
                        net_type, host.name, client_id, switch_sn, switch_port
                    )
                )
                # results = self._set_switchport_scheduler(switch_sn, switch_port, scheduler_id)
                results = self._set_switchport_state(
                    switch_sn=switch_sn, port=switch_port, state=True
                )
                if results.ok:
                    self.logger.info(
                        "Meraki {} host unblock successful for host:{} client:{}, switch_sn:{}, switch_port:{}".format(
                            net_type, host.name, client_id, switch_sn, switch_port
                        )
                    )
                    # unblocked_elements.append(scheduler_id)
                    unblocked_elements.append(client_network)
                else:
                    self.logger.info(
                        "Meraki {} host unblock unsuccessful for host:{} client:{}, switch_sn:{}, switch_port:{}, \
                         {}".format(
                            net_type,
                            host.name,
                            client_id,
                            switch_sn,
                            switch_port,
                            results.content,
                        )
                    )
        return unblocked_elements

    def groom_host(self, host) -> dict:
        """
        Method to determine if currently blocked client exists based on client id
        :param host: Vectra host object
        :return: return {'block': host, 'unblock': host.blocked_elements}
        """
        self.logger.info(
            "Groom host called.  Host tags: {}".format(host.blocked_elements)
        )
        meraki_blocked_elements = host.blocked_elements.get("MerakiClient")
        if meraki_blocked_elements:
            clients_list = self._get_client_id(
                host.ip, host.mac_addresses, host.last_seen_ts_utc
            )
            for element in meraki_blocked_elements:
                if element.split(":")[0] in clients_list:
                    # Client found by blocked ClientID, don't do anything
                    self.logger.info(
                        "Host grooming client still active, doing nothing."
                    )
                    return {"block": False, "unblock": False}
                else:
                    # Client not found, return host object to be blocked, return blocked_elements to unblock
                    self.logger.info(
                        "Host grooming client not found, requesting original client to unblock and current"
                        " client to block."
                    )
                    return {"block": True, "unblock": True}
        else:
            # No Meraki blocked elements
            return {"block": False, "unblock": False}

    def block_detection(self, detection):
        self.logger.warning("Meraki client does not implement detection-based blocking")
        return []

    def unblock_detection(self, detection):
        self.logger.warning("Meraki client does not implement detection-based blocking")
        return []

    def block_account(self, account: VectraAccount) -> list:
        self.logger.warning("Meraki client does not implement account-based blocking")
        return []

    def unblock_account(self, account: VectraAccount) -> list:
        self.logger.warning("Meraki client does not implement account-based blocking")
        return []

    def block_static_dst_ips(self, ips: VectraStaticIP) -> list:
        self.logger.warning("Meraki client does not implement static IP-based blocking")
        return []

    def unblock_static_dst_ips(self, ips: VectraStaticIP) -> list:
        self.logger.warning("Meraki client does not implement static IP-based blocking")
        return []

    def _get_networks(self):
        """
        Obtains and returns a list of network IDs based on the list of organizations.
        :return: list of networks
        """
        networks = []
        for org in self.orgs:
            result = None
            result = requests.get(
                url=self.urlbase + "/organizations/{}/networks/".format(org),
                headers=self.headers,
                verify=self.verify,
            )
            for item in result.json():
                networks.append(item.get("id"))
        return networks

    def _get_client(self, network_id, client_id):
        """
        Obtains client by client ID
        :param network_id: client's network id
        :param client_id: client's id
        :return: requests response
        """
        if network_id and client_id:
            result = requests.get(
                url=self.urlbase
                + "/networks/{}/clients/{}".format(network_id, client_id),
                headers=self.headers,
                verify=self.verify,
            )
            return result
        else:
            return None

    def _get_client_policy(self, network_id, client_id):
        """
        Obtains clients policy
        :param network_id: client's network id
        :param client_id: client's id
        :return: requests response
        """
        if network_id and client_id:
            result = requests.get(
                url=self.urlbase
                + "/networks/{}/clients/{}/policy".format(network_id, client_id),
                headers=self.headers,
                verify=self.verify,
            )
            return result
        else:
            return None

    def _get_client_id(self, ip, macs, last_seen):
        """
        Searches for the client over the list of retrieved network IDs.  Switch self.inactive controls whether or not
        inactive clients are returned or not
        :param ip: IP of host to search for
        :param macs: MAC list of host to search for
        :last_seen: last seen timestamp
        :return: A list of dictionary items containing the network ID and client ID, mac, and hostname
         of the host with the provided IP
        """
        networks = self._get_networks()
        ret_list = []
        # search by MAC first if single MAC present or allowed to block multiple MACs
        if len(macs) == 1 or (len(macs) > 1 and self.multi_mac):
            for net_id in networks:
                for mac in macs:
                    self.logger.debug("Searching based on MAC: {}".format(mac))
                    # Search for host with MAC address starting 7 days prior to Detect's last_seen time for host
                    params = {"mac": mac, "t0": last_seen - 604800}
                    result = requests.get(
                        url=self.urlbase + "/networks/{}/clients".format(net_id),
                        headers=self.headers,
                        params=params,
                        verify=self.verify,
                    )
                    if result.ok:
                        if len(result.json()) > 0:
                            self.logger.debug(
                                "Found client(s) based on MAC.{}, {}".format(
                                    mac, result.json()
                                )
                            )
                            ret_list += [
                                {
                                    "id": i["id"],
                                    "net_id": net_id,
                                    "mac": i["mac"],
                                    "description": i["description"],
                                    "switchport": i.get("switchport"),
                                    "recentDeviceMac": i.get("recentDeviceMac"),
                                    "recentDeviceSerial": i.get("recentDeviceSerial"),
                                    "ssid": i.get("ssid"),
                                    "status": i.get("status"),
                                    "recentDeviceConnection": i.get(
                                        "recentDeviceConnection"
                                    ),
                                }
                                for i in result.json()
                            ]
                    else:
                        self.logger.error(
                            "Unable to search via MAC address: {}".format(
                                result.content
                            )
                        )
        elif len(ret_list) < 1:
            for net_id in networks:
                params = {"ip": ip, "t0": last_seen - 604800}
                result = requests.get(
                    url=self.urlbase + "/networks/{}/clients".format(net_id),
                    headers=self.headers,
                    params=params,
                    verify=self.verify,
                )
                if result.ok:
                    if len(result.json()) == 1 or (
                        len(result.json()) > 1 and self.multi_ip
                    ):
                        ret_list += [
                            {
                                "id": i["id"],
                                "net_id": net_id,
                                "mac": i["mac"],
                                "description": i["description"],
                                "switchport": i.get("switchport"),
                                "recentDeviceMac": i.get("recentDeviceMac"),
                                "recentDeviceSerial": i.get("recentDeviceSerial"),
                                "ssid": i.get("ssid"),
                                "status": i.get("status"),
                                "recentDeviceConnection": i.get(
                                    "recentDeviceConnection"
                                ),
                            }
                            for i in result.json()
                        ]
                    else:
                        self.logger.info(
                            "Search by IP {} returned {} clients, no clients found or \
                                         multiple clients not allowed.".format(
                                ip, len(result.json())
                            )
                        )
                else:
                    self.logger.error(
                        "Unable to search via IP address: {}".format(result.content)
                    )

        return ret_list

    def _block_client(self, client):
        """
        Block client by updating client's policy to 'Block'.

        :param client: Client object
        :return:  request's response object
        """
        # https://developer.cisco.com/meraki/api-latest/#!update-network-client-policy
        body = {"devicePolicy": self.block_policy}
        self.logger.debug("Device block policy: {}".format(body))
        response = requests.put(
            self.urlbase
            + "/networks/{}/clients/{}/policy".format(
                client.get("net_id"), client.get("id")
            ),
            headers=self.headers,
            data=json.dumps(body),
            verify=self.verify,
        )
        self.logger.debug("Block request response: {}".format(response.text))
        return response

    def _unblock_client(self, client_id, net_id, policy_id):
        """
        Unblock client by updating client's policy to 'Normal'
        :param client_id: client id
        :param net_id: network id
        :param policy_id: policy id to set
        :return:  request's response object
        """
        # body = {"devicePolicy": "Normal"}
        body = {"devicePolicy": policy_id}
        response = requests.put(
            self.urlbase + "/networks/{}/clients/{}/policy".format(net_id, client_id),
            headers=self.headers,
            data=json.dumps(body),
            verify=self.verify,
        )
        return response

    def _set_switchport_scheduler(self, switch_sn, port, scheduler_id=None):
        """
        Sets the scheduler ID on a switchport.  Setting null removes the scheduler
        :param switch_sn:
        :param port:
        :param scheduler_id: scheduler ID, null for None
        :return:
        """
        body = {"portScheduleId": scheduler_id}
        results = requests.put(
            self.urlbase + "/devices/{}/switch/ports/{}".format(switch_sn, port),
            headers=self.headers,
            json=body,
            verify=self.verify,
        )
        return results

    def _set_switchport_state(self, switch_sn, port, state=True):
        """
        Sets the switchport 'enabled' state on a switchport.
        :param switch_sn:
        :param port:
        :param state: True or False
        :return:
        """
        body = {"enabled": state}
        results = requests.put(
            self.urlbase + "/devices/{}/switch/ports/{}".format(switch_sn, port),
            headers=self.headers,
            json=body,
            verify=self.verify,
        )
        return results

    def _get_block_type(self, client):
        """
        Determines if client is connected to WLAN or Switch and if ok to block
        :param client: client dictionary
        :return: 'dev type', boolean
        """
        self.logger.debug("_get_block_type client: {}".format(client))
        if (
            client.get("switchport")
            and client.get("recentDeviceSerial")
            and client.get("recentDeviceConnection") == "Wired"
            and not client.get("ssid")
        ):
            ports = requests.get(
                self.urlbase
                + "/devices/{}/switch/ports/statuses".format(
                    client.get("recentDeviceSerial")
                ),
                headers=self.headers,
                verify=self.verify,
            )
            if ports.ok:
                for port in ports.json():
                    if client.get("switchport") == port.get("portId"):
                        if port.get("isUplink"):
                            self.logger.info(
                                "Client {} shows connected to uplink {}.".format(
                                    client.get("id"), port.get("portId")
                                )
                            )
                            return "switch", False
                        elif port.get("clientCount") > 1:
                            self.logger.info(
                                "Port show more than 1 client on port: {}".format(
                                    port.get("clientCount")
                                )
                            )
                            return "switch", False
                        else:
                            return "switch", True
            else:
                self.logger.error(
                    "Unable to retrieve switchport information: {}".format(
                        ports.content
                    )
                )
        if client.get("ssid") and client.get("recentDeviceConnection") == "WLAN":
            return "WLAN", True
        else:
            return "unknown", False

    def _get_switch_port_schedule(self, switch_sn, port):
        """
        Returns the port schedule ID of the supplied switch port
        :param switch_sn: serial of switch
        :param port: port number of switch
        :return: int
        """
        results = requests.get(
            self.urlbase + "/devices/{}/switch/ports/{}".format(switch_sn, port),
            headers=self.headers,
            verify=self.verify,
        )
        if results.ok:
            if results.json().get("portScheduleId") is None:
                return "No_Scheduler"
            else:
                return results.json().get("portScheduleId")
        else:
            self.logger.info(
                "Unable to obtain port scheduler information for switch: {}, port:{}. {}".format(
                    switch_sn, port, results.content
                )
            )
            return None

    def _get_port_schedule_id(self, network):
        """
        :return:
        """
        params = {"name": self.port_schedule_name}
        results = requests.get(
            self.urlbase + "/networks/{}/switch/portSchedules".format(network),
            headers=self.headers,
            params=params,
            verify=self.verify,
        )
        if results.ok:
            if len(results.json()) == 1:
                return results.json()[0].get("id")
            else:
                self.logger.info(
                    "More than one port schedule found with name: {}".format(
                        self.port_schedule_name
                    )
                )
                return None
        else:
            self.logger.info(
                "Unable to retrieve port schedule for network {}".format(network)
            )
            return None
