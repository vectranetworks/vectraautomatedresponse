import logging
import re
from time import sleep

from common import _format_url, _get_password
from python_graphql_client import GraphqlClient
from third_party_clients.tanium.tanium_config import (
    BLOCK_PKG,
    UNBLOCK_PKG,
    URL,
)
from third_party_clients.third_party_interface import (
    ThirdPartyInterface,
    VectraAccount,
    VectraDetection,
    VectraHost,
    VectraStaticIP,
)


class HTTPException(Exception):
    pass


class Client(ThirdPartyInterface):
    def __init__(self, **kwargs):
        """
        Initialize Tanium client
        :param url: FQDN or IP of Tanium appliance - required
        :param token: Tanium API Token - required
        """
        self.name = "Tanium Client"
        self.module = "tanium"
        self.init_log(kwargs)
        self.url = f"{_format_url(URL)}/plugin/products/gateway/graphql"
        self.token = _get_password("Tanium", "Token", modify=kwargs["modify"])
        self.headers = {"Content-Type": "application/json", "session": self.token}
        self.graph_client = GraphqlClient(endpoint=self.url, headers=self.headers)

        for pkg in BLOCK_PKG:
            if "mac" in pkg.lower():
                self.block_pkg = {"Mac": pkg}
            elif "windows" in pkg.lower():
                self.block_pkg = {"Windows": pkg}
            elif "linux" in pkg.lower():
                self.block_pkg = {"Linux": pkg}

        for pkg in UNBLOCK_PKG:
            if "mac" in pkg.lower():
                self.unblock_pkg = {"Mac": pkg}
            elif "windows" in pkg.lower():
                self.unblock_pkg = {"Windows": pkg}
            elif "linux" in pkg.lower():
                self.unblock_pkg = {"Linux": pkg}

        # Instantiate parent class
        ThirdPartyInterface.__init__(self)

    def init_log(self, kwargs):
        dict_config = kwargs.get("dict_config", {})
        dict_config["loggers"].update({self.name: dict_config["loggers"]["VAR"]})
        logging.config.dictConfig(dict_config)
        self.logger = logging.getLogger(self.name)

    def block_host(self, host: VectraHost):
        try:
            node = self._get_node(host["name"])
            if node is None:
                self.logger.warning(f"{host['name']} was not found.")
                return
        except HTTPException:
            pass
        blocked_node = self._quarantaine_endpoint(node)
        return blocked_node

    def unblock_host(self, host: VectraHost):
        blocked_node = host.blocked_elements.get(self.name, [])
        node = self._get_node(blocked_node)
        if node is None:
            self.logger.warning(f"{blocked_node} was not found.")
            return
        unblocked_node = self._unquarantaine_endpoint(node)

        return unblocked_node

    def groom_host(self, host: VectraHost) -> dict:
        self.logger.warning("Tanium client does not implement host grooming")
        return []

    def block_detection(self, detection: VectraDetection):
        # this client only implements Host-based blocking
        self.logger.warning("Tanium client does not implement detection-based blocking")
        return []

    def unblock_detection(self, detection: VectraDetection):
        # this client only implements Host-based blocking
        self.logger.warning("Tanium client does not implement detection-based blocking")
        return []

    def block_account(self, account: VectraAccount) -> list:
        # this client only implements Host-based blocking
        self.logger.warning("Tanium client does not implement account-based blocking")
        return []

    def unblock_account(self, account: VectraAccount) -> list:
        # this client only implements Host-based blocking
        self.logger.warning("Tanium client does not implement account-based blocking")
        return []

    def block_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        self.logger.warning("Tanium client does not implement static IP-based blocking")
        return []

    def unblock_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        self.logger.warning("Tanium client does not implement static IP-based blocking")
        return []

    def _quarantaine_endpoint(self, node):
        """
        Put an endpoint in the Quarantaine policy based on its MAC address
        :param mac_address: MAC address of the endpoint to quarantaine - required
        :rtype: None
        """
        # Then we push the endpoint in the actual quarantaine policy
        self.logger.debug(f"Applying quarantine policy to {node['name']}")

        package, params = self._get_pkg(self.block_pkg[node["os"]["platform"]])
        action = self._deploy_pkg_to_node(node, package, params)
        id = int(action["scheduledAction"]["lastAction"]["id"])
        completed = False
        failed = False
        i = 0
        self.logger.debug(
            f"Awaiting quarantine policy for {node['name']} to be applied."
        )
        while not completed or not failed:
            if i != 12 * 5:
                status = self.get_actions(id)
                if status["results"]["completed"] == 1:
                    self.logger.debug(f"Quarantine policy applied on {node['name']}.")
                    completed = True
                    return node["name"]
                if status["results"]["failed"] == 1:
                    failed = True
                    self.logger.error(f"Quarantine action failed for {node['name']}.")
                    return None
                i += 1
                sleep(5)
            else:
                self.logger.error(
                    f"Quarantine action did not complete within 5 minutes for {node['name']}."
                )
                return None

    def _unquarantaine_endpoint(self, node):
        """
        Remove an endpoint from the Quarantaine policy based on its MAC address
        :param mac_address: MAC address of the endpoint to unquarantaine - required
        :rtype: Requests.Response
        """
        self.logger.debug(f"Removing quarantine policy from {node['name']}")

        package, params = self._get_pkg(self.unblock_pkg[node["os"]["platform"]])
        action = self._deploy_pkg_to_node(node, package, params)
        id = int(action["scheduledAction"]["lastAction"]["id"])
        completed = False
        failed = False
        i = 0
        self.logger.debug(
            f"Awaiting quarantine policy removal for {node['name']} to complete."
        )
        while not completed or not failed:
            if i != 12 * 5:
                status = self.get_actions(id)
                if status["results"]["completed"] == 1:
                    self.logger.debug(
                        f"Quarantine policy removal for {node['name']} completed."
                    )
                    completed = True
                    return node["name"]
                if status["results"]["failed"] == 1:
                    self.logger.error(f"Unquarantine action failed for {node['name']}.")
                    failed = True
                i += 1
                sleep(5)
            else:
                self.logger.error(
                    f"Unquarantine action did not complete within 5 minutes for {node['name']}."
                )
                return None

    def _get_node(self, search_term):
        query = """
            query getEndpointsByName ($path:String, $value:String){
                endpoints(filter: {path:$path,value: $value, op:STARTS_WITH}) {
                    edges {
                        node {
                            id
                            name
                            eidLastSeen
                            ipAddress
                            ipAddresses
                            macAddresses
                            os { platform }
                        }
                    }
                }
            }
        """
        self.logger.debug(f'Obtaining node information for "{search_term}"')

        if search_term.startswith("IP-"):
            search_term = search_term.split("-")[1]
        if re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", search_term):
            type = "macAddresses"
        elif re.match(r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$", search_term):
            type = "ipAddresses"
        else:
            type = "name"
        variables = {"path": type, "value": search_term}

        data = self.graph_client.execute(query=query, variables=variables)

        for resp in data["data"]["endpoints"]["edges"]:
            node = resp["node"]

        try:
            return node
        except UnboundLocalError:
            return None

    def _get_pkg(self, pkg):
        query = """
            query packageSpecs($value:String) {
                packageSpecs(filter: {path:"name",value:$value}) {
                    edges {
                        node {
                            params {
                                key
                                defaultValue
                            }
                        }
                    }
                }
            }
        """
        self.logger.debug(f'Obtaining package information for "{pkg}"')
        variables = {"value": pkg}
        data = self.graph_client.execute(query=query, variables=variables)
        for package in data["data"]["packageSpecs"]["edges"]:
            temp = package["node"]
        temp_params = {
            x["key"]: x["defaultValue"] if x["defaultValue"] is not None else ""
            for x in temp["params"]
        }
        params = []
        for param in range(1, len(temp_params) + 1):
            params.append(temp_params[f"${param}"])

        return pkg, params

    def _deploy_pkg_to_node(self, node, pkg, params):
        mutation = """
            mutation performActionOperation($name: String, $package: PackageRefInput!, $targeting: ActionTargetsInput!) {
                actionPerform(input: {
                    name: $name, 
                    package: $package, 
                    targets: $targeting
                }) {
                scheduledActions {
                    scheduledAction {
                        id
                        package { name }
                        targets { 
                            actionGroup { name }
                            targetGroup { name }
                        }
                        lastAction {
                            id
                            name
                            comment
                        }
                    }
                }
                error {
                    message
                    retryable
                    timedOut
                }
            }
        }
        """
        self.logger.debug(f"Applying \"{pkg}\" to \"{node['name']}\"")
        variables = {
            "package": {"name": pkg, "params": params},
            "name": "Vectra Automated Response",
            "comment": "VAR Action",
            "targeting": {
                "actionGroup": {"name": "Default - All Computers"},
                "targetGroup": {"name": "Default - All Computers"},
                "endpoints": [node["id"]],
                "platforms": [node["os"]["platform"]],
            },
        }
        try:
            data = self.graph_client.execute(query=mutation, variables=variables)
        except Exception as err:
            self.logger.error(err)
        for action in data["data"]["actionPerform"]["scheduledActions"]:
            return action

    def get_actions(self, id):
        query = """
            query getActionStatus($ref: IdRefInput!){
                action(ref: $ref){
                    status
                    results {
                        completed
                        downloading
                        expired
                        failed
                        failedVerification
                        id
                        pendingVerification
                        running
                        verified
                        waiting
                        waitingToRetry
                    }
                }   
            }
        """

        variables = {"ref": {"id": id}}

        data = self.graph_client.execute(query=query, variables=variables)
        return data["data"]["action"]
