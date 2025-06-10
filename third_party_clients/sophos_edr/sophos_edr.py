import logging
import requests

from common import _get_password
from third_party_clients.sophos_edr.sophos_edr_config import (
    AUTH_URL,
    WHOAMI_URL,
    VERIFY,
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
        self.name = "SophosEDR Client"
        self.module = "sophos_edr"
        self.init_log(kwargs)
        self.auth_url = AUTH_URL
        self.whoami_url = WHOAMI_URL
        self.verify = VERIFY
        self.client_id = _get_password("SophosEDR", "client_id", modify=kwargs["modify"])
        self.client_secret = _get_password("SophosEDR", "client_secret", modify=kwargs["modify"])
        try:
            self.token = self.get_bearer_tok(self.client_id, self.client_secret, self.auth_url)
            self.headers = {
                        "Authorization": f"Bearer {self.token}",
                        "Accept": "application/json"
                        }
            self.get_whoami_data()
        except Exception as e:
            self.logger.error("SophosEDR connection issue")
            raise e
        # Instantiate parent class
        ThirdPartyInterface.__init__(self)

    def init_log(self, kwargs):
        dict_config = kwargs.get("dict_config", {})
        dict_config["loggers"].update({self.name: dict_config["loggers"]["VAR"]})
        logging.config.dictConfig(dict_config)
        self.logger = logging.getLogger(self.name)

    def get_bearer_tok(self, client_id, client_secret, auth_url):
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data_tok = f"grant_type=client_credentials&client_id={client_id}&client_secret={client_secret}&scope=token"

        # post the url and api key information to obtain access_token
        self.logger.debug("Getting the bearer token for Sophos Central API")
        res = requests.post(auth_url, headers=headers, data=data_tok)
        res_code = res.status_code
        res_data = res.json()
        # Check the response and act accordingly
        if res_code == 200:
            # Send back the access token and headers
            sophos_access_token = res_data['access_token']
            self.logger.debug("Successfully obtained the bearer token")
            return sophos_access_token
        else:
            # Failed to obtain a bearer token
            self.logger.debug("Failed to obtain the bearer token")
            res_error_code = res_data['errorCode']
            res_message = "Response Code: {0} Message: {1}".format(res_code, res_data['message'])
            return None, res_message, res_error_code

    def get_whoami_data(self, whoami_url=WHOAMI_URL):
        # send the request to get the whoami id details
        self.logger.debug("Attempting to get whoami ID")
        try:
            res_whoami = requests.get(whoami_url, headers=self.headers)
            res_whoami.raise_for_status()
        except requests.exceptions.RequestException as res_exception:
            self.logger.error("Failed to obtain the whoami ID")
            self.logger.error(res_exception)
            raise res_exception
        else:
            whoami_data = res_whoami.json()
            self.headers['X-Tenant-ID'] = whoami_data['id']
            self.dataRegion = whoami_data.get('apiHosts', {}).get('dataRegion', '')
            self.logger.debug("Successfully obtained whoami ID")

    def _list_endpoint(self, host: VectraHost) -> list:
        """
        Searches for computer first IP addresses
        :param host:VectraHost: vectra host object to search for
        :return: list of endpoint IDs
        """
        # Search via IP
        search_endpoint_url = f'{self.dataRegion}/endpoint/v1/endpoints'
        params = {
                "ipAddresses": [host.ip]
                # Should add Last Seen Value
                }
        result = requests.get(search_endpoint_url, headers=self.headers, params=params)
        if result.status_code == 200:
            endpoints = result.json().get('items', [])
        else:
            endpoints = []
            self.logger.error(
                    f"Error searching for {host.ip}: {result.text}"
            )
        if len(endpoints) < 1:
            self.logger.error(
                "Found no endpoints. Aborting!"
            )
            return False
        else:
            endpoint = endpoints[0]
            return endpoint

    def block_host(self, host: VectraHost) -> list:
        endpoint = self._list_endpoint(host)
        log_string = f"{host.name} with id {endpoint['id']} and IP {host.ip}"
        if not endpoint:
            return []

        self.logger.info(f"Requesting SophosEDR isolation for {log_string}")
        body = {
                "enabled": True,
                "ids": [endpoint['id']],
                "comment": "Isolating requested by Vectra integration"
                }
        isolate_url = f"{self.dataRegion}/endpoint/v1/endpoints/isolation"
        try:
            results = requests.post(isolate_url, headers=self.headers, json=body)
        except Exception as e:
            self.logger.debug(f"SophosEDR isolation failed with status: {e}")
            results = False

        if results:
            self.logger.info(f"Successfully isolated {log_string}")
            return [endpoint["id"]]
        else:
            self.logger.info(f"Unable to isolate {log_string}")
            return []

    def unblock_host(self, host: VectraHost) -> list:
        isolate_url = f"{self.dataRegion}/endpoint/v1/endpoints/isolation"
        endpoint_ids = host.blocked_elements.get(self.name, [])
        un_isolated = []
        if endpoint_ids:
            for endpoint_id in endpoint_ids:
                log_string = f"{host.name} with id {endpoint_id} and IP {host.ip}"
                body = {
                        "enabled": False,
                        "ids": [endpoint_id],
                        "comment": "Isolating requested by Vectra integration"
                        }
                try:
                    results = requests.post(isolate_url, headers=self.headers, json=body)
                except Exception as e:
                    self.logger.debug(f"SophosEDR isolation failed with status: {e}")
                    results = False

                self.logger.info(f"Requesting SophosEDR un-isolation for {log_string}")

                if results:
                    self.logger.info(f"Successfully un-isolation {log_string}")
                    un_isolated.append(endpoint_id)
                else:
                    self.logger.info(f"Unable to un-isolation {log_string}")
            return un_isolated

    def groom_host(self, host) -> list:
        self.logger.warning("SophosEDR client does not implement host grooming")
        return []

    def block_detection(self, detection: VectraDetection) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "SophosEDR client does not implement detection-based blocking"
        )
        return []

    def unblock_detection(self, detection: VectraDetection) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "SophosEDR client does not implement detection-based blocking"
        )
        return []

    def block_account(self, account: VectraAccount) -> list:
        # this client only implements Host-based blocking
        self.logger.warning("SophosEDR client does not implement account-based blocking")
        return []

    def unblock_account(self, account: VectraAccount) -> list:
        # this client only implements Host-based blocking
        self.logger.warning("SophosEDR client does not implement account-based blocking")
        return []

    def block_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "SophosEDR client does not implement destination IP blocking"
        )
        return []

    def unblock_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "SophosEDR client does not implement destination IP blocking"
        )
        return []
