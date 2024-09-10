import logging
import fortiedr

from common import _get_password
from third_party_clients.third_party_interface import (
    ThirdPartyInterface,
    VectraAccount,
    VectraDetection,
    VectraHost,
    VectraStaticIP,
)
from third_party_clients.forti_edr.forti_edr_config import (
    BASE_URL,
    ORGANIZATION,
    VERIFY,
)


class Client(ThirdPartyInterface):
    def __init__(self, **kwargs):
        self.name = "FortiEDR Client"
        self.logger = logging.getLogger()
        self.url = BASE_URL
        self.org = ORGANIZATION
        self.verify = VERIFY
        self.user = _get_password("FortiEDR", "user", modify=kwargs["modify"])
        self.password = _get_password("FortiEDR", "password", modify=kwargs["modify"])
        try:
            auth = fortiedr.auth(
                user=self.user,
                passw=self.password,
                host=self.url,  # use only the hostname, without 'https://'
                org=self.org,  # Add organization IF needed.
            )
            if not auth["status"]:
                raise auth["data"]

        except Exception as e:
            self.logger.error("FortiEDR connection issue")
            raise e
        # Instantiate parent class
        ThirdPartyInterface.__init__(self)

    def _list_collector(self, host: VectraHost) -> list:
        """
        Searches for computer first by IP addresses
        :param host:VectraHost: vectra host object to search for
        :return: list of endpoint IDs
        """
        # Search via IP
        collectors = fortiedr.SystemInventory().list_collectors(ips=[host.ip])
        collectors = collectors.get("data")
        if len(collectors) != 1:
            self.logger.error(
                "Found no collectors or multiple collectors with same IP. Aborting!"
            )
            return False
        else:
            collector = collectors[0]
            # check collector name(including domainname) vs hostname
            if not f"{collector.get('name')}.{collector.get('domainDnsName')}".startswith(
                host.name
            ):
                self.logger.error(
                    f"Collector name {collector.get('name')}.{collector.get('domainDnsName')} \
                        does not match Vectra hostname {host.name}!"
                )
                return False
            else:
                self.logger.info("Collector name matches Vectra host name")
                return collector

    def block_host(self, host: VectraHost) -> list:
        collector = self._list_collector(host)
        log_string = f"{host.name} with id {collector['id']} and IP {host.ip}"
        if not collector:
            return []

        self.logger.info(f"Requesting FortiEDR isolation for {log_string}")
        try:
            results = fortiedr.SystemInventory().isolate_collectors(
                devicesIds=[collector["id"]]
            )
        except Exception as e:
            self.logger.debug(f"FortiEDR isolation failed with status: {e}")
            results = False

        if results:
            self.logger.info(f"Successfully isolated {log_string}")
            return [collector["id"]]
        else:
            self.logger.info(f"Unable to isolate {log_string}")
            return []

    def unblock_host(self, host: VectraHost) -> list:
        collector_ids = host.blocked_elements.get(self.name, [])
        un_isolated = []
        if collector_ids:
            for collector_id in collector_ids:
                log_string = f"{host.name} with id {collector_id} and IP {host.ip}"
                try:
                    results = fortiedr.SystemInventory().unisolate_collectors(
                        devicesIds=[collector_id]
                    )
                except Exception as e:
                    self.logger.debug(f"FortiEDR isolation failed with status: {e}")
                    results = False

                self.logger.info(f"Requesting FortiEDR un-isolation for {log_string}")

                if results:
                    self.logger.info(f"Successfully un-isolation {log_string}")
                    un_isolated.append(collector_id)
                else:
                    self.logger.info(f"Unable to un-isolation {log_string}")
            return un_isolated

    def groom_host(self, host) -> list:
        self.logger.warning("FortiEDR client does not implement host grooming")
        return []

    def block_detection(self, detection: VectraDetection) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "FortiEDR client does not implement detection-based blocking"
        )
        return []

    def unblock_detection(self, detection: VectraDetection) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "FortiEDR client does not implement detection-based blocking"
        )
        return []

    def block_account(self, account: VectraAccount) -> list:
        # this client only implements Host-based blocking
        self.logger.warning("FortiEDR client does not implement account-based blocking")
        return []

    def unblock_account(self, account: VectraAccount) -> list:
        # this client only implements Host-based blocking
        self.logger.warning("FortiEDR client does not implement account-based blocking")
        return []

    def block_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "FortiEDR client does not implement destination IP blocking"
        )
        return []

    def unblock_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        self.logger.warning(
            "FortiEDR client does not implement destination IP blocking"
        )
        return []
