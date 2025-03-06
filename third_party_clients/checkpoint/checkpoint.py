import json
import logging

import requests
from common import _get_password
from third_party_clients.checkpoint.checkpoint_config import (
    EXTERNAL_ADDRESS_GROUP,
    HOST,
    INTERNAL_ADDRESS_GROUP,
    PORT,
    USER,
)
from third_party_clients.third_party_interface import (
    ThirdPartyInterface,
    VectraAccount,
    VectraDetection,
    VectraHost,
    VectraStaticIP,
)
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


def validate_sid(func):
    def sid_wrapper(self, *args, **kwargs):
        if self._sid:
            return func(self, *args, **kwargs)
        else:
            raise RuntimeError("You need to login before you can make changes")

    return sid_wrapper


class CPManager:
    def __init__(self, user, password, ip, port=443):
        self._ip = ip
        self._port = port
        self._user = user
        self._password = password
        self._sid = ""
        self._url = f"https://{self._ip}:{self._port}/web_api"
        self._session = None

    def login(self):
        if self._sid:
            try:
                self.logout()
            except Exception:
                pass

        self._session = requests.Session()

        response = self._api_call(
            "login",
            headers={"content-type": "application/json"},
            payload=json.dumps({"user": self._user, "password": self._password}),
        )

        self._sid = response.json()["sid"]
        self.logger.info("Login to Check Point successful")

    @validate_sid
    def logout(self):
        try:
            self._api_call("logout")
            self.logger.info("Check Point session terminated")
        except Exception as e:
            self.logger.error("Unable to terminate Check Point session")
            raise e
        finally:
            self._sid = ""
            self._session.close()

    @validate_sid
    def add_host(self, ip, group_list=None):
        if not group_list:
            group_list = []
        self._api_call(
            "add-host",
            payload=json.dumps({"name": ip, "ip-address": ip, "groups": group_list}),
        )
        self.logger.debug(f"IP Registered: {ip}")

    @validate_sid
    def delete_host(self, ip):
        self._api_call("delete-host", payload=json.dumps({"name": ip}))
        self.logger.debug(f"IP Deleted: {ip}")

    @validate_sid
    def add_group(self, name):
        try:
            self._api_call("add-group", payload=json.dumps({"name": name}))
            self.logger.debug(f"group {name} created successfully")
        except Exception as e:
            try:
                self._api_call("show-group", payload=json.dumps({"name": name}))
                self.logger.debug(f"Group '{name}' already exists")
            except Exception:
                self.logger.warning(f"Unable to create group: {name}")
                raise e

        return True

    @validate_sid
    def remove_host_from_group(self, host, group):
        try:
            self._api_call(
                "set-group",
                payload=json.dumps({"name": group, "members": {"remove": host}}),
            )
        except Exception:
            self.logger.warning(f"Unable to remove host: {host} from group: {group}")

    @validate_sid
    def publish(self):
        response = self._api_call("publish")
        task_id = response.json()["task-id"]
        self.logger.info("Waiting for publishing to complete")
        while True:
            r = self._api_call("show-task", payload=json.dumps({"task-id": task_id}))
            status = r.json()["tasks"][0]["status"]
            if status in (
                "succeeded",
                "failed",
                "verification_failed",
                "aborted",
                "timed_out",
            ):
                if status == "succeeded":
                    self.logger.info("Changes saved")
                else:
                    self.logger.warning("Changes may not have been saved")
                break

    @validate_sid
    def discard(self):
        self._api_call("discard")
        self.logger.warning("Changes discarded")

    def __enter__(self):
        self.login()
        self.add_group(INTERNAL_ADDRESS_GROUP)
        self.add_group(EXTERNAL_ADDRESS_GROUP)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type:  # if fatal error causes early termination, discard changes
            try:
                self.discard()
            except Exception:
                self.logger.warning("discard unsuccessful, logging out")
        else:  # otherwise, publish changes
            try:
                self.publish()
            except Exception:
                self.logger.warning("publish unsuccessful, logging out")

        self.logout()

    def _api_call(self, command, headers=None, payload=None):
        if not headers:
            headers = {"content-type": "application/json", "x-chkp-sid": self._sid}
        if not payload:
            payload = json.dumps({})

        response = self._session.post(
            url=f"{self._url}/{command}",
            headers=headers,
            data=payload,
            verify=False,
            timeout=10,
        )
        response.raise_for_status()
        return response

    def block_ip(self, ip, group):
        try:
            self.add_host(ip, [group])
            return True
        except Exception:
            self.logger.warning(f"Unable to register IP: {ip} with group: {group}")
            return False

    def unblock_ip(self, ip, group=None):
        if group:
            try:
                self.remove_host_from_group(host=ip, group=group)
                self.logger.debug(f"Host: {ip} removed from Group: {group}")
            except Exception:
                pass
        try:
            self.delete_host(ip)
            return True
        except Exception:
            self.logger.warning(f"Unable to deregister IP: {ip}")
            return False


class Client(ThirdPartyInterface):
    def __init__(self, **kwargs):
        self.name = "CheckPoint Client"
        self.module = "checkpoint"
        self.init_log(kwargs)
        self.user_pass = _get_password("CheckPoint", USER, modify=kwargs["modify"])

        ThirdPartyInterface.__init__(self)

    def init_log(self, kwargs):
        dict_config = kwargs.get("dict_config", {})
        dict_config["loggers"].update({self.name: dict_config["loggers"]["VAR"]})
        logging.config.dictConfig(dict_config)
        self.logger = logging.getLogger(self.name)

    def block_host(self, host: VectraHost):
        ip = host.ip

        with CPManager(USER, self.user_pass, HOST, PORT) as cp_mgr:
            cp_mgr.block_ip(ip, INTERNAL_ADDRESS_GROUP)

        return ip

    def unblock_host(self, host: VectraHost):

        ips = host.blocked_elements.get(self.name, [])
        unisolated_list = []
        with CPManager(USER, self.user_pass, HOST, PORT) as cp_mgr:
            for ip in ips:
                unisolated = cp_mgr.unblock_ip(ip, INTERNAL_ADDRESS_GROUP)
                if unisolated != "":
                    unisolated_list.append(unisolated)
        return list(set(unisolated_list))

    def groom_host(self, host: VectraHost) -> dict:
        self.logger.warning("CheckPoint client does not implement host grooming")
        return []

    def block_detection(self, detection: VectraDetection):
        # TODO
        # with CPManager(USER, self.user_pass, HOST, PORT) as cp_mgr:
        #     cp_mgr.block_ip(ip, EXTERNAL_ADDRESS_GROUP)
        return []

    def unblock_detection(self, detection: VectraDetection):
        # TODO
        # with CPManager(USER, self.user_pass, HOST, PORT) as cp_mgr:
        #     cp_mgr.unblock_ip(ip, EXTERNAL_ADDRESS_GROUP)
        return []

    def block_account(self, account: VectraAccount) -> list:
        self.logger.warning("CheckPoint client does not implement account blocking")
        return []

    def unblock_account(self, account: VectraAccount) -> list:
        self.logger.warning("CheckPoint client does not implement account blocking")
        return []

    def block_static_dst_ips(self, ips: VectraStaticIP) -> list:
        self.logger.warning("CheckPoint client does not implement static IP-blocking")
        return []

    def unblock_static_dst_ips(self, ips: VectraStaticIP) -> list:
        self.logger.warning("CheckPoint client does not implement static IP-blocking")
        return []
