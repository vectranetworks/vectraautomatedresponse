import argparse
import importlib
import ipaddress
import json
import logging
import logging.config
import os
import re
import smtplib
import socket
import ssl
import sys
import time
import warnings
from datetime import datetime, timedelta
from logging.handlers import SysLogHandler
from multiprocessing import Process
from typing import Dict, Optional

import custom_log
import keyring
import requests
from common import _get_password
from config import (
    BLOCK_ACCOUNT_DETECTION_TYPES,
    BLOCK_ACCOUNT_DETECTION_TYPES_MIN_TC_SCORE,
    BLOCK_ACCOUNT_GROUP_NAME,
    BLOCK_ACCOUNT_TAG,
    BLOCK_ACCOUNT_THREAT_CERTAINTY,
    BLOCK_ACCOUNT_URGENCY,
    BLOCK_DAYS,
    BLOCK_END_TIME,
    BLOCK_HOST_DETECTION_TYPES,
    BLOCK_HOST_DETECTION_TYPES_MIN_TC_SCORE,
    BLOCK_HOST_GROUP_NAME,
    BLOCK_HOST_TAG,
    BLOCK_HOST_THREAT_CERTAINTY,
    BLOCK_HOST_URGENCY,
    BLOCK_START_TIME,
    COGNITO_URL,
    DST_EMAIL,
    EXPLICIT_UNBLOCK,
    EXTERNAL_BLOCK_DETECTION_TAG,
    EXTERNAL_BLOCK_DETECTION_TYPES,
    EXTERNAL_BLOCK_HOST_TC,
    EXTERNAL_UNBLOCK_DETECTION_TAG,
    NO_BLOCK_ACCOUNT_GROUP_NAME,
    NO_BLOCK_HOST_GROUP_NAME,
    SEND_EMAIL,
    SEND_SYSLOG,
    SLEEP_MINUTES,
    SMTP_AUTH,
    SMTP_PORT,
    SMTP_SERVER,
    SMTP_USER,
    SRC_EMAIL,
    STATIC_BLOCK_DESTINATION_IPS,
    SYSLOG_FORMAT,
    SYSLOG_PORT,
    SYSLOG_PROTO,
    SYSLOG_SERVER,
    THIRD_PARTY_CLIENTS,
    UNBLOCK_ACCOUNT_TAG,
    UNBLOCK_HOST_TAG,
)
from keyrings.alt import file
from requests import HTTPError
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from vat.platform import ClientV3_latest
from vat.vectra import ClientV2_latest
from vectra_automated_response_consts import (
    VectraAccount,
    VectraDetection,
    VectraHost,
    VectraStaticIP,
)

version = "3.1.0"


class CustomAdapter(logging.LoggerAdapter):
    def __init__(self, logger, extra):
        super().__init__(logger, extra)

    def process(self, record):
        record.brain = self.brain
        return True


def namestr(obj, namespace):
    return [name for name in namespace if namespace[name] is obj]


class TypeException(TypeError):
    def __init__(self, imported_list, val):
        logger.error(f"{imported_list} is not of {val}.")


clients = {}
for client in os.listdir(
    f"{os.path.dirname(os.path.realpath(__file__))}/third_party_clients"
):
    if client not in [
        "__init__.py",
        "__pycache__",
        ".DS_Store",
        "README.md",
        "third_party_interface.py",
    ]:
        tpc = [
            x
            for x in os.listdir(
                f"{os.path.dirname(os.path.realpath(__file__))}/third_party_clients/{client}"
            )
            if not x.startswith("__") and x.endswith(".py") and "config" not in x
        ]
        if tpc != []:
            clients[client] = tpc[0].split(".")[0]

Third_Party_Clients = []

for client in THIRD_PARTY_CLIENTS:
    if not isinstance(THIRD_PARTY_CLIENTS, list):
        break
    if client in clients:
        module_name = f"third_party_clients.{client}.{clients[client]}"
        Third_Party_Client = importlib.import_module(module_name)
        Third_Party_Clients.append(Third_Party_Client)
    elif client in clients.values():
        key = next(key for key, value in clients.items() if value == client)
        module_name = f"third_party_clients.{key}.{client}"
        Third_Party_Client = importlib.import_module(module_name)
        Third_Party_Clients.append(Third_Party_Client)
    else:
        print(f"The configured third party client - {client} - is not supported.")

if not Third_Party_Clients:
    print("No supported clients were configured.")
    sys.exit()

HostDict = Dict[str, VectraHost]
AccountDict = Dict[str, VectraAccount]
DetectionDict = Dict[str, VectraDetection]

URL = "portal.vectra.ai"


def log_conf():
    logging.basicConfig(
        format="%(asctime)s:%(levelname)s:%(name)s: %(message)s",
        encoding="utf-8",
        level=logging.DEBUG,
        datefmt="%Y-%m-%d %H:%M:%S",
    )


class HTTPException(Exception):
    def __init__(self, response):
        """
        Custom exception class to report possible API errors.
        The body is constructed by extracting the API error code from the requests.Response object.

        Args:
            response (requests.Response): The response object from the API request.
        """
        try:
            error_data = response.json()
            if "detail" in error_data:
                detail = error_data["detail"]
            elif "errors" in error_data:
                detail = error_data["errors"][0]["title"]
            elif "_meta" in error_data:
                detail = error_data["_meta"]["message"]
            else:
                detail = response.content
        except Exception:
            detail = response.content

        body = f"Status code: {response.status_code} - {detail}"
        super().__init__(body)


class VectraClient:
    def get_account_by_uid(self, uid: str) -> list:
        """
        Searches for accounts by account UID

        :param uid: UID of account to search for
        :return: list of raw account objects
        """
        params = {"uid": uid}
        response = requests.get(
            f"{self.url}/accounts",
            headers=self.headers,
            params=params,
            verify=self.verify,
        )
        if response.ok:
            return response.json().get("results", [])
        else:
            self.logger.error(f"Unable to get accounts: {response.content}")
            return []

    def get_hosts_in_group(self, group_name: str) -> HostDict:
        """
        Get a dictionary of all hosts present in a group.

        :param group_name: Name of the group for which to return the hosts
        :return: A dictionary of hosts present in the specified group
        :rtype: HostDict
        """
        hosts = {}
        try:
            groups = self.get_all_groups(name=group_name, type="host")
            for page in groups:
                for group in page.json()["results"]:
                    if group["name"] == group_name:
                        for member in group["members"]:
                            host_id = member["id"]
                            if host_id not in hosts:
                                host_info = self.get_host_by_id(host_id=host_id).json()
                                hosts[host_id] = VectraHost(host_info)
            return hosts
        except KeyError:
            raise HTTPError(page.text)

    def get_accounts_in_group(self, group_name: str) -> AccountDict:
        """
        Get a dictionary of all account present in a group.
        :param group_name: name of the group for which to return the hosts
        :rtype: AccountDict
        """
        accounts = {}
        group_list = []
        r = self.get_all_groups(name=group_name, type="account")
        try:
            for page in r:
                for group in page.json()["results"]:
                    if group["name"] == group_name:
                        group_list.append(group)
                for group in group_list:
                    for member in group["members"]:
                        account_list = self.get_account_by_uid(uid=member["uid"])
                        for account in account_list:
                            if account["id"] not in accounts:
                                accounts[account["id"]] = VectraAccount(account)
            return accounts
        except KeyError:
            raise HTTPError(page.text)

    def get_scored_hosts(self, tc_tuple, urgency_score) -> HostDict:
        """
        Get a dictionary of all hosts above given threat/certainty threshold
        :param t_score_gte: threat score threshold
        :param c_score_gte: certainty score threshold
        :param urgency_score: urgency score threshold for V3 only
        :rtype: HostDict
        """
        hosts = {}
        if tc_tuple is not None:
            try:
                t_score_gte, condition, c_score_gte = tc_tuple
                if not isinstance(t_score_gte, int) and isinstance(c_score_gte, int):
                    raise ValueError
                if condition not in ["and", "or"]:
                    raise ValueError
            except ValueError:
                self.logger.error(
                    "Invalid Threat/Certainty tuple provided in the BLOCK_HOST_THREAT_CERTAINTY parameter"
                )
                exit(99)

            if condition == "and":
                r = self.get_all_hosts(
                    t_score_gte=t_score_gte,
                    c_score_gte=c_score_gte,
                )
                for page in r:
                    if page.status_code not in [200, 201, 204]:
                        raise HTTPException(page)
                    for host in page.json().get("results", []):
                        hosts[host["id"]] = VectraHost(host)
            else:
                r = self.get_all_hosts(t_score_gte=t_score_gte)
                for page in r:
                    if page.status_code not in [200, 201, 204]:
                        raise HTTPException(page)
                    for host in page.json().get("results", []):
                        hosts[host["id"]] = VectraHost(host)
                r = self.get_all_hosts(c_score_gte=c_score_gte)
                for page in r:
                    if page.status_code not in [200, 201, 204]:
                        raise HTTPException(page)
                    for host in page.json().get("results", []):
                        hosts[host["id"]] = VectraHost(host)

        else:
            try:
                if not isinstance(urgency_score, int):
                    raise ValueError
            except ValueError:
                self.logger.error(
                    "Invalid Urgency Score provided in the BLOCK_HOST_URGENCY parameter"
                )
                exit(99)
            r = self.get_all_entities(type="host", ordering="-urgency_score")
            for page in r:
                if page.status_code not in [200, 201, 204]:
                    raise HTTPException(page)
                for entity in page.json().get("results", []):
                    if entity["urgency_score"] < urgency_score:
                        return hosts
                    elif entity["type"] == "host":
                        if entity["urgency_score"] >= urgency_score:
                            host = self.get_host_by_id(host_id=entity["id"]).json()
                            hosts[entity["id"]] = VectraHost(host)

        return hosts

    def get_scored_accounts(self, tc_tuple, urgency_score) -> AccountDict:
        """
        Get a dictionary of all accounts above given threat/certainty threshold
        :param t_score_gte: threat score threshold
        :param c_score_gte: certainty score threshold
        :param urgency_score: urgency score threshold for V3 only
        :rtype: AccountDict
        """
        accounts = {}
        if tc_tuple is not None:
            try:
                t_score_gte, condition, c_score_gte = tc_tuple
                if not isinstance(t_score_gte, int) and isinstance(c_score_gte, int):
                    raise ValueError
                if condition not in ["and", "or", "AND", "OR"]:
                    raise ValueError
            except ValueError:
                self.logger.error(
                    "Invalid Threat/Certainty tuple provided in the BLOCK_ACCOUNT_THREAT_CERTAINTY parameter"
                )
                exit(99)

            if condition == "and":
                r = self.get_all_accounts(
                    t_score_gte=t_score_gte,
                    c_score_gte=c_score_gte,
                )
                for page in r:
                    if page.status_code not in [200, 201, 204]:
                        raise HTTPException(page)
                    for account in page.json().get("results", []):
                        accounts[account["id"]] = VectraAccount(account)
            else:
                r = self.get_all_accounts(t_score_gte=t_score_gte)
                for page in r:
                    if page.status_code not in [200, 201, 204]:
                        raise HTTPException(page)
                    for account in page.json().get("results", []):
                        accounts[account["id"]] = VectraAccount(account)
                r = self.get_all_accounts(c_score_gte=c_score_gte)
                for page in r:
                    if page.status_code not in [200, 201, 204]:
                        raise HTTPException(page)
                    for account in page.json().get("results", []):
                        accounts[account["id"]] = VectraAccount(account)

        else:
            try:
                if not isinstance(urgency_score, int):
                    raise ValueError
            except ValueError:
                self.logger.error(
                    "Invalid Urgency Score provided in the BLOCK_ACCOUNT_URGENCY parameter"
                )
                exit(99)
            r = self.get_all_entities(type="account", ordering="-urgency_score")
            for page in r:
                if page.status_code not in [200, 201, 204]:
                    raise HTTPException(page)
                for entity in page.json().get("results", []):
                    if entity["urgency_score"] < urgency_score:
                        return accounts
                    elif entity["type"] == "account":
                        if entity["urgency_score"] >= urgency_score:
                            account = self.get_account_by_id(
                                account_id=entity["id"]
                            ).json()
                            accounts[entity["id"]] = VectraAccount(account)

        return accounts

    def get_tagged_hosts(self, tag: str) -> HostDict:
        """
        Get a dictionary of all hosts that contain given tag
        :param tag: tag to search
        :rtype: HostDict
        """
        hosts = {}
        r = self.get_all_hosts(tags=tag)
        for page in r:
            if page.status_code not in [200, 201, 204]:
                raise HTTPException(page)
            for host in page.json().get("results", []):
                hosts[host["id"]] = VectraHost(host)
        return hosts

    def get_tagged_accounts(self, tag: str) -> AccountDict:
        """
        Get a dictionary of all accounts that contain given tag
        :param tag: tag to search
        :rtype: AccountDict
        """
        accounts = {}

        r = self.get_all_accounts(tags=tag)
        for page in r:
            if page.status_code not in [200, 201, 204]:
                raise HTTPException(page)
            for account in page.json().get("results", []):
                accounts[account["id"]] = VectraAccount(account)
        return accounts

    def get_hosts_with_detection_types(
        self, detection_types: list, block_host_detections_types_min_host_tc: tuple
    ) -> HostDict:
        """
        Get a dictionary of all hosts containing detections of given type
        :param detection_types: list of all detections types
        :rtype: HostDict
        """
        hosts = {}
        try:
            (
                t_score_gte,
                condition,
                c_score_gte,
            ) = block_host_detections_types_min_host_tc
            if not isinstance(t_score_gte, int) and isinstance(c_score_gte, int):
                raise ValueError
            if condition not in ["and", "or"]:
                raise ValueError
        except ValueError:
            self.logger.error(
                "Invalid Threat/Certainty tuple provided in the BLOCK_HOST_THREAT_CERTAINTY parameter"
            )
            exit(99)

        detections = self.get_detections_by_type(detection_types=detection_types)
        for detection in detections.values():
            host_id = detection.host_id
            host = self.get_host_by_id(host_id=host_id).json()
            if condition == "and":
                if host["threat"] > t_score_gte and host["certainty"] > c_score_gte:
                    hosts[host["id"]] = VectraHost(host)
            elif condition == "or":
                if host["threat"] > t_score_gte or host["certainty"] > c_score_gte:
                    hosts[host["id"]] = VectraHost(host)
            else:
                continue
        return hosts

    def get_accounts_with_detection_types(
        self,
        detection_types: list,
        block_account_detections_types_min_account_tc: tuple,
    ) -> HostDict:
        """
        Get a dictionary of all accounts containing detections of given type
        :param detection_types: list of all detections types
        :rtype: AccountDict
        """
        accounts = {}
        try:
            (
                t_score_gte,
                condition,
                c_score_gte,
            ) = block_account_detections_types_min_account_tc
            if not isinstance(t_score_gte, int) and isinstance(c_score_gte, int):
                raise ValueError
            if condition not in ["and", "or"]:
                raise ValueError
        except ValueError:
            self.logger.error(
                "Invalid Threat/Certainty tuple provided in the BLOCK_ACCOUNT_THREAT_CERTAINTY parameter"
            )
            exit(99)

        detections = self.get_detections_by_type(detection_types=detection_types)
        for detection in detections.values():
            account_id = detection.account_id
            account = self.get_account_by_id(account_id=account_id).json()
            if condition == "and":
                if (
                    account["threat"] > t_score_gte
                    and account["certainty"] > c_score_gte
                ):
                    accounts[account["id"]] = VectraAccount(account)
            elif condition == "or":
                if (
                    account["threat"] > t_score_gte
                    or account["certainty"] > c_score_gte
                ):
                    accounts[account["id"]] = VectraAccount(account)
            else:
                continue
        return accounts

    def get_noblock_hosts(self, no_block_group: Optional[str] = None) -> HostDict:
        """
        Get all host IDs which should not be blocked
        :param no_block_group: group name containing hosts which should never be blocked - optional
        :rtype: HostDict
        """
        return (
            self.get_hosts_in_group(group_name=no_block_group) if no_block_group else {}
        )

    def get_noblock_accounts(self, no_block_group: Optional[str] = None) -> AccountDict:
        """
        Get all account IDs which should not be blocked
        :param no_block_group: group name containing accounts which should never be blocked - optional
        :rtype: AccountDict
        """
        return (
            self.get_accounts_in_group(group_name=no_block_group)
            if no_block_group
            else {}
        )

    def get_hosts_to_block(
        self,
        block_tag: Optional[str] = None,
        min_tc_score: Optional[tuple] = None,
        min_urgency_score: Optional[int] = None,
        block_host_group_name: Optional[str] = None,
        block_host_detection_types: list = [],
        block_host_detections_types_min_host_tc: tuple = (0, "and", 0),
    ) -> HostDict:
        """
        Get all host IDs which should be blocked given the parameters.
        :param block_tag: tag defining hosts that need to be blocked - optional
        :param min_tc_score: tuple of (threat, certainty) to query hosts exceeding this threshold - optional
        :param min_urgency_score: urgency to query hosts exceeding this threshold - optional
        :param block_host_detection_types: list of detections types which the host to be blocked - optional
        :rtype: HostDict
        """

        tagged_hosts = self.get_tagged_hosts(tag=block_tag) if block_tag else {}

        # if V3:
        if URL in self.url:
            if min_urgency_score is not None:
                min_tc_score = None
        else:
            min_urgency_score = None
        scored_hosts = (
            self.get_scored_hosts(
                tc_tuple=min_tc_score, urgency_score=min_urgency_score
            )
            if isinstance(min_tc_score, tuple) or isinstance(min_urgency_score, int)
            else {}
        )
        group_members = self.get_hosts_in_group(group_name=block_host_group_name)
        hosts_with_detection_types = (
            self.get_hosts_with_detection_types(
                block_host_detection_types, block_host_detections_types_min_host_tc
            )
            if block_host_detection_types
            else {}
        )
        return {
            **tagged_hosts,
            **scored_hosts,
            **group_members,
            **hosts_with_detection_types,
        }

    def get_hosts_to_unblock(
        self,
        unblock_tag: Optional[str] = None,
    ) -> HostDict:
        """
        Get all host IDs which should be blocked given the parameters.
        :param unblock_tag: tag defining hosts that need to be unblocked - optional

        :rtype: HostDict
        """

        tagged_hosts = self.get_tagged_hosts(tag=unblock_tag) if unblock_tag else {}

        return {**tagged_hosts}

    def get_accounts_to_block(
        self,
        block_tag: Optional[str] = None,
        min_tc_score: Optional[tuple] = None,
        min_urgency_score: Optional[int] = None,
        block_account_group_name: Optional[str] = None,
        block_account_detection_types: list = [],
        block_account_detections_types_min_account_tc: tuple = (0, "and", 0),
    ) -> AccountDict:
        """
        Get all account IDs which should be blocked given the parameters
        :param block_tag: tag defining account that need to be blocked - optional
        :param min_tc_score: tuple of (threat, certainty) to query account exceeding this threshold - optional
        :param block_account_group_name: group name of accounts to always block - optional
        :param block_account_detection_types: list of detections types which if present on a host will cause the
                account to be blocked - optional
        :param block_account_detections_types_min_account_tc: account minimum TC scores for accounts that have
                detections in block_account_detection_types
        :rtype: AccountDict
        """
        tagged_accounts = self.get_tagged_accounts(tag=block_tag) if block_tag else {}
        # if V3:
        if URL in self.url:
            if min_urgency_score is not None:
                min_tc_score = None
        else:
            min_urgency_score = None
        scored_accounts = (
            self.get_scored_accounts(
                tc_tuple=min_tc_score, urgency_score=min_urgency_score
            )
            if isinstance(min_tc_score, tuple) or isinstance(min_urgency_score, int)
            else {}
        )
        group_members = self.get_accounts_in_group(group_name=block_account_group_name)
        accounts_with_detection_types = (
            self.get_accounts_with_detection_types(
                block_account_detection_types,
                block_account_detections_types_min_account_tc,
            )
            if block_account_detection_types
            else {}
        )
        return {
            **tagged_accounts,
            **scored_accounts,
            **group_members,
            **accounts_with_detection_types,
        }

    def get_accounts_to_unblock(
        self,
        unblock_tag: Optional[str] = None,
    ) -> AccountDict:
        """
        Get all account IDs which should be blocked given the parameters
        :param unblock_tag: tag defining account that need to be unblocked - optional
        :rtype: AccountDict
        """
        tagged_accounts = (
            self.get_tagged_accounts(tag=unblock_tag) if unblock_tag else {}
        )

        return {
            **tagged_accounts,
        }

    def get_tagged_detections(self, tag: str) -> DetectionDict:
        """
        Get a dictionary of all detections that contain given tag
        :param tag: tag to search
        :rtype: DetectionDict
        """
        detections = {}
        r = self.get_all_detections(tags=tag)
        for page in r:
            if page.status_code not in [200, 201, 204]:
                raise HTTPException(page)
            for detection in page.json().get("results", []):
                # for some reason the API does substring matching, so we check
                if tag in detection["tags"]:
                    detections[detection["id"]] = VectraDetection(detection)
        return detections

    def get_detections_by_type(self, detection_types: list = []) -> DetectionDict:
        """
        Get a dictionary of all detections matching the given types.
        :param detection_types: list of all detection types to match.
        :rtype: DetectionDict
        """
        detections = {}
        if len(detection_types) < 1:
            return detections
        else:
            for detection_type in detection_types:
                r = self.get_all_detections(
                    detection_type=detection_type, state="active"
                )
                for page in r:
                    if page.status_code not in [200, 201, 204]:
                        raise HTTPException(page)
                    for detection in page.json().get("results", []):
                        detections[detection["id"]] = VectraDetection(detection)
        return detections

    def get_detections_on_host(self, host_id: int) -> DetectionDict:
        """
        Get a dictionary of all detections on a given host, matching by id.
        :param host_id: ID of the host for which to return all detections.
        :rtype: DetectionDict
        """
        # Get all detection IDs on hosts
        detection_ids = set()
        host = self.get_host_by_id(host_id=host_id, fields="detection_set").json()
        for detection in host.get("detection_set", []):
            detection_ids.add(detection.rsplit("/", 1)[1])
        # Get individual detections
        detections = {}
        for detection_id in detection_ids:
            r = self.get_detection_by_id(detection_id=detection_id)
            detection = r.json()
            # Ignore info detections, custom and inactive ones
            if (
                detection.get("category") != "INFO"
                and detection.get("state") == "active"
                and detection.get("is_triaged") is False
            ):
                detections[detection["id"]] = VectraDetection(detection)
        return detections

    def get_detections_on_account(self, account_id: int) -> DetectionDict:
        """
        Get a dictionary of all detections on a given account, matching by id.
        :param account_id: ID of the account for which to return all detections.
        :rtype: DetectionDict
        """
        # Get all detection IDs on accounts
        detection_ids = set()
        account = self.get_account_by_id(
            account_id=account_id, fields="detection_set"
        ).json()
        for detection in account.get("detection_set", []):
            detection_ids.add(detection.rsplit("/", 1)[1])
        # Get individual detections
        detections = {}
        for detection_id in detection_ids:
            r = self.get_detection_by_id(detection_id=detection_id)
            detection = r.json()
            # Ignore info detections, custom and inactive ones
            if (
                detection.get("category") != "INFO"
                and detection.get("state") == "active"
                and detection.get("is_triaged") is False
            ):
                detections[detection["id"]] = VectraDetection(detection)
        return detections

    def get_detections_on_hosts_in_group(self, group_name: str) -> DetectionDict:
        """
        Get a dictionary of all detections present on members of the host group given in parameter.
        :param group_name: name of the host group to query
        :rtype: DetectionDict
        """
        detections = {}
        r = self.get_all_groups(name=group_name, type="host")
        for page in r:
            for group in page.json()["results"]:
                for member in group["members"]:
                    detections.update(self.get_detections_on_host(host_id=member["id"]))
        return detections

    def get_detections_on_accounts_in_group(self, group_name: str) -> DetectionDict:
        """
        Get a dictionary of all detections present on members of the account group given in parameter.
        :param group_name: name of the account group to query
        :rtype: DetectionDict
        """
        detections = {}
        r = self.get_all_groups(name=group_name, type="account")
        for page in r:
            for group in page.json()["results"]:
                for member in group["members"]:
                    detections.update(
                        self.get_detections_on_account(account_id=member["id"])
                    )
        return detections

    def get_detections_on_scored_host(
        self, min_host_tc_score: tuple, min_urgency_score: int
    ) -> DetectionDict:
        """
        Get a dictionary of all detections present on hosts exceeding the threat/certainty threshold..
        :param host_t_score_gte: min threat score of hosts to match
        :param host_c_score_gte: min certainty score of hosts to match
        :rtype: DetectionDict
        """
        detections = {}
        hosts = self.get_scored_hosts(
            tc_tuple=min_host_tc_score, urgency_score=min_urgency_score
        )
        # iterate through the matching host IDs
        for host_id in hosts.keys():
            detections.update(self.get_detections_on_host(host_id=host_id))
        return detections

    def get_detections_on_scored_accounts(
        self, min_account_tc_score: tuple, min_urgency_score: int
    ) -> DetectionDict:
        """
        Get a dictionary of all detections present on accounts exceeding the threat/certainty threshold..
        :param min_account_tc_score: min scores tuple of accounts
        :rtype: DetectionDict
        """
        detections = {}
        accounts = self.get_scored_accounts(
            tc_tuple=min_account_tc_score, urgency_score=min_urgency_score
        )
        # iterate through the matching host IDs
        for account_id in accounts.keys():
            detections.update(self.get_detections_on_account(account_id=account_id))
        return detections

    def get_noblock_detections(
        self, no_block_group: Optional[str] = None
    ) -> DetectionDict:
        """
        Get a dict of all detection IDs which should not be blocked given the parameters.
        :param no_block_group: name of the host group whose member detections should never be blocked - optional
        :rtype: DetectionDict
        """
        return (
            self.get_detections_on_hosts_in_group(group_name=no_block_group)
            if no_block_group
            else {}
        )

    def get_detections_to_block(
        self,
        block_tag: Optional[str] = None,
        detection_types_to_block: Optional[list] = None,
        min_host_tc_score: Optional[tuple] = None,
        min_urgency_score: int = None,
    ) -> DetectionDict:
        """
        Get a dict of all detection IDs which should be blocked given the parameters.
        :param block_tag: tag defining detections which should be blocked or unblocked - optional
        :param detection_types_to_block: list of detection types to block, regardless of score
        :param min_host_tc_score: tuple (int, int) of min host threat/certainty score for which,\
            if exceeded to block all detections on host.
        :rtype: DetectionDict
        """
        tagged_detections = (
            self.get_tagged_detections(tag=block_tag) if block_tag else {}
        )
        typed_detections = (
            self.get_detections_by_type(detection_types=detection_types_to_block)
            if detection_types_to_block
            else {}
        )
        detections_of_scored_hosts = (
            self.get_detections_on_scored_host(
                min_host_tc_score=min_host_tc_score, min_urgency_score=min_urgency_score
            )
            if min_host_tc_score or min_urgency_score
            else {}
        )
        return {**tagged_detections, **typed_detections, **detections_of_scored_hosts}

    def get_detections_to_unblock(
        self,
        unblock_tag: Optional[str] = None,
    ) -> DetectionDict:
        """
        Get a dict of all detection IDs which should be blocked given the parameters.
        :param unblock_tag: tag defining detections which should be unblocked or unblocked - optional
        :rtype: DetectionDict
        """
        tagged_detections = (
            self.get_tagged_detections(tag=unblock_tag) if unblock_tag else {}
        )

        return {**tagged_detections}

class VectraClientV3(ClientV3_latest, VectraClient):
    """
    Initialize Vectra client V3
    :param url: IP or hostname of Vectra brain - required
    :param client_id: V3 API Client ID for authentication - required
    :param secret_key: V3 API Secret Key for authentication - required
    :param verify: verify SSL - optional
    """

    def __init__(
        self,
        url: Optional[str] = "",
        client_id: Optional[str] = "",
        secret_key: Optional[str] = "",
        store: bool = False,
        verify: bool = False,
    ) -> None:
        self.store = store
        super().__init__(
            url=url, client_id=client_id, secret_key=secret_key, verify=verify
        )

    def _check_token(self):
        if self.store:
            rux_tokens = self._get_rux_tokens()
            if rux_tokens:
                self._access = rux_tokens.get("_access", None)
                self._accessTime = rux_tokens.get("_accessTime", None)
                self._refresh = rux_tokens.get("_refresh", None)
                self._refreshTime = rux_tokens.get("_refreshTime", None)
            if not self._access:
                self._get_token()
                self._set_rux_tokens()
            elif self._accessTime < int(time.time()):
                self._refresh_token()
                self._set_rux_tokens()
        else:
            if not self._access:
                self._get_token()
            elif self._accessTime < int(time.time()):
                self._refresh_token()

    def _get_rux_tokens(self):
        rux_tokens = keyring.get_password(self.base_url, "rux_tokens")
        if rux_tokens:
            rux_tokens = json.loads(rux_tokens)
            if rux_tokens.get("_accessTime", 0) > round(time.time()):
                return rux_tokens
            else:
                pass
        return {}

    def _set_rux_tokens(self):
        keyring.set_password(
            self.base_url,
            "rux_tokens",
            json.dumps(
                {
                    "_access": self._access,
                    "_refresh": self._refresh,
                    "_accessTime": self._accessTime,
                    "_refreshTime": self._refreshTime,
                }
            ),
        )


class VectraClientV2(ClientV2_latest, VectraClient):
    """
    Initialize Vectra client V2
    :param url: IP or hostname of Vectra brain - required
    :param token: V2 API token for authentication - required
    :param verify: verify SSL - optional
    """

    def __init__(
        self,
        url: Optional[str] = "",
        client_id: Optional[str] = "",
        secret_key: Optional[str] = "",
        verify: bool = False,
    ) -> None:
        super().__init__(
            url=url, client_id=client_id, secret_key=secret_key, verify=verify
        )

    def _check_token(self):
        rux_tokens = self._get_rux_tokens()
        if rux_tokens:
            self._access = rux_tokens.get("_access", None)
            self._accessTime = rux_tokens.get("_accessTime", None)
            self._refresh = rux_tokens.get("_refresh", None)
            self._refreshTime = rux_tokens.get("_refreshTime", None)
        if not self._access:
            self._get_token()
            self._set_rux_tokens()
        elif self._accessTime < int(time.time()):
            self._refresh_token()
            self._set_rux_tokens()

    def _get_rux_tokens(self):
        rux_tokens = keyring.get_password(self.url, "rux_tokens")
        if rux_tokens:
            rux_tokens = json.loads(rux_tokens)
            if rux_tokens.get("_accessTime", 0) > round(time.time()):
                return rux_tokens
            else:
                pass
        return {}

    def _set_rux_tokens(self):
        keyring.set_password(
            self.url,
            "rux_tokens",
            json.dumps(
                {
                    "_access": self._access,
                    "_refresh": self._refresh,
                    "_accessTime": self._accessTime,
                    "_refreshTime": self._refreshTime,
                }
            ),
        )


class VectraClientV2(ClientV2_latest, VectraClient):
    """
    Initialize Vectra client V2
    :param url: IP or hostname of Vectra brain - required
    :param token: V2 API token for authentication - required
    :param verify: verify SSL - optional
    """

    def __init__(
        self,
        url: Optional[str] = "",
        token: Optional[str] = "",
        verify: bool = False,
    ) -> None:
        super().__init__(url=url, token=token, verify=verify)


class VectraAutomatedResponse(object):
    def __init__(
        self,
        brain: str,
        third_party_clients: list,
        vectra_api_client: VectraClient,
        block_host_tag: Optional[str],
        block_account_tag: Optional[str],
        block_host_tc_score: tuple,
        block_host_urgency_score: Optional[int],
        block_account_tc_score: tuple,
        block_account_urgency_score: Optional[int],
        block_host_group_name: Optional[str],
        block_account_group_name: Optional[str],
        block_host_detection_types: list,
        block_account_detection_types: list,
        block_host_detections_types_min_host_tc: tuple,
        block_account_detections_types_min_account_tc: tuple,
        no_block_host_group_name: Optional[str],
        no_block_account_group_name: Optional[str],
        external_block_host_tc: tuple,
        external_block_detection_types: list,
        external_block_detection_tag: Optional[str],
        static_dest_ip_block_file: str,
        log_dict_config: dict,
        explicit_unblock: bool,
        unblock_host_tag: Optional[str],
        unblock_account_tag: Optional[str],
        external_unblock_detection_tag: Optional[str],
    ):
        # Generic setup
        self.third_party_clients = third_party_clients
        self.vectra_api_client = vectra_api_client
        logging.config.dictConfig(log_dict_config)
        self.logger = logging.LoggerAdapter(
            logger=logging.getLogger("VAR_Client"),
            extra=dict(brain=self.vectra_api_client.url.split("/")[2]),
        )
        # Internal (un)blocking variables
        self.block_host_tag = block_host_tag
        self.block_host_tc_score = block_host_tc_score
        self.block_host_urgency_score = block_host_urgency_score
        self.block_host_group_name = block_host_group_name
        self.block_host_detection_types = block_host_detection_types
        self.block_host_detections_types_min_host_tc = (
            block_host_detections_types_min_host_tc
        )
        self.no_block_host_group_name = no_block_host_group_name
        self.block_account_tag = block_account_tag
        self.block_account_tc_score = block_account_tc_score
        self.block_account_urgency_score = block_account_urgency_score
        self.block_account_group_name = block_account_group_name
        self.block_account_detection_types = block_account_detection_types
        self.block_account_detections_types_min_account_tc = (
            block_account_detections_types_min_account_tc
        )
        self.no_block_account_group_name = no_block_account_group_name
        # External (un)blocking variables
        self.external_block_host_tc = external_block_host_tc
        self.external_block_detection_types = external_block_detection_types
        self.external_block_detection_tag = external_block_detection_tag
        self.static_dest_ip_block_file = static_dest_ip_block_file
        self.info_msg = []
        self.warn_msg = []
        self.err_msg = []

        self.explicit_unblock = explicit_unblock
        self.unblock_host_tag = unblock_host_tag
        self.unblock_account_tag = unblock_account_tag
        self.external_unblock_detection_tag = external_unblock_detection_tag

    @staticmethod
    def _get_dict_keys_intersect(dict1, dict2):
        """
        Function that return dict of all keys present in both dict1 and dict2
        """
        result_dict = {}
        for key, value in dict1.items():
            if key in dict2.keys():
                result_dict[key] = value
        return result_dict

    @staticmethod
    def _get_dict_keys_relative_complement(dict1, dict2):
        """
        Function that returns dict of all keys present in dict1 and NOT in dict 2
        """
        result_dict = {}
        for key, value in dict1.items():
            if key not in dict2.keys():
                result_dict[key] = value
        return result_dict

    def get_hosts_to_block_unblock(self, groom=False):
        """
        Get all host IDs matching the criteria to be blocked or unblocked
        :rtype: list
        """
        # Set of all host IDs that should never be blocked
        no_block_hosts = self.vectra_api_client.get_noblock_hosts(
            no_block_group=self.no_block_host_group_name
        )
        # Get a dict of hosts to block
        matching_hosts = self.vectra_api_client.get_hosts_to_block(
            block_tag=self.block_host_tag,
            min_tc_score=self.block_host_tc_score,
            min_urgency_score=self.block_host_urgency_score,
            block_host_group_name=self.block_host_group_name,
            block_host_detection_types=self.block_host_detection_types,
            block_host_detections_types_min_host_tc=self.block_host_detections_types_min_host_tc,
        )
        # Get a dict of hosts already blocked
        blocked_hosts = self.vectra_api_client.get_tagged_hosts(tag="VAR Host Blocked")

        message = "Found {} already blocked hosts on Vectra".format(
            str(len(blocked_hosts.keys()))
        )

        self.logger.debug(message)

        if len(blocked_hosts.keys()) > 0:
            self.logger.info(message)

        # Find blocked hosts that should be unblocked
        hosts_wrongly_blocked = self._get_dict_keys_intersect(
            blocked_hosts, no_block_hosts
        )

        message = (
            "Found {} blocked hosts that are now part of the no-block lists".format(
                str(len(hosts_wrongly_blocked.keys()))
            )
        )

        self.logger.debug(message)

        if len(hosts_wrongly_blocked.keys()) > 0:
            self.logger.info(message)

        # Compute hosts that should be blocked
        hosts_to_block = self._get_dict_keys_relative_complement(
            matching_hosts, blocked_hosts
        )
        # Take into account exclusions
        hosts_to_block = self._get_dict_keys_relative_complement(
            hosts_to_block, no_block_hosts
        )

        message = "Found {} hosts that need to be blocked".format(
            str(len(hosts_to_block.keys()))
        )

        self.logger.debug(message)

        if len(hosts_to_block.keys()) > 0:
            self.logger.info(message)

        # Compute hosts that should be unblocked
        if self.explicit_unblock:
            # Get a dict of hosts to unblock
            hosts_to_unblock = self.vectra_api_client.get_hosts_to_unblock(
                unblock_tag=self.unblock_host_tag,
            )
        else:
            hosts_to_unblock = self._get_dict_keys_relative_complement(
                blocked_hosts, matching_hosts
            )

        # Add wrongly blocked hosts
        hosts_to_unblock = {**hosts_to_unblock, **hosts_wrongly_blocked}

        message = "Found {} hosts that need to be unblocked".format(
            str(len(hosts_to_unblock.keys()))
        )

        self.logger.debug(message)

        if len(hosts_to_unblock.keys()) > 0:
            self.logger.info(message)

        hosts_to_groom = {}
        if groom:
            # Compute hosts to be groomed
            hosts_to_groom = self._get_dict_keys_relative_complement(
                blocked_hosts, hosts_wrongly_blocked
            )

            message = "Found {} hosts that need to be groomed".format(
                len(hosts_to_groom.keys())
            )

            self.logger.debug(message)

            if len(hosts_to_groom.keys()) > 0:
                self.logger.info(message)

        return hosts_to_block, hosts_to_unblock, hosts_to_groom

    def get_accounts_to_block_unblock(self):
        """
        Get all account IDs matching the criteria to be blocked or unblocked
        :rtype: list
        """
        # Set of all account IDs that should never be blocked
        no_block_accounts = self.vectra_api_client.get_noblock_accounts(
            no_block_group=self.no_block_account_group_name
        )
        # Get a dict of accounts to block
        matching_accounts = self.vectra_api_client.get_accounts_to_block(
            block_tag=self.block_account_tag,
            min_tc_score=self.block_account_tc_score,
            min_urgency_score=self.block_account_urgency_score,
            block_account_group_name=self.block_account_group_name,
            block_account_detection_types=self.block_account_detection_types,
            block_account_detections_types_min_account_tc=self.block_account_detections_types_min_account_tc,
        )
        # Get a dict of accounts already blocked
        blocked_accounts = self.vectra_api_client.get_tagged_accounts(
            tag="VAR Account Blocked"
        )

        message = "Found {} already blocked accounts on Vectra".format(
            str(len(blocked_accounts.keys()))
        )

        self.logger.debug(message)

        if len(blocked_accounts.keys()) > 0:
            self.logger.info(message)

        # Find blocked account that should be unblocked
        accounts_wrongly_blocked = self._get_dict_keys_intersect(
            blocked_accounts, no_block_accounts
        )

        message = (
            "Found {} blocked accounts that are now part of the no-block lists".format(
                str(len(accounts_wrongly_blocked.keys()))
            )
        )

        self.logger.debug(message)

        if len(accounts_wrongly_blocked.keys()) > 0:
            self.logger.info(message)

        # Compute accounts that should be blocked
        accounts_to_block = self._get_dict_keys_relative_complement(
            matching_accounts, blocked_accounts
        )
        # Take into account exclusions
        accounts_to_block = self._get_dict_keys_relative_complement(
            accounts_to_block, no_block_accounts
        )

        message = "Found {} accounts that need to be blocked".format(
            str(len(accounts_to_block.keys()))
        )

        self.logger.debug(message)

        if len(accounts_to_block.keys()) > 0:
            self.logger.info(message)

        # Compute accounts that should be unblocked
        if self.explicit_unblock:
            # Get a dict of hosts to unblock
            accounts_to_unblock = self.vectra_api_client.get_accounts_to_unblock(
                unblock_tag=self.unblock_account_tag,
            )
        else:
            accounts_to_unblock = self._get_dict_keys_relative_complement(
                blocked_accounts, matching_accounts
            )

        # Add wrongly blocked accounts
        accounts_to_unblock = {**accounts_to_unblock, **accounts_wrongly_blocked}

        message = "Found {} accounts that need to be unblocked".format(
            str(len(accounts_to_unblock.keys()))
        )

        self.logger.debug(message)

        if len(accounts_to_unblock.keys()) > 0:
            self.logger.info(message)

        return accounts_to_block, accounts_to_unblock

    def get_detections_to_block_unblock(self):
        # Get a list of all detections that should be unblocked or never blocked
        no_block_detections = self.vectra_api_client.get_noblock_detections(
            no_block_group=self.no_block_host_group_name
        )
        # Get a dict of detections to block
        matching_detections = self.vectra_api_client.get_detections_to_block(
            block_tag=self.external_block_detection_tag,
            detection_types_to_block=self.external_block_detection_types,
            min_host_tc_score=self.external_block_host_tc,
        )
        # Get a dict of detections already blocked
        blocked_detections = self.vectra_api_client.get_tagged_detections(
            tag="VAR Detection Blocked"
        )

        message = "Found {} already blocked detections on Vectra".format(
            str(len(blocked_detections.keys()))
        )

        self.logger.debug(message)

        if len(blocked_detections.keys()) > 0:
            self.logger.info(message)

        # Find blocked detections that should be unblocked
        detections_wrongly_blocked = self._get_dict_keys_intersect(
            blocked_detections, no_block_detections
        )

        message = "Found {} blocked detections that are now part of the no-block lists".format(
            str(len(detections_wrongly_blocked.keys()))
        )

        self.logger.debug(message)

        if len(detections_wrongly_blocked.keys()) > 0:
            self.logger.info(message)

        # Compute detections that should be blocked
        detections_to_block = self._get_dict_keys_relative_complement(
            matching_detections, blocked_detections
        )
        # Take into account exclusions
        detections_to_block = self._get_dict_keys_relative_complement(
            detections_to_block, no_block_detections
        )

        message = "Found {} detections that need to be blocked".format(
            str(len(detections_to_block.keys()))
        )

        self.logger.debug(message)

        if len(detections_to_block.keys()) > 0:
            self.logger.info(message)

        # Compute detections that should be unblocked
        if self.explicit_unblock:
            # Get a dict of hosts to unblock
            detections_to_unblock = self.vectra_api_client.get_detections_to_unblock(
                unblock_tag=self.external_unblock_detection_tag,
            )
        else:
            detections_to_unblock = self._get_dict_keys_relative_complement(
                blocked_detections, matching_detections
            )

        # Add wrongly blocked detections
        detections_to_unblock = {**detections_to_unblock, **detections_wrongly_blocked}

        message = "Found {} detections that need to be unblocked".format(
            str(len(detections_to_unblock.keys()))
        )

        self.logger.debug(message)

        if len(detections_to_unblock.keys()) > 0:
            self.logger.info(message)

        return detections_to_block, detections_to_unblock

    def get_static_dst_ips_to_block_unblock(self):
        # Read in currently blocked IPs
        def valid_ip(ip):
            try:
                return bool(ipaddress.ip_address(ip))
            except ValueError:
                try:
                    return bool(ipaddress.ip_network(ip))
                except ValueError:
                    return False

        try:
            with open(".current_blocked_static_destination_ips") as current_ip_file:
                current_ips_blocked = [
                    line.rstrip() for line in current_ip_file.readlines()
                ]
        except FileNotFoundError:
            with open(".current_blocked_static_destination_ips", "w") as fp:
                pass
            current_ips_blocked = []
        # Read in IPs that should be blocked
        try:
            with open(self.static_dest_ip_block_file) as ips_to_block_file:
                ips_from_block_file = ips_to_block_file.readlines()
                requested_ips_to_block = [line.rstrip() for line in ips_from_block_file]
        except FileNotFoundError:
            with open(self.static_dest_ip_block_file, "w") as fp:
                ips_from_block_file = []
                pass
            requested_ips_to_block = []
        ips_to_block = [
            x
            for x in requested_ips_to_block
            if x not in current_ips_blocked and valid_ip(x)
        ]
        ips_to_unblock = [
            x for x in current_ips_blocked if x not in requested_ips_to_block
        ]
        # Write the new IPs to file
        with open(".current_blocked_static_destination_ips", "w") as output_file:
            output_file.writelines(
                [
                    line.strip() + "\n"
                    for line in ips_from_block_file
                    if valid_ip(line.strip())
                ]
            )

        message = "Found {} static IPs to block, {} to unblock".format(
            len(ips_to_block), len(ips_to_unblock)
        )

        self.logger.debug(message)

        if len(ips_to_block) > 0 or len(ips_to_unblock) > 0:
            self.logger.info(message)

        return ips_to_block, ips_to_unblock

    def block_hosts(self, hosts_to_block):
        for host_id, host in hosts_to_block.items():
            usable_third_party_clients = [
                tag.split(":")[1].lower()
                for tag in host.tags
                if tag.lower().startswith("client")
            ]
            for third_party_client in self.third_party_clients:
                if usable_third_party_clients == []:
                    pass
                else:
                    try:
                        self.logger.debug(
                            f"TPC:{third_party_client.module.lower()}; Usable TPCs:{usable_third_party_clients}"
                        )
                        if (
                            third_party_client.module.lower()
                            not in usable_third_party_clients
                        ):
                            continue
                    except AttributeError:
                        continue
                try:
                    # Block endpoint
                    blocked_elements = third_party_client.block_host(host=host)
                    if len(blocked_elements) > 0:
                        message = "Blocked host {id}, {name}, {ip} with client {client}".format(
                            id=host_id,
                            name=host.name,
                            ip=host.ip,
                            client=third_party_client.name,
                        )
                        self.logger.info(message)
                        self.info_msg.append(message)
                        # Set a "VAR Host Blocked" to set the host as being blocked and
                        # register what elements were blocked in separate tags
                        tag_to_set = host.tags
                        tag_to_set.append("VAR Host Blocked")
                        for element in blocked_elements:
                            tag_to_set.append(
                                "VAR ID:{client_class}:{id}".format(
                                    client_class=third_party_client.name,
                                    id=element,
                                )
                            )
                        self.vectra_api_client.set_host_tags(
                            host_id=host_id, tags=tag_to_set, append=False
                        )
                        self.vectra_api_client.set_host_note(
                            host_id=host_id,
                            note="VAR: Blocked on {}".format(
                                datetime.now().strftime("%d %b %Y at %H:%M:%S")
                            ),
                        )
                        self.logger.debug("Added Tags to host")
                    else:
                        message = (
                            "Did not find any elements to block on host ID {}".format(
                                host_id
                            )
                        )
                        self.logger.warning(message)
                        self.warn_msg.append(message)
                except HTTPException as e:
                    message = "Error encountered trying to block Host ID {}: {}".format(
                        host.id, str(e)
                    )
                    self.logger.error(message)
                    self.err_msg.append(message)

    def unblock_hosts(self, hosts_to_unblock):
        for host_id, host in hosts_to_unblock.items():
            blocked_elements = host.blocked_elements
            if len(blocked_elements) < 1:
                message = "Could not find what was blocked on host {}".format(host.name)
                self.logger.error(message)
                self.err_msg.append(message)
                continue
            for third_party_client in self.third_party_clients:
                try:
                    unblocked_elements = third_party_client.unblock_host(host)
                    if unblocked_elements is None:
                        unblocked_elements = []
                    if len(unblocked_elements) > 0:
                        for element in unblocked_elements:
                            blocked_elements[third_party_client.name].remove(element)
                            self.logger.debug("Unblocked element {}".format(element))
                        message = "Unblocked host {id}, {name}, {ip} with client {client}".format(
                            id=host_id,
                            name=host.name,
                            ip=host.ip,
                            client=third_party_client.name,
                        )
                        tags = host.tags
                        if len(blocked_elements[third_party_client.name]) > 0:
                            tags.append("VAR Host Blocked")
                            for element in blocked_elements[third_party_client.name]:
                                tags.append(
                                    "VAR ID:{client_class}:{id}".format(
                                        client_class=third_party_client.name,
                                        id=element,
                                    )
                                )
                        self.logger.info(message)
                        self.info_msg.append(message)
                        # Remove all tags set by this script from the host.
                        if "block" in tags:
                            print(host.keys())
                            message = 'Host {} is in no-block list but has a "block" tag. Removing tag..'.format(
                                host["name"]
                            )
                            self.logger.warning(message)
                            self.warn_msg.append(message)
                            tags.remove("block")

                        self.vectra_api_client.set_host_tags(
                            host_id=host_id, tags=tags, append=False
                        )
                        self.vectra_api_client.set_host_note(
                            host_id=host_id,
                            note="VAR: Unblocked on {}".format(
                                datetime.now().strftime("%d %b %Y at %H:%M:%S")
                            ),
                        )
                        self.logger.debug("Removed tags")
                    else:
                        message = "Could not unblock host {} element(s) {}".format(
                            host.name, blocked_elements[third_party_client.name]
                        )
                        self.logger.error(message)
                        self.err_msg.append(message)
                except HTTPException as e:
                    message = (
                        "Error encountered trying to unblock Host ID{}: {}".format(
                            host.id, str(e)
                        )
                    )
                    self.logger.error(message)
                    self.err_msg.append(message)
                except KeyError:
                    pass

    def groom_hosts(self, hosts_to_groom):
        for host_id, host in hosts_to_groom.items():
            usable_third_party_clients = [
                tag.split(":")[1].lower()
                for tag in host.tags
                if tag.lower().startswith("client")
            ]
            for third_party_client in self.third_party_clients:
                if usable_third_party_clients == []:
                    pass
                else:
                    try:
                        self.logger.debug(
                            f"TPC:{third_party_client.module.lower()}; Usable TPCs:{usable_third_party_clients}"
                        )
                        if (
                            third_party_client.module.lower()
                            not in usable_third_party_clients
                        ):
                            continue
                    except AttributeError:
                        continue
                groomed = third_party_client.groom_host(host=host)
                self.logger.debug("groomed: {}".format(groomed))
                if groomed["unblock"]:
                    message = (
                        "Groomed host {} to be unblocked based on IP change: {}".format(
                            host_id, host.ip
                        )
                    )
                    self.logger.info(message)
                    self.info_msg.append(message)
                    try:
                        unblocked_elements = third_party_client.unblock_host(host)
                        for element in unblocked_elements:
                            self.logger.debug("Unblocked element {}".format(element))
                        message = "Unblocked host {id}, {name}, {ip} with client {client}".format(
                            id=host_id,
                            name=host.name,
                            ip=host.ip,
                            client=third_party_client.name,
                        )
                        self.logger.info(message)
                        self.info_msg.append(message)

                        self.vectra_api_client.set_host_tags(
                            host_id=host_id, tags=host.tags, append=False
                        )
                        self.vectra_api_client.set_host_note(
                            host_id=host_id,
                            note="VAR: Unblocked due to grooming on {}".format(
                                datetime.now().strftime("%d %b %Y at %H:%M:%S")
                            ),
                        )
                    except HTTPException as e:
                        message = (
                            "Error encountered trying to unblock Host ID{}: {}".format(
                                host.id, str(e)
                            )
                        )
                        self.logger.error(message)
                        self.err_msg.append(message)
                if groomed["block"]:
                    message = (
                        "Groomed host {} to be blocked based on IP change: {}".format(
                            host_id, host.ip
                        )
                    )
                    self.logger.info(message)
                    self.info_msg.append(message)
                    try:
                        # Block endpoint
                        blocked_elements = third_party_client.block_host(host=host)
                        message = "Blocked host {id}, {name}, {ip} with client {client}".format(
                            id=host_id,
                            name=host.name,
                            ip=host.ip,
                            client=third_party_client.name,
                        )
                        self.logger.info(message)
                        self.info_msg.append(message)
                        # Set a "VAR Host Blocked" to set the host as being blocked and registered what elements were
                        # blocked in separate tags
                        tag_to_set = ["VAR Host Blocked"]
                        if len(blocked_elements) < 1:
                            message = "Did not find any elements to block on host ID {}".format(
                                host_id
                            )
                            self.logger.warning(message)
                            self.warn_msg.append(message)
                        for element in blocked_elements:
                            tag_to_set.append(
                                "VAR ID:{client_class}:{id}".format(
                                    client_class=third_party_client.name,
                                    id=element,
                                )
                            )
                        self.vectra_api_client.set_host_tags(
                            host_id=host_id, tags=tag_to_set, append=True
                        )
                        self.vectra_api_client.set_host_note(
                            host_id=host_id,
                            note="VAR: Blocked on {}".format(
                                datetime.now().strftime("%d %b %Y at %H:%M:%S")
                            ),
                        )
                        self.logger.debug("Added Tags to host")
                    except HTTPException as e:
                        message = (
                            "Error encountered trying to block Host ID {}: {}".format(
                                host.id, str(e)
                            )
                        )
                        self.logger.error(message)
                        self.err_msg.append(message)

    def block_accounts(self, accounts_to_block):
        for account_id, account in accounts_to_block.items():
            usable_third_party_clients = [
                tag.split(":")[1].lower()
                for tag in account.tags
                if tag.lower().startswith("client")
            ]
            for third_party_client in self.third_party_clients:
                if usable_third_party_clients == []:
                    pass
                else:
                    try:
                        self.logger.debug(
                            f"TPC:{third_party_client.module.lower()}; Usable TPCs:{usable_third_party_clients}"
                        )
                        if (
                            third_party_client.module.lower()
                            not in usable_third_party_clients
                        ):
                            continue
                    except AttributeError:
                        continue
                try:
                    # Block account
                    blocked_elements = third_party_client.block_account(account=account)
                    if len(blocked_elements) > 0:
                        message = (
                            "Blocked account {id}, {name},  on client {client}".format(
                                id=account_id,
                                name=account.name,
                                client=third_party_client.name,
                            )
                        )
                        self.logger.info(message)
                        self.info_msg.append(message)

                        # Set a "VAR Account Blocked" to set the account as being blocked and
                        # register what elements were blocked in separate tags
                        tag_to_set = account.tags
                        tag_to_set.append("VAR Account Blocked")

                        for element in blocked_elements:
                            tag_to_set.append(
                                "VAR ID:{client_class}:{id}".format(
                                    client_class=third_party_client.name,
                                    id=element,
                                )
                            )
                        self.vectra_api_client.set_account_tags(
                            account_id=account_id, tags=tag_to_set, append=False
                        )
                        self.vectra_api_client.set_account_note(
                            account_id=account_id,
                            note="VAR: Blocked on {}".format(
                                datetime.now().strftime("%d %b %Y at %H:%M:%S")
                            ),
                        )
                        self.logger.debug("Added Tags to account")
                    else:
                        message = "Did not find any elements to block on account ID {}".format(
                            account_id
                        )
                        self.logger.warning(message)
                        self.warn_msg.append(message)

                except HTTPException as e:
                    message = (
                        "Error encountered trying to block account ID {}: {}".format(
                            account.id, str(e)
                        )
                    )
                    self.logger.error(message)
                    self.err_msg.append(message)

    def unblock_accounts(self, accounts_to_unblock):
        for account_id, account in accounts_to_unblock.items():
            blocked_elements = account.blocked_elements
            if len(blocked_elements) < 1:
                message = "Could not find what was blocked on account {}".format(
                    account.name
                )
                self.logger.error(message)
                self.err_msg.append(message)
                continue
            for third_party_client in self.third_party_clients:
                try:
                    unblocked_elements = third_party_client.unblock_account(account)
                    if len(unblocked_elements) > 0:
                        for element in unblocked_elements:
                            blocked_elements[third_party_client.name].remove(element)
                            self.logger.debug("Unblocked element {}".format(element))
                        self.logger.info(
                            "Unblocked account {id}, {name} on client {client}".format(
                                id=account_id,
                                name=account.name,
                                client=third_party_client.name,
                            )
                        )
                        # Remove all tags set by this script from the account.
                        if "block" in account.tags:
                            message = 'Account {} is in no-block list but has a "block" tag. Removing tag..'.format(
                                account.display_name
                            )
                            self.logger.warning(message)
                            self.warn_msg.append(message)
                            account.tags.remove("block")
                        self.vectra_api_client.set_account_tags(
                            account_id=account_id, tags=account.tags, append=False
                        )
                        self.vectra_api_client.set_account_note(
                            account_id=account_id,
                            note="VAR: Unblocked on {}".format(
                                datetime.now().strftime("%d %b %Y at %H:%M:%S")
                            ),
                        )
                        self.logger.debug("Removed tags")
                    else:
                        message = "Could not unblock account {}".format(account.name)
                        self.logger.error(message)
                        self.err_msg.append(message)
                except HTTPException as e:
                    message = (
                        "Error encountered trying to unblock Account ID{}: {}".format(
                            account.id, str(e)
                        )
                    )
                    self.logger.error(message)
                    self.err_msg.append(message)

    def block_detections(self, detections_to_block):
        for detection_id, detection in detections_to_block.items():
            usable_third_party_clients = [
                tag.split(":")[1].lower()
                for tag in detection_id.tags
                if tag.lower().startswith("client")
            ]
            for third_party_client in self.third_party_clients:
                if usable_third_party_clients == []:
                    pass
                else:
                    try:
                        self.logger.debug(
                            f"TPC:{third_party_client.module.lower()}; Usable TPCs:{usable_third_party_clients}"
                        )
                        if (
                            third_party_client.module.lower()
                            not in usable_third_party_clients
                        ):
                            continue
                    except AttributeError:
                        continue
                try:
                    # Block endpoint
                    blocked_elements = third_party_client.block_detection(
                        detection=detection
                    )
                    if len(blocked_elements) > 0:
                        # Set a "VAR Detection Blocked" to set the detection as being blocked
                        # and register what elements were blocked in separate tags
                        tag_to_set = detection.tags
                        tag_to_set.append("VAR Detection Blocked")
                        if len(blocked_elements) < 1:
                            message = "Did not find any elements to block on detection ID {}".format(
                                detection.id
                            )
                            self.logger.warning(message)
                            self.warn_msg.append(message)
                        for element in blocked_elements:
                            tag_to_set.append(
                                "VAR ID:{client_class}:{id}".format(
                                    client_class=third_party_client.name,
                                    id=element,
                                )
                            )
                        message = "Blocked detection ID {id} on client {client}".format(
                            id=detection.id,
                            client=third_party_client.name,
                        )
                        self.logger.info(message)
                        self.info_msg.append(message)
                        self.vectra_api_client.set_detection_tags(
                            detection_id=detection_id, tags=tag_to_set, append=False
                        )
                        self.vectra_api_client.set_detection_note(
                            detection_id=detection.id,
                            note="VAR: Blocked on {}".format(
                                datetime.now().strftime("%d %b %Y at %H:%M:%S")
                            ),
                        )
                        self.logger.debug("Added Tags to detection")
                    else:
                        message = "Did not find any elements to block on detection ID {}".format(
                            detection.id
                        )
                        self.logger.warning(message)
                        self.warn_msg.append(message)
                except HTTPException as e:
                    message = (
                        "Error encountered trying to block detection ID {}: {}".format(
                            detection.id, str(e)
                        )
                    )
                    self.logger.error(message)
                    self.err_msg.append(message)

    def unblock_detections(self, detections_to_unblock):
        for detection_id, detection in detections_to_unblock.items():
            blocked_elements = detection.blocked_elements
            if len(blocked_elements) < 1:
                message = "Could not find what was blocked on detection {}".format(
                    detection.id
                )
                self.logger.error(message)
                self.err_msg.append(message)
                continue
            for third_party_client in self.third_party_clients:
                try:
                    unblocked_elements = third_party_client.unblock_detection(detection)
                    for element in unblocked_elements:
                        blocked_elements[third_party_client.name].remove(element)
                        self.logger.debug("Unblocked element {}".format(element))
                    message = "Unblock detection ID {id} on {client}".format(
                        id=detection.id,
                        client=third_party_client.name,
                    )
                    self.logger.info(message)
                    self.info_msg.append(message)
                    # Remove all tags set by this script from the detection.
                    if "block" in detection.tags:
                        message = 'detection ID {} is in no-block list but has a "block" tag. Removing tag..'.format(
                            detection.id
                        )
                        self.logger.warning(message)
                        self.warn_msg.append(message)
                        detection.tags.remove("block")
                    self.vectra_api_client.set_detection_tags(
                        detection_id=detection_id, tags=detection.tags, append=False
                    )
                    self.vectra_api_client.set_detection_note(
                        detection_id=detection.id,
                        note="VAR: Unblocked on {}".format(
                            datetime.now().strftime("%d %b %Y at %H:%M:%S")
                        ),
                    )
                    self.logger.debug("Removed tags")
                    # else:
                    #     message = "Could not unblock detection {}".format(detection.id)
                    #     self.logger.error(message)
                    #     self.err_msg.append(message)
                except HTTPException as e:
                    message = "Error encountered trying to unblock detection ID {}: {}".format(
                        detection.id, str(e)
                    )
                    self.logger.error(message)
                    self.err_msg.append(message)

    def block_static_dst_ips(self, ips_to_block):
        if len(ips_to_block) > 0:
            dst_ips = VectraStaticIP(dst_ips=ips_to_block)
            for third_party_client in self.third_party_clients:
                third_party_client.block_static_dst_ips(dst_ips)

    def unblock_static_dst_ips(self, ips_to_unblock):
        if len(ips_to_unblock) > 0:
            dst_ips = VectraStaticIP(dst_ips=ips_to_unblock)
            for third_party_client in self.third_party_clients:
                third_party_client.unblock_static_dst_ips(dst_ips)


# Functioned used to generate notification
def generate_messages(messages, **kwargs):
    if SEND_EMAIL or kwargs.get("test_smtp", False):
        if kwargs.get("test_smtp", False):
            if not all([SRC_EMAIL, DST_EMAIL, SMTP_USER, SMTP_SERVER, SMTP_PORT]):
                logger.error("Configure SMTP to test.")
                sys.exit()

        sender_id = SRC_EMAIL
        receiver_id = DST_EMAIL
        smtp_user = SMTP_USER
        smtp = None

        try:
            smtp = smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT)
        except smtplib.SMTPException:
            logger.debug("SMTP Server does not support SSL")
        except ssl.SSLError as e:
            logger.debug(str(e))

        if smtp is None:
            try:
                smtp = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
                smtp.starttls()
            except smtplib.SMTPNotSupportedError:
                logger.debug("SMTP Server does not support STARTTLS")
                pass

        if SMTP_AUTH:
            try:
                smtp.login(smtp_user, _get_password("VAR", "Email", kwargs))
            except smtplib.SMTPAuthenticationError:
                logger.error("SMTP Authentication Error")

        if not kwargs.get("test_smtp", False):
            i = 0
            msg_type = ["Info", "Warning", "Error"]
            string = ""
            for collection in messages:
                if collection != []:
                    string = msg_type[i] + "\n"
                    for message in collection:
                        string += message
                        string += "\n"
                i += 1
            email_body = string
            email_subject = "Vectra Automated Response"
            message = "Subject: {}\n\n{}".format(email_subject, email_body)
        else:
            email_body = "Info: TEST TEST TEST"
            email_subject = "TEST - Vectra Automated Response - TEST "
            message = "Subject: {}\n\n{}".format(email_subject, email_body)

        # Sending Email
        try:
            if email_body != "":
                if kwargs.get("test_smtp", False):
                    logger.info("Sending test email...")
                else:
                    logger.info("Sending email messages...")
                smtp.sendmail(sender_id, receiver_id, message)
        except smtplib.SMTPSenderRefused as err:
            logger.error("Sender address refused: {}".format(err))
        except smtplib.SMTPRecipientsRefused as err:
            logger.error("Recipient address refused: {}".format(err))
        except smtplib.SMTPDataError as err:
            logger.error("Server refused to accept message data: {}".format(err))
        except smtplib.SMTPException as err:
            logger.error("SMTP Error: {}".format(err))

        # Close Session
        smtp.quit()

    if SEND_SYSLOG or kwargs.get("test_syslog", False):
        syslog = logging.getLogger("syslog")
        msg_type = ["Info", "Warning", "Error"]
        syslog_lvl = [syslog.info, syslog.warning, syslog.error]
        sev = [2, 5, 8]
        if not kwargs.get("test_syslog", False):
            i = 0
            for collection in messages:
                if collection != []:
                    string = msg_type[i] + ": "
                    for message in collection:
                        string += message
                        string += "; "
                    if SYSLOG_FORMAT == "CEF":
                        msg = f"CEF:0|Vectra Networks|X Series|var|Vectra Automated Response|{sev[i]}|{string}"
                    elif SYSLOG_FORMAT == "Standard":
                        msg = f"{string}"

                    logger.info("Sending syslog messages...")
                    syslog_lvl[i](msg)
                i += 1
        else:
            logger.info("Sending test syslog...")
            string = "INFO: TEST TEST TEST"
            if SYSLOG_FORMAT == "CEF":
                msg = f"CEF:0|Vectra Networks|X Series|var|Vectra Automated Response|2|{string}"
            elif SYSLOG_FORMAT == "Standard":
                msg = f"{string}"
            syslog_lvl[0](msg)


def conf_syslog():
    try:
        syslog = logging.getLogger("syslog")
        syslog.setLevel(logging.INFO)
        syslog.propagate = False
        proto = {"TCP": socket.SOCK_STREAM, "UDP": socket.SOCK_DGRAM}
        syslog_handle = SysLogHandler(
            address=(SYSLOG_SERVER, int(SYSLOG_PORT)), socktype=proto[SYSLOG_PROTO]
        )
        syslog.addHandler(syslog_handle)
    except ConnectionRefusedError:
        logger.error("Check Syslog configurations.")


def main(args, vectra_api_client, modify, log_dict_config):
    var = VectraAutomatedResponse(
        brain=vectra_api_client.url,
        third_party_clients=[
            Third_Party_Client.Client(modify=modify, dict_config=log_dict_config)
            for Third_Party_Client in Third_Party_Clients
        ],
        vectra_api_client=vectra_api_client,
        block_host_tag=BLOCK_HOST_TAG,
        block_account_tag=BLOCK_ACCOUNT_TAG,
        block_host_tc_score=BLOCK_HOST_THREAT_CERTAINTY,
        block_host_urgency_score=BLOCK_HOST_URGENCY,
        block_account_tc_score=BLOCK_ACCOUNT_THREAT_CERTAINTY,
        block_account_urgency_score=BLOCK_ACCOUNT_URGENCY,
        block_host_group_name=BLOCK_HOST_GROUP_NAME,
        block_account_group_name=BLOCK_ACCOUNT_GROUP_NAME,
        block_host_detection_types=BLOCK_HOST_DETECTION_TYPES,
        block_account_detection_types=BLOCK_ACCOUNT_DETECTION_TYPES,
        block_host_detections_types_min_host_tc=BLOCK_HOST_DETECTION_TYPES_MIN_TC_SCORE,
        block_account_detections_types_min_account_tc=BLOCK_ACCOUNT_DETECTION_TYPES_MIN_TC_SCORE,
        no_block_host_group_name=NO_BLOCK_HOST_GROUP_NAME,
        no_block_account_group_name=NO_BLOCK_ACCOUNT_GROUP_NAME,
        external_block_host_tc=EXTERNAL_BLOCK_HOST_TC,
        external_block_detection_types=EXTERNAL_BLOCK_DETECTION_TYPES,
        external_block_detection_tag=EXTERNAL_BLOCK_DETECTION_TAG,
        static_dest_ip_block_file=STATIC_BLOCK_DESTINATION_IPS,
        log_dict_config=log_dict_config,
        explicit_unblock=EXPLICIT_UNBLOCK,
        unblock_host_tag=UNBLOCK_HOST_TAG,
        unblock_account_tag=UNBLOCK_ACCOUNT_TAG,
        external_unblock_detection_tag=EXTERNAL_UNBLOCK_DETECTION_TAG,
    )

    if SEND_SYSLOG:
        conf_syslog()

    def take_action(alert):
        (
            hosts_to_block,
            hosts_to_unblock,
            hosts_to_groom,
        ) = var.get_hosts_to_block_unblock(groom=args.groom)

        if not alert:
            var.block_hosts(hosts_to_block)
            var.unblock_hosts(hosts_to_unblock)
            var.groom_hosts(hosts_to_groom)

        accounts_to_block, accounts_to_unblock = var.get_accounts_to_block_unblock()
        if not alert:
            var.block_accounts(accounts_to_block)
            var.unblock_accounts(accounts_to_unblock)

        (
            detections_to_block,
            detections_to_unblock,
        ) = var.get_detections_to_block_unblock()
        if not alert:
            var.block_detections(detections_to_block)
            var.unblock_detections(detections_to_unblock)

        (
            static_dst_ips_to_block,
            static_ips_to_unblock,
        ) = var.get_static_dst_ips_to_block_unblock()
        if not alert:
            var.block_static_dst_ips(static_dst_ips_to_block)
            var.unblock_static_dst_ips(static_ips_to_unblock)

        generate_messages((var.info_msg, var.warn_msg, var.err_msg))
        if len(var.info_msg) == len(var.warn_msg) == len(var.err_msg) == 0:
            var.logger.info("No actions taken.")
        var.logger.info("Run finished.")

    def create_block_days():
        block_days = []
        if BLOCK_DAYS == [] or "week" in BLOCK_DAYS:
            block_days = [0, 1, 2, 3, 4, 5, 6]
        elif "weekday" in BLOCK_DAYS:
            block_days = [0, 1, 2, 3, 4]
        elif "weekend" in BLOCK_DAYS:
            block_days = [5, 6]
        else:
            days = {
                "monday": 0,
                "tuesday": 1,
                "wednesday": 2,
                "thursday": 3,
                "friday": 4,
                "saturday": 5,
                "sunday": 6,
            }
            for day in BLOCK_DAYS:
                block_days.append(days[day])
        return block_days

    def create_block_time(block_days):
        today = datetime.today()
        if BLOCK_START_TIME != "" and BLOCK_END_TIME != "":
            time_diff = 24 + (int(BLOCK_END_TIME) - int(BLOCK_START_TIME))
            start = datetime(
                year=today.year,
                month=today.month,
                day=today.day,
                hour=int(BLOCK_START_TIME),
            )
            end = start + timedelta(hours=time_diff)
        elif BLOCK_START_TIME == "" or BLOCK_END_TIME == "":
            logger.info(
                "Either a start or end time was not provided. Handling as full time."
            )
            start = datetime(
                year=today.year, month=today.month, day=today.day, hour=0, minute=0
            )
            end = datetime(
                year=today.year, month=today.month, day=today.day, hour=23, minute=59
            )
        return start, end

    if args.loop:
        init = True
        block_days = create_block_days()
        start, end = create_block_time(block_days)

        test = datetime.now()

        while True:
            if vectra_api_client.version > 2:
                vectra_api_client._check_token()
            if test.weekday() in block_days:
                if init and (test - timedelta(hours=24)).weekday() in block_days:
                    if (
                        (start - timedelta(hours=24))
                        <= datetime.now()
                        <= (end - timedelta(hours=24))
                    ):
                        test -= timedelta(hours=24)
                        start -= timedelta(hours=24)
                        end -= timedelta(hours=24)

                while start <= datetime.now() <= end:
                    take_action(args.alert)
                    time.sleep(60 * SLEEP_MINUTES)

                init = False

                if test.weekday() != datetime.now().weekday():
                    test = datetime.now()
                    start += timedelta(hours=24)
                    end += timedelta(hours=24)
                logger.info("Not within automated response window.")
            else:
                take_action(args.alert)

            time.sleep(60 * SLEEP_MINUTES)
    else:
        take_action(args.alert)


if __name__ == "__main__":

    def obtain_args():
        parser = argparse.ArgumentParser(
            description="Vectra Automated Response Framework ",
            prefix_chars="--",
            formatter_class=argparse.RawTextHelpFormatter,
            epilog="",
        )
        parser.add_argument(
            "--loop",
            default=False,
            action="store_true",
            help="Run in loop.  Required when ran as service or caching.",
        )

        parser.add_argument(
            "--groom",
            default=False,
            action="store_true",
            help="Attempt to re-block hosts to accommodate changes to IP addresses.",
        )
        parser.add_argument(
            "--alert",
            default=False,
            action="store_true",
            help="Show what is found, but don't take action.",
        )
        parser.add_argument(
            "--debug",
            default=False,
            action="store_true",
            help="Set DEBUG log level.",
        )

        parser.add_argument(
            "--no_store_secrets",
            default=False,
            action="store_true",
            help="Determines whether or not to write secrets to system's keyring",
        )

        parser.add_argument(
            "--update_secrets",
            default=False,
            action="store_true",
            help="Change secrets stored in keyring",
        )

        parser.add_argument(
            "--test_smtp",
            default=False,
            action="store_true",
            help="Test SMTP configurations",
        )

        parser.add_argument(
            "--test_syslog",
            default=False,
            action="store_true",
            help="Test Syslog configurations",
        )

        parser.add_argument(
            "--plaintext",
            default=False,
            action="store_true",
            help="Utilize keyrings.alt.file",
        )

        return parser.parse_args()

    args = obtain_args()
    log_dict_config = custom_log.dict_config
    for loggers in log_dict_config["loggers"]:
        if loggers == "urllib3":
            pass
        else:
            log_dict_config["loggers"][loggers]["level"] = (
                "INFO" if not args.debug else "DEBUG"
            )
    logging.config.dictConfig(log_dict_config)
    logger = logging.getLogger("VAR")

    if args.plaintext:
        keyring.set_keyring(file.PlaintextKeyring())

    if args.test_syslog:
        logger = logging.getLogger("Syslog")
        log_conf()
        conf_syslog()
        generate_messages("", test_syslog=True)
        sys.exit()

    if args.test_smtp:
        logger = logging.getLogger("SMTP")
        log_conf()
        generate_messages("", test_smtp=True)
        sys.exit()

    exit = False
    for imported_list in [
        COGNITO_URL,
        BLOCK_DAYS,
        THIRD_PARTY_CLIENTS,
        BLOCK_HOST_DETECTION_TYPES,
        EXTERNAL_BLOCK_DETECTION_TYPES,
        BLOCK_ACCOUNT_DETECTION_TYPES,
    ]:
        if not isinstance(imported_list, list):
            TypeException(namestr(imported_list, globals())[0], type([]))
            exit = True

    for imported_tuple in [
        BLOCK_HOST_THREAT_CERTAINTY,
        BLOCK_HOST_DETECTION_TYPES_MIN_TC_SCORE,
        EXTERNAL_BLOCK_HOST_TC,
        BLOCK_ACCOUNT_THREAT_CERTAINTY,
        BLOCK_ACCOUNT_DETECTION_TYPES_MIN_TC_SCORE,
    ]:
        if not isinstance(imported_tuple, tuple):
            TypeException(namestr(imported_tuple, globals())[0], type(()))
            exit = True

    if exit:
        logger.error(
            "Correct configurations and re-run.\
             Note that lists should be wrapped in square brackets, [], \
             and tuples wrapped in parentheses, ()."
        )
        sys.exit()

    if args.no_store_secrets:
        store = False
    else:
        store = True

    modify = (store, args.update_secrets)
    vectra_api_clients = []
    for url in COGNITO_URL:
        logger.debug(f"Configuring Vectra API Client for {url}")
        if URL in url:
            vectra_api_clients.append(
                VectraClientV3(
                    url=url,
                    client_id=_get_password(url, "Client_ID", modify=modify),
                    secret_key=_get_password(url, "Secret_Key", modify=modify),
                    store=store,
                )
            )
        else:
            vectra_api_clients.append(
                VectraClientV2(
                    url=url,
                    token=_get_password(url, "Token", modify=modify),
                )
            )

    processors = []
    logger.debug("Creating individual process for each Vectra API Client")
    for vectra_api_client in vectra_api_clients:
        processors.append(
            Process(
                target=main,
                args=(args, vectra_api_client, modify, log_dict_config),
            )
        )
    for p in processors:
        p.start()
    for p in processors:
        p.join()
