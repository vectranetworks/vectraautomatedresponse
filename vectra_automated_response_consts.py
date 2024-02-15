import datetime
import ipaddress
import re


class VectraHost:
    def __init__(self, host):
        self.id = host["id"]
        self.name = host["name"]
        self.ip = host["last_source"]
        self.probable_owner = host["probable_owner"]
        self.certainty = host["certainty"]
        self.threat = host["threat"]
        self.is_key_asset = host["key_asset"]
        self.targets_key_asset = host["targets_key_asset"]
        self.artifacts_types = self._get_artifact_types(host["host_artifact_set"])
        self.mac_addresses = self._get_host_mac_addresses(host["host_artifact_set"])
        self.vmware_vm_name = self._get_vmware_vm_name(host["host_artifact_set"])
        self.vmware_vm_uuid = self._get_vmware_vm_uuid(host["host_artifact_set"])
        self.aws_vm_uuid = self._get_aws_vm_uuid(host["host_artifact_set"])
        self.tags = self._get_external_tags(host["tags"])
        self.most_recent_note = host["note"]
        self.blocked_elements = self._get_blocked_elements(host["tags"])
        self.last_seen = (
            host.get("last_seen")
            if host.get("last_seen") is not None
            else datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        )
        self.last_seen_ts_utc = datetime.datetime.strptime(
            self.last_seen, "%Y-%m-%dT%H:%M:%S.%fZ"
        ).timestamp()
        self._raw = host

    def get_full_name(self):
        if "windows_defender_name" in self.artifacts_types:
            return self._get_artifact_value("windows_defender_name")[0]
        if "dns" in self.artifacts_types:
            return self._get_artifact_value("dns")[0]
        if "rdns" in self.artifacts_types:
            return self._get_artifact_value("rdns")[0]
        if self._raw["ldap"]:
            if "dns_hostname" in self._raw["ldap"].keys():
                return self._raw["ldap"]["dns_hostname"][0]
        return self.name

    def _get_artifact_value(self, artifact_type):
        values = set()
        for artifact in self._raw["host_artifact_set"]:
            if artifact["type"] == artifact_type:
                values.add(artifact["value"])
        return list(values)

    def _get_artifact_types(self, artifact_set):
        artifact_keys = set()
        for artifact in artifact_set:
            artifact_keys.add(artifact["type"])
        return list(artifact_keys)

    def _get_host_mac_addresses(self, artifact_set):
        mac_addresses = set()
        for artifact in artifact_set:
            if artifact["type"] == "mac":
                mac_addresses.add(artifact["value"])
        return list(mac_addresses)

    def _get_vmware_vm_name(self, artifact_set):
        for artifact in artifact_set:
            if artifact["type"] == "vmachine_info":
                return artifact["value"]
        return None

    def _get_vmware_vm_uuid(self, artifact_set):
        for artifact in artifact_set:
            if artifact["type"] == "vm_uuid":
                return artifact["value"]
        return None

    def _get_aws_vm_uuid(self, artifact_set):
        for artifact in artifact_set:
            if artifact["type"] == "aws_vm_uuid":
                return artifact["value"]
        return None

    def _get_blocked_elements(self, tags):
        blocked_elements = {}
        for tag in tags:
            if tag.startswith("VAR ID:"):
                # Tags are in the form "VAR ID:Client:ID"
                blocking_client = re.findall(":.*?:", tag)[0].replace(":", "")
                id = tag[tag.find(blocking_client) + len(blocking_client) + 1 :]
                if blocking_client not in blocked_elements:
                    blocked_elements[blocking_client] = [id]
                else:
                    blocked_elements[blocking_client].append(id)
        return blocked_elements

    def _get_external_tags(self, tags):
        tags_to_keep = []
        for tag in tags:
            if not tag.startswith("VAR ID:") and tag not in ["VAR Blocked","block","unblock"]:
                tags_to_keep.append(tag)
        return tags_to_keep


class VectraAccount:
    def __init__(self, account):
        self._raw = account
        self.id = account["id"]
        self.names = account["name"]
        self.display_name = (
            account["display_name"] if account.get("display_name") else account["name"]
        )
        self.type = account["account_type"]
        self.certainty = account["certainty"]
        self.threat = account["threat"]
        self.severity = account["severity"]
        self.ldap = self._get_ldap()
        # self.is_key_asset = account['key_asset']
        # self.targets_key_asset = account['targets_key_asset']
        self.privilege_level = account["privilege_level"]
        self.privilege_category = account["privilege_category"]
        self.probable_home = account["probable_home"]
        self.tags = self._get_external_tags(account["tags"])
        self.most_recent_note = account["note"]
        self.blocked_elements = self._get_blocked_elements(account["tags"])
        self.context = self._get_context_tag(account["tags"])
        self.normalized_name = (
            re.split(":", self.display_name)[1]
            if re.findall(":", self.display_name)
            else self.display_name
        )
        self.fake_sam = self.normalized_name.split("@")[0]

    def _get_ldap(self):
        values = {}
        if self._raw.get("ldap") is not None:
            values["description"] = self._raw["description"]
            values["location"] = self._raw["location"]
            values["sam_account_name"] = self._raw["sAMAccountName"]
            values["title"] = self._raw["title"]
            values["upn"] = self._raw["user_principal_name"]
            values["common_name"] = self._raw["common_name"]
            values["email"] = self._raw["email"]
        return values

    @staticmethod
    def _get_context_tag(tags):
        context = ""
        for tag in tags:
            if tag.startswith("Context:"):
                context = re.split(":", tag)[1]
        return context

    @staticmethod
    def _get_blocked_elements(tags):
        blocked_elements = {}
        for tag in tags:
            if tag.startswith("VAR ID:"):
                # Tags are in the form "VAR ID:Client:ID"
                blocking_client = re.findall(":.*?:", tag)[0].replace(":", "")
                id = tag[tag.find(blocking_client) + len(blocking_client) + 1 :]
                if blocking_client not in blocked_elements:
                    blocked_elements[blocking_client] = [id]
                else:
                    blocked_elements[blocking_client].append(id)
        return blocked_elements

    @staticmethod
    def _get_external_tags(tags):
        tags_to_keep = []
        for tag in tags:
            if not tag.startswith("VAR ID:") and tag not in ["VAR Blocked","block","unblock"]:
                tags_to_keep.append(tag)
        return tags_to_keep


class VectraStaticIP:
    def __init__(self, src_ips=[], dst_ips=[]):
        self.src_ips = (src_ips,)
        self.dst_ips = dst_ips


class VectraDetection:
    def __init__(self, detection):
        self.id = detection["id"]
        self.host_id = detection["src_host"]["id"]
        self.category = detection["category"]
        self.detection_type = detection["detection_type"]
        self.src = detection["src_ip"]
        self.dst_ips = self._get_dst_ips(detection)
        self.dst_domains = self._get_dst_domains(detection)
        self.state = detection["state"]
        self.c_score = detection["c_score"]
        self.t_score = detection["t_score"]
        self.targets_ka = detection["targets_key_asset"]
        self.triage = detection["triage_rule_id"]
        self.tags = self._get_external_tags(detection["tags"])
        self.blocked_elements = self._get_blocked_elements(detection["tags"])

    def _get_dst_ips(self, detection):
        dst_ips = set()
        for ip in detection["summary"].get("dst_ips", []):
            try:
                if not ipaddress.ip_address(ip).is_private:
                    dst_ips.add(ip)
            except ValueError:
                continue
        return list(dst_ips)

    def _get_dst_domains(self, detection):
        dst_domains = set()
        for domain in detection["summary"].get("target_domains", []):
            dst_domains.add(domain)
        return list(dst_domains)

    def _get_blocked_elements(self, tags):
        blocked_elements = {}
        for tag in tags:
            if tag.startswith("VAR ID:"):
                # Tags are in the form "VAR ID:Client:ID"
                blocking_client = re.findall(":.*?:", tag)[0].replace(":", "")
                id = tag[tag.find(blocking_client) + len(blocking_client) + 1 :]
                if blocking_client not in blocked_elements:
                    blocked_elements[blocking_client] = [id]
                else:
                    blocked_elements[blocking_client].append(id)
        return blocked_elements

    def _get_external_tags(self, tags):
        tags = []
        for tag in tags:
            if not tag.startswith("VAR ID:") and tag not in ["VAR Blocked","block","unblock"]:
                tags.append(tag)
        return tags
