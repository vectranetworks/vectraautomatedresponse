import logging
import subprocess
import uuid

from third_party_clients.external_call.external_call_config import (
    ACCOUNT_BLOCK_CMD,
    ACCOUNT_UNBLOCK_CMD,
    DETECTION_BLOCK_CMD,
    DETECTION_UNBLOCK_CMD,
    HOST_BLOCK_CMD,
    HOST_UNBLOCK_CMD,
)
from third_party_clients.third_party_interface import (
    ThirdPartyInterface,
    VectraAccount,
    VectraDetection,
    VectraHost,
    VectraStaticIP,
)


class Client(ThirdPartyInterface):
    def __init__(self):
        self.name = "External Call Client"
        # Instantiate parent class
        self.logger = logging.getLogger()
        ThirdPartyInterface.__init__(self)

    def block_host(self, host):
        if HOST_BLOCK_CMD:
            id = uuid.uuid4()
            cmd = HOST_BLOCK_CMD
            cmd.append(host.ip)
            r = subprocess.run(cmd)
            if r.returncode == 0:
                return [id]
            else:
                self.logger.warning('Execution of block_host command: {} was not successful'.format(r.args))
                return []
        else:
            self.logger.info('external_call block_host not configured.')
            return []

    def block_account(self, account) -> list:
        if ACCOUNT_BLOCK_CMD:
            id = uuid.uuid4()
            cmd = ACCOUNT_BLOCK_CMD
            cmd.append(account.ldap.get('sam_account_name') if account.ldap.get('sam_account_name')
                       else account.fake_sam)
            cmd.append(account.context)
            r = subprocess.run(cmd)
            if r.returncode == 0:
                return [id]
            else:
                self.logger.warning('Execution of block_account command: {} was not successful'.format(r.args))
                return []
        else:
            self.logger.info('external_call block_account not configured.')
            return []

    def unblock_host(self, host):
        if HOST_UNBLOCK_CMD:
            cmd = HOST_UNBLOCK_CMD
            cmd.append(host.ip)
            r = subprocess.run(cmd)
            if r.returncode == 0:
                return host.blocked_elements.get(self.__class__.__name__)
            else:
                self.logger.warning('Execution of unblock_host command: {} was not successful'.format(r.args))
                return []
        else:
            self.logger.info('external_call unblock_host not configured.')
            return []

    def unblock_account(self, account):
        if ACCOUNT_UNBLOCK_CMD:
            cmd = ACCOUNT_UNBLOCK_CMD
            cmd.append(account.ldap.get('sam_account_name') if account.ldap.get('sam_account_name')
                       else account.fake_sam)
            r = subprocess.run(cmd)
            if r.returncode == 0:
                return account.blocked_elements.get(self.__class__.__name__)
            else:
                self.logger.warning('Execution of block_account command: {} was not successful'.format(r.args))
                return []
        else:
            self.logger.info('external_call unblock_account not configured.')
            return []

    def groom_host(self, host) -> dict:
        self.logger.info('external_call groom_host not configured.')
        return []

    def block_detection(self, detection):
        if DETECTION_BLOCK_CMD:
            id = uuid.uuid4()
            cmd = DETECTION_BLOCK_CMD
            cmd.append(detection.dst_ips)
            r = subprocess.run(cmd)
            if r.returncode == 0:
                return [id]
            else:
                self.logger.warning('Execution of block_detection command: {} was not successful'.format(r.args))
                return []
        else:
            self.logger.info('external_call block_detection not configured.')
            return []

    def unblock_detection(self, detection):
        if DETECTION_UNBLOCK_CMD:
            cmd = DETECTION_UNBLOCK_CMD
            cmd.append(detection.dst_ips)
            r = subprocess.run(cmd)
            if r.returncode == 0:
                return detection.blocked_elements.get(self.__class__.__name__)
            else:
                self.logger.warning('Execution of unblock_detection command: {} was not successful'.format(r.args))
                return []
        else:
            self.logger.info('external_call unblock_detection not configured.')
            return []

    def block_static_dst_ips(self, ips: VectraStaticIP) -> list:
        self.logger.info('external_call block static destination IP not configured.')
        return []

    def unblock_static_dst_ips(self, ips: VectraStaticIP) -> list:
        self.logger.info('external_call block static destination IP not configured.')
        return []     