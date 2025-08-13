import logging
import uuid
import winrm

from common import _get_password
from third_party_clients.third_party_interface import (
    ThirdPartyInterface,
    VectraAccount,
    VectraHost,
    VectraStaticIP,
)

from third_party_clients.windows_killnic.windows_killnic_config import (
    PORT,
    SERVICE_NAME
)


# class TestClient(ThirdPartyInterface):
class Client(ThirdPartyInterface):
    def __init__(self, **kwargs):
        # Instantiate parent class
        self.name = "Windows Kill Network Interface"
        self.module = "windows_killnic"
        self.domain = _get_password(SERVICE_NAME, "domain", modify=kwargs["modify"])
        self.username = _get_password(SERVICE_NAME, "username", modify=kwargs["modify"])
        self.password = _get_password(SERVICE_NAME, "password", modify=kwargs["modify"])
        self.init_log(kwargs)
        ThirdPartyInterface.__init__(self)

    def init_log(self, kwargs):
        dict_config = kwargs.get("dict_config", {})
        dict_config["loggers"].update(
            {self.name: dict_config["loggers"]["VAR"]})
        logging.config.dictConfig(dict_config)
        self.logger = logging.getLogger(self.name)

    def block_host(self, host: VectraHost):
        winrm_url = f"http://{host.name}:{PORT}/wsman"

        powershell_script = """
        Get-WmiObject -Class Win32_NetworkAdapter |
        Where-Object { $_.NetEnabled -eq $true -and $_.PhysicalAdapter -eq $true } |
        ForEach-Object { $_.Disable() }
        """

        try:
            session = winrm.Session(
                winrm_url,
                auth=(f'{self.domain}\\{self.username}', self.password),
                transport='ntlm',
                server_cert_validation='ignore'
            )

            result = session.run_ps(powershell_script)

            std_out = result.std_out.decode() if result.std_out else ''
            std_err = result.std_err.decode() if result.std_err else ''

            self.logger.info(std_out)
            if std_err:
                self.logger.error(std_err)

        except Exception as e:
            self.logger.error(f"An issue ocurred trying to disable NIC of: {host.name}")
            return []
        
        return [host.name]

    def unblock_host(self, host: VectraHost):
        self.logger.warning("This client cannot restart a NIC automatically")
        return []

    def groom_host(self, host) -> dict:
        self.logger.warning("This client does not implement host grooming")
        return []

    def block_detection(self, detection):
        # this client only implements Host-based blocking
        self.logger.warning("This client does not implement detection-based blocking")
        return []

    def unblock_detection(self, detection):
        # this client only implements Host-based blocking
        self.logger.warning("This client only implements Host-based blocking")
        return []

    def block_account(self, account: VectraAccount) -> list:
        # this client only implements Host-based blocking
        self.logger.warning("This client only implements Host-based blocking")
        return []

    def unblock_account(self, account: VectraAccount) -> list:
        # this client only implements Host-based blocking
        self.logger.warning("This client only implements Host-based blocking")
        return []

    def block_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        self.logger.warning("This client only implements Host-based blocking")
        return []

    def unblock_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        self.logger.warning("This client only implements Host-based blocking")
        return []
