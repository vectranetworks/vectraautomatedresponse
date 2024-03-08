import base64
import logging

import requests
from cachetools import TTLCache, cached
from third_party_clients.bitdefender.bitdefender_config import (
    BLOCK_MULTIPLE,
    CHECK_SSL,
    HOSTNAME,
)
from third_party_clients.third_party_interface import ThirdPartyInterface

from vectra_automated_response import _get_password


class Client(ThirdPartyInterface):
    def __init__(self, **kwargs):
        self.name = "Harmony Client"
        self.logger = logging.getLogger()
        self.api_key = _get_password("Harmony", "API_Key", modify=kwargs["modify"])
        self.url = "https://" + HOSTNAME + "/api/v1.0/jsonrpc"
        self.verify = CHECK_SSL
        self.block_multiple = BLOCK_MULTIPLE
        login_string = self.apiKey + ":"
        encoded_bytes = base64.b64encode(login_string.encode())
        encoded_user_pass_sequence = str(encoded_bytes, "utf-8")
        self.authorization_header = {
            "Authorization": "Basic " + encoded_user_pass_sequence,
            "Content-Type": "application/json",
        }
        self.company_id = self._get_company_id()
        # Instantiate parent class
        ThirdPartyInterface.__init__(self)
