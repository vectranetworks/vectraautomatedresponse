import requests
import base64
import json
import time
import logging
from datetime import datetime
from third_party_clients.xtreme_networks_nbi.xnnbi_config import (
    CHECK_SSL,
    HOSTNAME,
)

from third_party_clients.third_party_interface import (
    ThirdPartyInterface,
    VectraAccount,
    VectraStaticIP
)

from common import _get_password


class Client(ThirdPartyInterface):
    def __init__(self, **kwargs):
        self.name = "XtremeNBI"
        self.nbiUrl = 'https://' + HOSTNAME + ':8443/nbi/graphql'
        self.host = HOSTNAME
        self.port  = 8443
        self.verify = CHECK_SSL
        self.clientId = _get_password("XNNBI", "Client_ID", modify=kwargs["modify"])  
        self.secret = _get_password("XNNBI", "Client_Secret", modify=kwargs["modify"])  
        self.timeout = 10
        self.token = None
        self.logger = logging.getLogger()
        self.expire = 0
        self.renewTime = 90 # in procentage of the max expire time
        self.session = self._login()
        # Instantiate parent class
        ThirdPartyInterface.__init__(self)

    def _computeExpireTime(self, TimeStart, TimeEnd):
        '''internal use only'''
        timeDiff = TimeEnd - TimeStart
        unixtime = time.mktime( datetime.today().timetuple() )
        return     unixtime + ( timeDiff.total_seconds() / 100 * self.renewTime )

    def _ifExpire(self):
        '''internal use only'''
        if self.expire > time.mktime( datetime.today().timetuple() ):
            return False
        else:
            return True

    def _login(self):
        '''internal use only'''
        token_url = 'https://'+ self.host +':'+ str(self.port) +'/oauth/token/access-token?grant_type=client_credentials'
        headers   = {"Content-Type" : "application/x-www-form-urlencoded"}
        response = requests.post(token_url, auth=(self.clientId, self.secret), headers=headers, verify=self.verify)
        response.raise_for_status()
        result = response.json()
        self.token = result.get('access_token')
        xmcTokenElements = self.token.split('.')
        tokenData = json.loads(base64.b64decode(xmcTokenElements[1]+ "==") )
        self.expire = self._computeExpireTime(datetime.fromtimestamp( tokenData['iat'] ), datetime.fromtimestamp( tokenData['exp'] ) )
        session = requests.Session()
        session.verify = False
        session.timeout = self.timeout
        session.headers.update({
            'Accept': 'application/json',
            'Content-type': 'application/json',
            'Authorization':'Bearer ' + self.token,
            'Cache-Control': 'no-cache',
            })
        return session

    def _query(self, query: str):
        if self._ifExpire():
            self.expire  = 0
            self.session = self._login()
        return self.session.post(self.nbiUrl, json = {'query': query})
    
    def _get_mac_from_ip(self, ip_address: str):
        mac_to_ip_query = f'''
        query getMAC {{
            accessControl {{
                endSystemByIp(ipAddress:"{ip_address}"){{
                    endSystem {{
                        ipAddress
                        macAddress
                    }}
                }}
            }}
        }}
        '''
        r = self._query(mac_to_ip_query)
        return r.json()['data']['accessControl']['endSystemByIp']['endSystem']['macAddress']
    
    def _add_mac_to_blacklist(self, mac_address:str):
        block_device_query = f'''
            mutation blockMAC {{
                accessControl {{
                    addMACToBlacklist(input: {{value:"{mac_address}", reauthenticate:true}}){{
                        status
                        errorCode
                        results
                    }}
                }}
            }}
            '''
        r = self._query(block_device_query)
        return int(r.json()['data']['accessControl']['addMACToBlacklist']['errorCode'])
    
    def _remove_mac_from_blacklist(self, mac_address:str):
        unblock_device_query = f'''
            mutation unblockMAC {{
                accessControl {{
                    removeMACFromBlacklist(input: {{value:"{mac_address}", reauthenticate:true}}){{
                        status
                        errorCode
                        results
                    }}
                }}
            }}
        '''
        r = self._query(unblock_device_query)
        return int(r.json()['data']['accessControl']['removeMACFromBlacklist']['errorCode'])
        
    def block_host(self, host):
        ip_address = host.ip
        mac_addresses = set(host.mac_addresses)
        resolved_mac_address = self._get_mac_from_ip(ip_address=ip_address)
        mac_addresses.update(resolved_mac_address)
        blocked_addresses = []
        for mac_address in mac_addresses:
            if self._add_mac_to_blacklist(mac_address) == 0:
                blocked_addresses.append(mac_address)
        return blocked_addresses

    def unblock_host(self, host):
        mac_addresses = host.blocked_elements.get(self.name, [])
        for mac_address in mac_addresses:
            self._remove_mac_from_blacklist(mac_address)
        return mac_addresses

    def groom_host(self, host) -> dict:
        self.logger.warn("This client does not implement host grooming")
        return []

    def block_detection(self, detection):
        # this client only implements Host-based blocking
        self.logger.warn("This client does not implement detection-based blocking")
        return []

    def unblock_detection(self, detection):
        # this client only implements Host-based blocking
        self.logger.warn("This client only implements Host-based blocking")
        return []

    def block_account(self, account: VectraAccount) -> list:
        # this client only implements Host-based blocking
        self.logger.warn("This client only implements Host-based blocking")
        return []

    def unblock_account(self, account: VectraAccount) -> list:
        # this client only implements Host-based blocking
        self.logger.warn("This client only implements Host-based blocking")
        return []

    def block_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        self.logger.warn("This client only implements Host-based blocking")
        return []

    def unblock_static_dst_ips(self, ips: VectraStaticIP) -> list:
        # this client only implements Host-based blocking
        self.logger.warn("This client only implements Host-based blocking")
        return []
