### GENERAL SETUP
# Vectra brain API access.
COGNITO_URL = [""]
SLEEP_MINUTES = 5

# The AUTH mechanism that you are using: OAUTH or TOKEN. Token is only valid for API v2.5 and lower
AUTH = "OAUTH"

# All brains must use the same API version. Run a different instance of this script for each API version

# Available options: ['bitdefender', 'checkpoint', 'cisco_amp', 'cisco_asa_http', 'cisco_fmc', 'cisco_ise',
# 'cisco_pxgrid', 'clearpass', 'cortex', 'endgame', 'external_call', 'forti_edr', 'fortinet',
# 'harmony', 'mcafee_epo', 'meraki', 'pan', 'pulse_nac', 'sophos', 'tanium', 'test_client', 'trendmicro_apexone',
# 'trendmicro_cloudone', 'trendmicro_visionone', 'vmware', 'watchguard', 'windows_killnic', 'windows_shutdown', 'withsecure_elements',
# 'xtreme_networks_nbi']
THIRD_PARTY_CLIENTS = ["test_client"]

### ALLOWED BLOCKING WINDOW
# Days that automated blocking is allowed
BLOCK_DAYS = []
# Time windows that automated blocking is allowed
# 0-23
BLOCK_START_TIME = 0
# 0-23
BLOCK_END_TIME = 0

EXPLICIT_UNBLOCK = False

### INTERNAL IP BLOCKING
# Tag that will cause a host to be blocked; remove the tag to unblock the host if EXPLICIT_UNBLOCK is False
BLOCK_HOST_TAG = "vectra_host_block"
# Tag that will cause a host to be unblocked; used with `EXPLICIT_UNBLOCK = True`
UNBLOCK_HOST_TAG = "vectra_host_unblock"
# Host group for which member will NEVER be blocked.
NO_BLOCK_HOST_GROUP_NAME = "NoBlock"
# Host group for which all members will be blocked
BLOCK_HOST_GROUP_NAME = "Block"
# Threshold threat/certainty score for automatically blocking host.
# The middle argument can be 'and' or 'or', defining how the threshold conditions are read
BLOCK_HOST_THREAT_CERTAINTY = (100, "and", 100)
# V3 Only - Threshold urgency score for automatically blocking host.
BLOCK_HOST_URGENCY = 100
# Can't have both BLOCK_HOST_THREAT_CERTAINTY and BLOCK_HOST_URGENCY.
# If both provided and V3 is True, BLOCK_HOST_URGENCY will be used.
# To use BLOCK_HOST_THREAT_CERTAINTY set BLOCK_HOST_URGENCY = None

# List of detection types that when present will cause host to be blocked.
# The second argument enforces a threat/certainty threshold for hosts with those detection types on.
# BLOCK_HOST_DETECTION_TYPES = ["External Remote Access","Hidden DNS Tunnel"]
BLOCK_HOST_DETECTION_TYPES = []
BLOCK_HOST_DETECTION_TYPES_MIN_TC_SCORE = (100, "and", 100)

### EXTERNAL IP BlOCKING
# Host threat/certainty score when reached will get all detections on the host.
# All external IPs in those detections will then be blocked.
# The middle argument can be 'and' or 'or', defining how the threshold conditions are read
EXTERNAL_BLOCK_HOST_TC = (100, "and", 100)
# Tag to block external IPs present in detection; remove the tag to unblock the host if EXPLICIT_UNBLOCK is False
EXTERNAL_BLOCK_DETECTION_TAG = "block"
# Tag to unblock external IPs present in detection; used with `EXPLICIT_UNBLOCK = True`
EXTERNAL_UNBLOCK_DETECTION_TAG = "unblock"
# Detection types for which we will block all external IPs present on those.
# E.g. "External Remote Access, Data Smuggler"
EXTERNAL_BLOCK_DETECTION_TYPES = []
# File containing static destination IPs to block
STATIC_BLOCK_DESTINATION_IPS = "static_dst_ips_to_block.txt"

### ACCOUNT BLOCKING
# Tag that will cause an account to be blocked; remove the tag to unblock the host if EXPLICIT_UNBLOCK is False
BLOCK_ACCOUNT_TAG = "vectra_account_block"
# Tag that will cause an account to be unblocked; used with `EXPLICIT_UNBLOCK = True`
UNBLOCK_ACCOUNT_TAG = "vectra_account_unblock"
# Account group for which member will NEVER be blocked.
NO_BLOCK_ACCOUNT_GROUP_NAME = "NoBlock"
# Account group for which all members will be blocked
BLOCK_ACCOUNT_GROUP_NAME = "Block"
# Threshold threat/certainty score for automatically blocking account.
# The middle argument can be 'and' or 'or', defining how the threshold conditions are read
BLOCK_ACCOUNT_THREAT_CERTAINTY = (100, "and", 100)
# V3 Only - Threshold urgency score for automatically blocking account.
BLOCK_ACCOUNT_URGENCY = 100
# Can't have both BLOCK_ACCOUNT_THREAT_CERTAINTY and BLOCK_ACCOUNT_URGENCY.
# If both provided and V3 is True, BLOCK_ACCOUNT_URGENCY will be used.
# To use BLOCK_ACCOUNT_THREAT_CERTAINTY set BLOCK_ACCOUNT_URGENCY = None

# List of detection types that when present will cause account to be blocked.
# The second argument enforces a threat/certainty threshold for accounts with those detection types on.
BLOCK_ACCOUNT_DETECTION_TYPES = []
BLOCK_ACCOUNT_DETECTION_TYPES_MIN_TC_SCORE = (100, "and", 100)

### Notification Setup
# SMTP Configuration
SEND_EMAIL = False
# SMTP Server FQDN or IP
SMTP_SERVER = ""
SMTP_PORT = 25

SRC_EMAIL = "example@email.com"
DST_EMAIL = "example@email.com"
SMTP_AUTH = False
SMTP_USER = "user"

# Syslog Configuration
SEND_SYSLOG = False
# Syslog Server FQDN or IP
SYSLOG_SERVER = ""
SYSLOG_PORT = 514
# Proto: TCP or UDP
SYSLOG_PROTO = "TCP"
# Format: Standard or CEF
SYSLOG_FORMAT = "CEF"
