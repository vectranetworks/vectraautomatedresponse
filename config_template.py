### GENERAL SETUP
# Vectra brain API access.
COGNITO_URL = "https://<fqdn or ip>"
COGNITO_TOKEN = "api token"
COGNITO_CLIENT_ID = "client_id"
COGNITO_SECRET_KEY = "secret_key"
# V3 is a boolean for which API Client to use
V3 = False 
LOG_TO_FILE = False
LOG_FILE = "vae.log"
SLEEP_MINUTES = 5
# Available options: ['bitdefender', 'cisco_amp', 'cisco_fmc', 'cisco_ise',
# 'cisco_nxos', 'cisco_pxgrid', 'clearpass', 'endgame', 'external_call', 'fortinet',
# 'harmony', 'meraki', 'pan', 'pulse_nac', 'sophos', 'test_client', 'trendmicro_apexone',
# 'trendmicro_cloudone', 'trendmicro_visionone', 'vmware', 'windows_shutdown', 'withsecure_elements']
THIRD_PARTY_CLIENTS = ["test_client"]

### ALLOWED BLOCKING WINDOW
# Days that automated blocking is allowed
BLOCK_DAYS = []
# Time windows that automated blocking is allowed
# 0-23
BLOCK_START_TIME = 0
# 0-23
BLOCK_END_TIME = 0

### INTERNAL IP BLOCKING
# Tag that will cause a host to be blocked; remove the tag to unblock the host
BLOCK_HOST_TAG = "block"
# Host group for which member will NEVER be blocked.
NO_BLOCK_HOST_GROUP_NAME = "NoBlock"
# Host groupfor which all members will be blocked
BLOCK_HOST_GROUP_NAME = "Block"
# Threshold threat/certainty score for automatically blocking host.
# The middle argument can be 'and' or 'or', defining how the threshold conditions are read
BLOCK_HOST_THREAT_CERTAINTY = (100, "and", 100)
# List of detection types that when present will cause host to be blocked.
# The second argument enforces a threat/cetainty threshold for hosts with those detection types on.
BLOCK_HOST_DETECTION_TYPES = []
BLOCK_HOST_DETECTION_TYPES_MIN_TC_SCORE = (100, "or", 100)

### EXTERNAL IP BlOCKING
# Host threat/certainty score when reached will get all detections on the host.
# All external IPs in those detections will then be blocked.
# The middle argument can be 'and' or 'or', defining how the threshold conditions are read
EXTERNAL_BLOCK_HOST_TC = (100, "and", 100)
# Tag to block external IPs present in detection; remove the tag to unblock the detection.
EXTERNAL_BLOCK_DETECTION_TAG = "block"
# Detection types for which we will block all external IPs present on those.
# E.g. "External Remote Access, Data Smuggler"
EXTERNAL_BLOCK_DETECTION_TYPES = []
# File containing static destination IPs to block
STATIC_BLOCK_DESTINATION_IPS = "static_dst_ips_to_block.txt"

### ACCOUNT BLOCKING
# Tag that will cause an account to be blocked; remove the tag to unblock the host
BLOCK_ACCOUNT_TAG = "block"
# Account group for which member will NEVER be blocked.
NO_BLOCK_ACCOUNT_GROUP_NAME = "NoBlock"
# Account group for which all members will be blocked
BLOCK_ACCOUNT_GROUP_NAME = "Block"
# Threshold threat/certainty score for automatically blocking account.
# The middle argument can be 'and' or 'or', defining how the threshold conditions are read
BLOCK_ACCOUNT_THREAT_CERTAINTY = (100, "and", 100)
# List of detection types that when present will cause account to be blocked.
# The second argument enforces a threat/cetainty threshold for accounts with those detection types on.
BLOCK_ACCOUNT_DETECTION_TYPES = []
BLOCK_ACCOUNT_DETECTION_TYPES_MIN_TC_SCORE = (100, "or", 100)

### Notification Setup
# SMTP Configuration
SMTP_SERVER = "fqdn or ip"
SMTP_PORT = 25
SRC_EMAIL = "example@mail.com"
DST_EMAIL = "example@mail.com"
SMTP_AUTH = False
SMTP_USER = "user"
SMTP_PASSWORD = "password"

# Syslog Configuration
SYSLOG_SERVER = "fqdn or ip"
SYSLOG_PORT = 514
# Proto: TCP or UDP
SYSLOG_PROTO = "TCP"
# Format: Standard or CEF
SYSLOG_FORMAT = "CEF"
