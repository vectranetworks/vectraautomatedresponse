# FortiManager Integration Configuration

# Whether to verify SSL certs when communicating with FortiManager
CHECK_SSL = False

# FortiManager base URL(s)
URLS = ["https://fmg.example.com"]

# ADOM (Administrative Domain) in FortiManager where changes will be made
ADOM = "vectra_adom"

# Name of the policy package that contains the deny rule
POLICY_PKG = "vectra_policy"

# Name of the address group that the block rule uses
BLOCK_GROUP = "Blocked_Vectra_IPs"

# FortiManager username used for API authentication
FMG_USER = "apiadmin"

# Tag to apply to FortiManager for internal hosts being blocked 
INTERNAL_BLOCK_TAG = "Block_Host"

# Tag to apply to external detections being blocked
EXTERNAL_BLOCK_TAG = "Block_Detection"
