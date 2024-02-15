VERIFY_SSL = False
# Palo Alto tag used to associate with internal dynamic group
INTERNAL_BLOCK_TAG = "Block_Host"
# Palo Alto tag used to associate with external dynamic group
EXTERNAL_BLOCK_TAG = "Block_Detection"
# Connection information
URL = "https://<IP or hostname>"
API_KEY = "<api-key>"

# STOP
PAN_APPLIANCE_LIST = [{"url": URL, "api_key": API_KEY}]
