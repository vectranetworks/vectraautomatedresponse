# External Call
This client is used to isolate/unisolate hosts' network connectivity, account access, and/or destination IPs utilizing the commands provided. The commands provided need to be tested and validated on their own with the appropriate permission or configurations in place to work. This client is only a way to automated these types of commands.

# Requirements
- __Python packages__
  - requests
  - urllib3

# Configuration
This client uses the configuration file [external_call_config.py](external_call_config.py). 
  - `HOST_BLOCK_CMD`: Provided command to isolate hosts
  - `HOST_UNBLOCK_CMD`: Provided command to unisolate hosts
  - `ACCOUNT_BLOCK_CMD`: Provided command to isolate accounts
  - `ACCOUNT_UNBLOCK_CMD`: Provided command to unisolate accounts
  - `DETECTION_BLOCK_CMD`: Provided command to block destination IPs based on detection
  - `DETECTION_UNBLOCK_CMD`: Provided command to unblock destination IPs
  
# Example Config
```
HOST_BLOCK_CMD = []
HOST_UNBLOCK_CMD = []
ACCOUNT_BLOCK_CMD = []
ACCOUNT_UNBLOCK_CMD = []
DETECTION_BLOCK_CMD = []
DETECTION_UNBLOCK_CMD = []
```

# Authentication
- The VAR Framework utilizes the Python Keyring package to maintain secrets. 
- This client assumes permissions to run the provided commands are in place and does not request or store any secrets. 


# Enablement
To utilize this client within the VAR Framework, add `"external_call"` to the list of `THIRD_PARTY_CLIENTS` in [config.py](../../config.py).
