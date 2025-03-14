# Sophos Firewall Client
This client is used to isolate/unisolate hosts' network connectivity utilizing the Sophos Firewall API.  

# Requirements
- __Python packages__
  - requests


# Configuration
This client uses the configuration file [sophos.py](sophos_config.py). 
  - `HOSTNAME`: hostname or IP of the Sophos Firewall.
  - `PORT`: port to connect to Sophos Firewall (default: 4444)
  - `IS_ENCRYPTED`: whether or not the login password is encrypted or plain text
  - `BLOCK_LIST_NAME`: name of the Sophos list to be updated with hostname or IP for isolation/unisolation

# Example Config
```
HOSTNAME = ""
PORT = 4444
IS_ENCRYPTED = True
BLOCK_LIST_NAME = "Vectra - Sophos Integration"
```

# Authentication
- The VAR Framework utilizes the Python Keyring package to maintain secrets. 
- This client will request the required credentials on first run. 
- The client requires Sophos Username and Password

# Enablement
To utilize this client within the VAR Framework, add `"sophos"` to the list of `THIRD_PARTY_CLIENTS` in [config.py](../../config.py).

# Validation
- __Untested__

# Resources
- https://docs.sophos.com/nsg/sophos-firewall/19.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/BackupAndFirmware/API/index.html
