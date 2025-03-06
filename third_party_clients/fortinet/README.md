# Fortinet Client

# Introduction
This third party client implements automated blocking by integrating with FortiOS. The script can either connect to a centralized Fortinet management appliance, or to every individual firewall of the environment (which will of couse be less efficient).

One of those address groups is meant for containing internal IP address of hosts, while the other is for containing external IPs found on detections with an external component. 

The internal address group will only be populated if host-based blocking is enabled, while the external address group will only be populated if detection-based blocking is enabled. 

# Requirements
- __Python packages__
  - requests
  - urllib3

- __Fortinet Address Groups__
  - INTERNAL_ADDRESS_GROUP
  - EXTERNAL_ADDRESS_GROUP

- __Obtaining Fortinet API Token__
  - Step 1: Determine your Source Address: 
    - The source address is needed to ensure the __API token__ can only be used from trusted hosts. 
    - As the API calls will come from the middleware server, you need to determine its IP address, running for instance ```bash ip addr```. 
  - Step 2: Create an Administrator profile: 
    - You need to create a profile that only has __Read/Write__ access to the firewall address permission group. 
    - On the FortiGate GUI, select `System > Admin Profiles > Create New`. Populate the fields according to your environment.
  - Step 3: Create the REST API Admin: 
    - On the FortiGate GUI, select `System > Administrators > Create New > REST API Admin`.
    - The Trusted Host must be specified to ensure that your local host can reach the FortiGate. 
      - __For example__, to restrict requests as coming from only 10.20.100.99, enter 10.20.100.99/32. 
      - The Trusted Host is created from the Source Address obtained in Step 1: Determine your Source Address.
    - In Administrator Profile field, select profile from Step2. __Note__: 
      - If you want to configure VDOM or resources related to administrator user permissions, you need to set the field with the System predefined Administrator Profile super_admin by CLI.
    - Click OK and an API token will be generated.
    - Make note of the __API token__ as it is only shown once and cannot be retrieved. It will be needed for the rest of the tutorial.
    - Click `Close` to complete creation of the REST API Admin.

# Configuration
This client uses the configuration file [fortinet_config.py](./fortinet_config.py).
  - `INTERNAL_ADDRESS_GROUP`: Address group to which to add internal IPs for blocking (E-W traffic). __NOTE__: Used for host-based blocking only.
  - `EXTERNAL_ADDRESS_GROUP`: Address group to which to add external IPs for blocking (N-S traffic). __NOTE__: Used for detection-based blocking only.
  - `IP`: List of IPs associated with a centralized Fortinet management appliance, or to every individual firewall of the environment
  - `PORT`: The Rest API port for each of the configured IPs
  - `VDOM`: Fortinet Virtual Domain
  - `CHECK_SSL`: set to True to validate server SSL certificates (default: False)

# Example Config
```
INTERNAL_ADDRESS_GROUP = "Internal-Block"
EXTERNAL_ADDRESS_GROUP = "External-Block"
IP = ["IP1", "IP2"]
PORT = [443, 443]
VDOM = ["root", "root"]
CHECK_SSL = [False, False]
```

# Authentication
- The VAR Framework utilizes the Python Keyring package to maintain secrets. 
- This client will request the required credentials on first run. 
- The client requires:
   - The __API Token__ discussed above

# Enablement
To utilize this client within the VAR Framework, add `"fortinet"` to the list of `THIRD_PARTY_CLIENTS` in [config.py](../../config.py).

# Validation


# Resources
- https://docs.fortinet.com/document/fortigate/7.0.0/secgw-for-mobile-networks-deployment/238243/fortios-rest-api