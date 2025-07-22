# FortiManager Client
This client is used to isolate/unisolate hosts' network connectivity utilizing FortiManager.

# Requirements
- __Python packages__
  - requests
  - urllib3

# FortiManager Setup
If you’re new to FortiManager, follow these UI steps:

###  Step 1: Create an ADOM

- **Navigate** to: `System Settings ➞ ADOM`
- Click `Create New`
- Name it `vectra_adom` and enable workspace mode (optional)

### Step 2: Create an Address Group

- **Navigate**: `Policy & Objects ➞ Object Configurations ➞ Addresses`
- Click `Create New ➞ Address Group`
- Name: `Blocked_Vectra_IPs`
- Leave members empty — the script will populate it

![Address group setup](https://tse2.mm.bing.net/th/id/OIP.EcfIclg18rElWxs87HzPpAHaFW)

### Step 3: Create a Deny Rule

In `Policy & Objects ➞ Policy Packages`:
- Create/edit a package (e.g., `vectra_policy`)
- Add a new rule:
  - **Source**: `Blocked_Vectra_IPs`
  - **Destination**: `all`
  - **Action**: `deny`
  - Enable logging

### Step 4: Install Target Devices

- In the policy package, go to `Install`
- Select your FortiGate device(s) and vdom(s)
- Confirm and Save

# Configuration
This client uses the configuration file [fortimanager_config.py](fortimanager_config.py). 
  - `URLS`: FortiManager base URL(s)
  - `ADOM`: ADOM (Administrative Domain) in FortiManager where changes will be made
  - `POLICY_PKG`: Name of the policy package that contains the deny rule
  - `BLOCK_GROUP`: Name of the address group that the block rule uses
  - `FMG_USER`: FortiManager username used for API authentication
  - `INTERNAL_BLOCK_TAG`: Tag to apply within FortiManager for internal hosts being blocked 
  - `EXTERNAL_BLOCK_TAG`: Tag to apply within FortiManager for external hosts being blocked
  - `CHECK_SSL`: Whether to verify SSL certs when communicating with FortiManager
  
# Example Config
```
URLS = ["https://fmg.example.com"]
ADOM = "vectra_adom"
POLICY_PKG = "vectra_policy"
BLOCK_GROUP = "Blocked_Vectra_IPs"
FMG_USER = "apiadmin"
INTERNAL_BLOCK_TAG = "Block_Host"
EXTERNAL_BLOCK_TAG = "Block_Detection"
CHECK_SSL = False
```

# Authentication
- The VAR Framework utilizes the Python Keyring package to maintain secrets. 
- This client will request the required credentials on first run. 
- The client requires:
   - Username and Password

# Enablement
To utilize this client within the VAR Framework, add `"fortimanager"` to the list of `THIRD_PARTY_CLIENTS` in [config.py](../../config.py).

# Validation
- not validated

# Resources
- https://docs.fortinet.com/document/fortigate/7.2.0/secgw-for-mobile-networks-deployment/634366/fortimanager-json-api