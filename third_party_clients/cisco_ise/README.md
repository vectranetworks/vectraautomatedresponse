# Cisco ISE Client
This client is used to isolate/unisolate hosts' network connectivity utilizing the Cisco ISE API.  

# Requirements
- __Python packages__
  - requests
  - xmltodict

# Configuration
This client uses the configuration file [ise_config.py](ise_config.py). 
  - `ISE_APPLIANCE_IP`: IP/Hostname of the Cisco ISE Appliance
  - `CHECK_SSL`: set to True to validate server SSL certificates (default: False)
  - `PORTBOUNCE_POLICY`: name of the policy to bounce the port of the host
  - `QUARANTAINE_POLICY`: name of the policy to quarantine the port of the host
  - `ENHANCED`: set to True if `Use CSRF Check for Enhanced Security` is enabled in Cisco ISE GUI (default: False)

# Example Config
```
ISE_APPLIANCE_IP = ""
CHECK_SSL = False
PORTBOUNCE_POLICY = "PortBounce"
QUARANTAINE_POLICY = "Quarantine"
ENHANCED = False
```

# Authentication
- The VAR Framework utilizes the Python Keyring package to maintain secrets. 
- This client will request the required credentials on first run. 
- The client requires Cisco ISE username and password with the following permissions:
  - __NOTE:__ The account associated with the credentials must be authorized within Cisco ISE

# Cisco ISE: Enable API Service
- In the Cisco ISE GUI, click the Menu icon and choose Administration > System > Settings > API Settings > API Service Settings.
- In the API Service Settings for Primary Administration Node area, click the ERS (Read/Write) toggle button to enable ERS on the Primary Administration node (PAN)
- In the API Service Settings for All Other Nodes area, click the ERS (Read) toggle button to enable the ERS on all other nodes
- In the CSRF Check area, click the radio button for one of the following options:
  - Use CSRF Check for Enhanced Security
  - Disable CSRF for ERS Request

# Enablement
To utilize this client within the VAR Framework, add `"cisco_ise"` to the list of `THIRD_PARTY_CLIENTS` in [config.py](../../config.py).

# Validation
- Jan 24, 2025
  - API v1

# Resources
- https://developer.cisco.com/docs/identity-services-engine/latest/