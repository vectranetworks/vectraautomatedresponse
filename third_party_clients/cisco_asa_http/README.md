 # Cisco ASA HTTP Client
This client is used to isolate/unisolate hosts' network connectivity utilizing the Cisco ASA HTTP API.  

# Requirements
- __Python packages__
  - requests

# Configuration
This client uses the configuration file [asa_http_config.py](asa_http_config.py). 
  - `URL`: URL of the Cisco ASA HTTP Interface
  - `BLOCK_GROUP`: Name of group configured in Cisco ASA used for isolation
  - `USER_AGENT`: A unique user agent configured for use with the ASA HTTP Interface

# Example Config
```
URL=""
BLOCK_GROUP=""
USER_AGENT=""
```

# Cisco ASA HTTP Configurations
- This integration relies upon the Cisco Secure Firewall ASA HTTP Interface.
- The following configurations are required to be made on the firewall
  - Set an approved unique user-agent string
    ```
    http server basic-auth-client <USER_AGENT>
    ```
    ```
    example:
    http server basic-auth-client Vectra_Isolation
    ```
  - If not using a AAA server for user authentication
    ```
    aaa authentication http console LOCAL
    ```
  - Enable the HTTP server and allow access
    ```
    http server enable
    http <subnet> <netmask> <source_interface>
    ```
    ```
    example:
    http server enable
    http 10.10.0.1 255.255.0.0 interface1
    ```
  - Create the isolation group
    ```
    object-group network <BLOCK_GROUP>
    ```
    ```
    example:
    object-group network Vectra_Block_Group
    ```
  - Create the isolation ACL
    ```
    access-list BLOCK_GROUP extended deny ip object-group <BLOCK_GROUP> any
    access-list BLOCK_GROUP extended deny ip any object-group <BLOCK_GROUP>
    access-list BLOCK_GROUP extended permit ip any any
    ```
    ```
    example:
    access-list BLOCK_GROUP extended deny ip object-group Vectra_Block_Group any
    access-list BLOCK_GROUP extended deny ip any object-group Vectra_Block_Group
    access-list BLOCK_GROUP extended permit ip any any
    ```
  - Apply the isolation ACL to each interface on the ASA firewall
    ```
    access-group <BLOCK_GROUP> in interface <interface_name>
    ```
    ```
    example:
    access-group Vectra_Block_Group in interface interface1
    ```

# Authentication
- The VAR Framework utilizes the Python Keyring package to maintain secrets. 
- This client will request the required credentials on first run. 
- The client requires Cisco ASA username and password

# Enablement
To utilize this client within the VAR Framework, add `"cisco_asa_http"` to the list of `THIRD_PARTY_CLIENTS` in [config.py](../../config.py).

# Validation
- Untested

# Resources
- https://www.cisco.com/c/en/us/td/docs/security/asa/misc/http-interface/asa-http-interface.html#Cisco_Concept.dita_9364044a-3b0e-4963-8a41-06ddade07255
