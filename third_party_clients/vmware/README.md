# VMWare Client
This client is used to isolate/unisolate VMs by disabling/enabling corresponding virtual network interfaces.  

# Requirements
- __Python packages__
  - requests
  - pyVmomi
- __Vectra Integrations__
  - vCenter External Connector 
    - In the UI -> Settings -> External Connectors -> vCenter
    - ___Note:___ This client utilizes the vCenter UUID Host ID artifact as the key to isolate/unisolate VMs.


# Configuration
This client uses the configuration file [vmware_config.py](vmware_config.py). 
  - `HOSTS`: a list of all ESXi or vSphere hosts that may contain the VMs to isolate/unisolate.

# Example Config
`HOSTS=["esxi1.example","esxi2.example","vsphere.example"]`

# Authentication
- The VAR Framework utilizes the Python Keyring package to maintain secrets. 
- This client will request the required credentials on first run. 
- The client requires credentials for each ESXi or vSphere host configured with permissions to query for VM information AND to alter the state of the respective virtual network interfaces. 

# Enablement
To utilize this client within the VAR Framework, add `"vmware"` to the list of `THIRD_PARTY_CLIENTS` in [config.py](../../config.py).

# Validation
- Jan 23, 2025
  - ESXi v6.7
  - vSphere v6.7

# Resources
- https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/
