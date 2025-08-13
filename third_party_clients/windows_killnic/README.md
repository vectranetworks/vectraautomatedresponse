# Windows Shutdown Client
This client is used to disable all NICs via WinRM on a remote Windows Host.

# Requirements
- Must be ran from a Windows machine.
- This client uses a Powershell Scriptlet and WinRM to disable all NICs on a remote windows Host. So `pywinrm` is required.

# Configuration
- You may configure the `SERVICE_NAME` under which your credentials are stored in the keyring in [windows_killnic_config.py](./windows_killnic_config.py).

# Authentication
- This client requires that the associated account has administrative privileges.

# Enablement
To utilize this client within the VAR Framework, add `"windows_killnic"` to the list of `THIRD_PARTY_CLIENTS` in [config.py](../../config.py).

# Validation
Unvalidated, validation following.

# Resources
- https://learn.microsoft.com/de-de/windows/win32/cimwin32prov/win32-networkadapter
- https://www.telonic.de
