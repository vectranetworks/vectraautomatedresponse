# Windows Shutdown Client
This client is used to shutdown a Windows host  

# Requirements
- Must be ran from a Windows machine
- This client uses the Windows default `shutdown.exe` to remotely shutdown a host


# Configuration
- No configuration required.


# Authentication
- This client requires that the associated account has administrative privileges


# Enablement
To utilize this client within the VAR Framework, add `"windows_shutdown"` to the list of `THIRD_PARTY_CLIENTS` in [config.py](../../config.py).


# Validation


# Resources
- https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/shutdown
