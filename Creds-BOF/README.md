# Creds-BOF

BOF tools that can be used to harvest passwords.

![](_img/01.png)



## askcreds

A BOF tool that can be used to collect passwords using CredUIPromptForWindowsCredentialsName.

```
askcreds [-p prompt] [-n note] [-t wait_time]
```



## autologon

Checks the registry for autologon information.

```
autologon
```



## credman

Checks the current user's Windows Credential Manager for saved web passwords and returns them.

```
credman
```



## hashdump

Gathers NTLM hashes from SAM and SYSTEM.

```
hashdump
```

The **Hashdump** item will be added to the **Access** menu in the Sessions Table and Graph.

![](_img/02.png)



## nanodump

A flexible tool that creates a minidump of the LSASS process. [More details](https://github.com/Adaptix-Framework/Extension-Kit/blob/main/Creds-BOF/nanodumnp/README.md)



## Credits
* C2-Tool-Collection - https://github.com/outflanknl/C2-Tool-Collection
* PrivCheck - https://github.com/ostrichgolf/PrivCheck
* nanodump - https://github.com/fortra/nanodump