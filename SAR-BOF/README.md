# SAR-BOF

This extension enhances situational awareness by providing a set of remote Beacon Object File (BOF) commands. These commands allow the operator to gather detailed information about the target.

![](_img/01.png)


## quser

Query user sessions on a remote machine, providing session information.

```
quser [host]
```


## taskhound

Collect scheduled tasks from remote systems, with options to filter for domain accounts with stored credentials and save XML task definitions for offline analysis.

```
taskhound <target> [username] [password] [-save <directory>] [-unsaved-creds]
```

**Parameters:**
- `target` (required): Remote system to collect from (IP or hostname)
- `username` (optional): Username for authentication
- `password` (optional): Password for authentication
- `-save <directory>` (optional): Directory to save XML task files locally
- `-unsaved-creds` (optional): Show tasks without stored credentials (interactive token only)

**Examples:**
```
# Basic usage with current user context
taskhound 192.168.1.100

# Using explicit credentials
taskhound DC01 -u domain\admin -p P@ssw0rd

# Save XML files locally for offline analysis
taskhound 192.168.1.100 -save C:\TaskOutput

# Show all domain tasks including those without stored credentials
taskhound 192.168.1.100 -unsaved-creds

# Combined: save files and show all tasks
taskhound DC01 -u domain\admin -p P@ssw0rd -save C:\Output -unsaved-creds
```

## Credits
* Quser-BOF - https://github.com/netero1010/Quser-BOF
* TaskHound - https://github.com/1r0BIT/TaskHound