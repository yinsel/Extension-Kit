# SAR-BOF

This extension enhances situational awareness by providing a set of remote Beacon Object File (BOF) commands. These commands allow the operator to gather detailed information about the target.

![](_img/01.png)


## ldapsearch

Execute LDAP searches (NOTE: specify *,ntsecuritydescriptor as attribute parameter if you want all attributes + base64 encoded ACL of the objects, this can then be resolved using BOFHound. Could possibly break pagination, although everything seemed fine during testing.)

```
ldapsearch <query> <-attributes attributes> <-count count> <-scope scope> <-hostname hostname> <-dn dn> <-ldaps ldaps>
```

## quser

Query user sessions on a remote machine, providing session information.

```
quser [host]
```



## Credits
* CS-Situational-Awareness-BOF - https://github.com/trustedsec/CS-Situational-Awareness-BOF
* Quser-BOF - https://github.com/netero1010/Quser-BOF