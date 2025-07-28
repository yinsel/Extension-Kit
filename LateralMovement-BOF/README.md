# LateralMovement-BOF

BOFs kit for lateral movements

![](_img/01.png)

## PsExec

Attempt to spawn a session on a remote target via PsExec

```
jump psexec <SvcBinary> <Computer>
```



## token make

Creates an impersonated token from a given credentials

```
token make <username> <password> <domain> <type>
```

![](_img/02.png)

The **Make token** item will be added to the **Access** menu in the Sessions Table and Graph.

![](_img/03.png)

![](_img/04.png)



## token steal

Steal access token from a process

```
token steal <pid>
```

The **Steal token** item will be added to the context menu in the Process Browser.

![](_img/05.png)
