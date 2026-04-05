# WRITE_UP #

## EVENT HORIZON ##

### 1. Analysis ###
* **Given:** `Logs` and `TraceFormat` folder
* **Description:** Our CEO's computer was compromised in a phishing attack. The attackers took care to clear the PowerShell logs, so we don't know what they executed. Can you help us?
* **Hints:**   
    * No hints are given 

### 2. Investigation ###
#### EVENT HORIZON ####
Since we are given the `Logs` folder, we can use `chainsaw` - a powerful tool to detect suspicious event in the machine. Because the description mentioned `Powershell`, we only hunt threats from the powershell log:

```bash
~/tools/chainsaw/chainsaw hunt "/mnt/d/sv_it/htb/Easy/Easy/Event Horizon/Logs/Microsoft-Windows-PowerShell%4Operational.evtx" -s ~/sigma-rules/rules --mapping ~/tools/chainsaw/mappings/sigma-event-logs-all.yml

 ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗ █████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔════╝██╔══██╗██║    ██║
██║     ███████║███████║██║██╔██╗ ██║███████╗███████║██║ █╗ ██║
██║     ██╔══██║██╔══██║██║██║╚██╗██║╚════██║██╔══██║██║███╗██║
╚██████╗██║  ██║██║  ██║██║██║ ╚████║███████║██║  ██║╚███╔███╔╝
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
    By WithSecure Countercept (@FranticTyping, @AlexKornitzer)

[+] Loading detection rules from: /home/kittne/sigma-rules/rules
[!] Loaded 2887 detection rules (227 not loaded)
[+] Loading forensic artefacts from: /mnt/d/sv_it/htb/Easy/Easy/Event Horizon/Logs/Microsoft-Windows-PowerShell%4Operational.evtx (extensions: .evtx, .evt)
[+] Loaded 1 forensic artefacts (5.1 MiB)
[+] Current Artifact: /mnt/d/sv_it/htb/Easy/Easy/Event Horizon/Logs/Microsoft-Windows-PowerShell%4Operational.evtx
[+] Hunting [========================================] 1/1   [00:00:00]
[+] Group: Sigma
┌─────────────────────┬────────────────────────────────┬───────┬──────────────────────────────┬──────────┬───────────┬─────────────────┬──────────────────────────────────┐
│      timestamp      │           detections           │ count │    Event.System.Provider     │ Event ID │ Record ID │    Computer     │            Event Data            │
├─────────────────────┼────────────────────────────────┼───────┼──────────────────────────────┼──────────┼───────────┼─────────────────┼──────────────────────────────────┤
│ 2020-10-22 22:06:14 │ ‣ Malicious PowerShell         │ 1     │ Microsoft-Windows-PowerShell │ 4104     │ 31        │ WIN-PTFPHFCRDJ0 │ MessageNumber: 1                 │
│                     │ Commandlets - ScriptBlock      │       │                              │          │           │                 │ ScriptBlockText: |-              │
│                     │ ‣ Potential Suspicious         │       │                              │          │           │                 │  <#                              │
│                     │ PowerShell Keywords            │       │                              │          │           │                 │                                  │
│                     │                                │       │                              │          │           │                 │  PowerUp aims to be a clearing   │
│                     │                                │       │                              │          │           │                 │ house of common Windows privil   │
│                     │                                │       │                              │          │           │                 │ ege escalation                   │
│                     │                                │       │                              │          │           │                 │  vectors that rely on misconfi   │
│                     │                                │       │                              │          │           │                 │ gurations. See README.md for m   │
│                     │                                │       │                              │          │           │                 │ ore information.                 │
│                     │                                │       │                              │          │           │                 │                                  │
│                     │                                │       │                              │          │           │                 │  Author: @harmj0y                │
│                     │                                │       │                              │          │           │                 │  License: BSD 3-Clause           │
│                     │                                │       │                              │          │           │                 │  Required Dependencies: None     │
│                     │                                │       │                              │          │           │                 │  Optional Dependencies: None     │
│                     │                                │       │                              │          │           │                 │                                  │
│                     │                                │       │                              │          │           │                 │  #>                              │
│                     │                                │       │                              │          │           │                 │                                  │
│                     │                                │       │                              │          │           │                 │  #Requires -Version 2            │
│                     │                                │       │                              │          │           │                 │                                  │
│                     │                                │       │                              │          │           │                 │                                  │
│                     │                                │       │                              │          │           │                 │  #############################   │
│                     │                                │       │                              │          │           │                 │ ###########################      │
│                     │                                │       │                              │          │           │                 │                                  │
│                     │                                │       │                              │          │           │                 │                                  │
│                     │                                │       │                              │          │           │                 │  # HTB{8Lu3_734m_F0r3v3R}        │
│                     │                                │       │                              │          │           │                 │                                  │
│                     │                                │       │                              │          │           │                 │                                  │
│                     │                                │       │                              │          │           │                 │  # PSReflect code for Windows    │
│                     │                                │       │                              │          │           │                 │ API access                       │
│                     │                                │       │                              │          │           │                 │  # Author: @mattifestation       │
│                     │                                │       │                              │          │           │                 │  #  https://raw.githubusercont   │
│                     │                                │       │                              │          │           │                 │ ent.com/mattifestation/PSRefle   │
│                     │                                │       │                              │          │           │                 │ ct/master/PSReflect.psm1         │
│                     │                                │       │                              │          │           │                 │  #                               │
│                     │                                │       │                              │          │           │                 │  #############################   │
│                     │                                │       │                              │          │           │                 │ ###########################      │
│                     │                                │       │                              │          │           │                 │                                  │
│                     │                                │       │                              │          │           │                 │  function New-InMemoryModule {   │
│                     │                                │       │                              │          │           │                 │  <#                              │
│                     │                                │       │                              │          │           │                 │  .SYNOPSIS                       │
│                     │                                │       │                              │          │           │                 │                                  │
│                     │                                │       │                              │          │           │                 │  Creates an in-memory assembly   │
│                     │                                │       │                              │          │           │                 │  and module                      │
│                     │                                │       │                              │          │           │                 │                                  │
│                     │                                │       │                              │          │           │                 │  Author: Matthew Graeber (@mat   │
│                     │                                │       │                              │          │           │                 │ tifestation)                     │
│                     │                                │       │                              │          │           │                 │  License: BSD 3-Clause           │
│                     │                                │       │                              │          │           │                 │  Required Dependencies: None     │
│                     │                                │       │                              │          │           │                 │  Optional Dependencies: None     │
│                     │                                │       │                              │          │           │                 │                                  │
│                     │                                │       │                              │          │           │                 │  .DESCRIPTION                    │
│                     │                                │       │                              │          │           │                 │                                  │
│                     │                                │       │                              │          │           │                 │  When defining custom enums, s   │
│                     │                                │       │                              │          │           │                 │ tructs, and unmanaged function   │
│                     │                                │       │                              │          │           │                 │ s, it is                         │
│                     │                                │       │                              │          │           │                 │  necessary to associate to an    │
│                     │                                │       │                              │          │           │                 │ assembly module. This helper f   │
│                     │                                │       │                              │          │           │                 │ unction                          │
│                     │                                │       │                              │          │           │                 │  creates an in-memory module t   │
│                     │                                │       │                              │          │           │                 │ hat can be passed to the 'enum   │
│                     │                                │       │                              │          │           │                 │ ',                               │
│                     │                                │       │                              │          │           │                 │  'struct', and Add-Win32Type f   │
│                     │                                │       │                              │          │           │                 │ unctions.                        │
│                     │                                │       │                              │          │           │                 │                                  │
│                     │                                │       │                              │          │           │                 │  .PARAMETER ModuleName           │
│                     │                                │       │                              │          │           │                 │                                  │
│                     │                                │       │                              │          │           │                 │  Specifies the desired name fo   │
│                     │                                │       │                              │          │           │                 │ r the in-memory assembly and m   │
│                     │                                │       │                              │          │           │                 │ odule. If                        │
│                     │                                │       │                              │          │           │                 │  ModuleName is not provided, i   │
│                     │                                │       │                              │          │           │                 │ t will default to a GUID.        │
│                     │                                │       │                              │          │           │                 │                                  │
│                     │                                │       │                              │          │           │                 │  .EXAMPLE                        │
│                     │                                │       │                              │          │           │                 │                                  │
│                     │                                │       │                              │          │           │                 │  $Module = New-InMemoryModule    │
│                     │                                │       │                              │          │           │                 │ -ModuleName Win32                │
│                     │                                │       │                              │          │           │                 │  #>                              │
│                     │                                │       │                              │          │           │                 │                                  │
│                     │                                │       │                              │          │           │                 │    [Diagnostics.CodeAnalysis.S   │
│                     │                                │       │                              │          │           │                 │ uppressMessageAttribute('PSUse   │
│                     │                                │       │                              │          │           │                 │ ShouldProcessForStateChangingF   │
│                     │                                │       │                              │          │           │                 │ unctions', '')]                  │
│                     │                                │       │                              │          │           │                 │    [CmdletBinding()]             │
│                     │                                │       │                              │          │           │                 │    Param (                       │
│                     │                                │       │                              │          │           │                 │      [Parameter(Position = 0)]   │
│                     │                                │       │                              │          │           │                 │      [ValidateNotNullOrEmpty()   │
│                     │                                │       │                              │          │           │                 │ ]                                │
│                     │                                │       │                              │          │           │                 │      [String]                    │
│                     │                                │       │                              │          │           │                 │      $ModuleName = [Guid]::New   │
│                     │                                │       │                              │          │           │                 │ Guid().ToString()                │
│                     │                                │       │                              │          │           │                 │    )                             │
│                     │                                │       │                              │          │           │                 │                                  │
│                     │                                │       │                              │          │           │                 │    $AppDomain = [Reflection.As   │
│                     │                                │       │                              │          │           │                 │ sembly].Assembly.GetType('Syst   │
│                     │                                │       │                              │          │           │                 │ em.AppDomain').GetProperty('Cu   │
│                     │                                │       │                              │          │           │                 │ rrentDomain').GetValue($null,    │
│                     │                                │       │                              │          │           │                 │ @())                             │
│                     │                                │       │                              │          │           │                 │    $LoadedAssemblies = $AppDom   │
│                     │                                │       │                              │          │           │                 │ ain.GetAssemblies()              │
│                     │                                │       │                              │          │           │                 │                                  │
│                     │                                │       │                              │          │           │                 │    foreach ($Assembly in $Load   │
│                     │                                │       │                              │          │           │                 │ edAssemblies) {                  │
│                     │                                │       │                              │          │           │                 │      if ($Assembly.FullName -a   │
│                     │                                │       │                              │          │           │                 │ nd ($Assembly.FullName.Split('   │
│                     │                                │       │                              │          │           │                 │ ,')[0] -eq $ModuleName)) {       │
│                     │                                │       │                              │          │           │                 │        return $Assembly          │
│                     │                                │       │                              │          │           │                 │      }                           │
│                     │                                │       │                              │          │           │                 │    }                             │
│                     │                                │       │                              │          │           │                 │                                  │
│                     │                                │       │                              │          │           │                 │    $DynAssembly = New-Object R   │
│                     │                                │       │                              │          │           │                 │ eflection.AssemblyName($Module   │
│                     │                                │       │                              │          │           │                 │ Name)                            │
│                     │                                │       │                              │          │           │                 │    $Domain = $AppDomain          │
│                     │                                │       │                              │          │           │                 │    $AssemblyBuilder = $Domain.   │
│                     │                                │       │                              │          │           │                 │ DefineDynamicAssembly($DynAsse   │
│                     │                                │       │                              │          │           │                 │ mbly, 'Run')                     │
│                     │                                │       │                              │          │           │                 │    $ModuleBuilder = $AssemblyB   │
│                     │                                │       │                              │          │           │                 │ uilder.DefineDynamicModule($Mo   │
│                     │                                │       │                              │          │           │                 │ duleName, $False)                │
│                     │                                │       │                              │          │           │                 │                                  │
│                     │                                │       │                              │          │           │                 │    return $ModuleBuilder         │
│                     │                                │       │                              │          │           │                 │  }                               │
│                     │                                │       │                              │          │           │                 │                                  │
│                     │                                │       │                              │          │           │                 │                                  │
│                     │                                │       │                              │          │           │                 │  # A helper function used to r   │
│                     │                                │       │                              │          │           │                 │ educe typing while defining fu   │
│                     │                                │       │                              │          │           │                 │ nction                           │
│                     │                                │       │                              │          │           │                 │  # prototypes for Add-Win32Typ   │
│                     │                                │       │                              │          │           │                 │ e.                               │
│                     │                                │       │                              │          │           │                 │  function func {                 │
│                     │                                │       │                              │          │           │                 │    Param (                       │
│                     │                                │       │                              │          │           │                 │      [Parameter(Position = 0,    │
│                     │                                │       │                              │          │           │                 │ Mandatory = $True)]              │
│                     │                                │       │                              │          │           │                 │      [String]                    │
│                     │                                │       │                              │          │           │                 │      $DllName,                   │
│                     │                                │       │                              │          │           │                 │                                  │
│                     │                                │       │                              │          │           │                 │      [Parameter(Position = 1,    │
│                     │                                │       │                              │          │           │                 │ Mandatory = $True)]              │
│                     │                                │       │                              │          │           │                 │      [string]                    │
│                     │                                │       │                              │          │           │                 │      $FunctionName,              │
│                     │                                │       │                              │          │           │                 │                                  │
│                     │                                │       │                              │          │           │                 │      [Parameter(Position = 2,    │
│                     │                                │       │                              │          │           │                 │ Mandatory = $True)]              │
│                     │                                │       │                              │          │           │                 │      [Type]                      │
│                     │                                │       │                              │          │           │                 │      $ReturnType,                │
│                     │                                │       │                              │          │           │                 │                                  │
│                     │                                │       │                              │          │           │                 │      [Parameter(Position = 3)]   │
│                     │                                │       │                              │          │           │                 │      [Type[]]                    │
│                     │                                │       │                              │          │           │                 │      $ParameterTypes,            │
│                     │                                │       │                              │          │           │                 │                                  │
│                     │                                │       │                              │          │           │                 │      [Parameter(Position = 4)]   │
│                     │                                │       │                              │          │           │                 │      [Runtime.InteropServices.   │
│                     │                                │       │                              │          │           │                 │ CallingConvention]               │
│                     │                                │       │                              │          │           │                 │      $NativeCallingConvention,   │
│                     │                                │       │                              │          │           │                 │                                  │
│                     │                                │       │                              │          │           │                 │      [Parameter(Position = 5)]   │
│                     │                                │       │                              │          │           │                 │      [Runtime.InteropServices.   │
│                     │                                │       │                              │          │           │                 │ CharSet]                         │
│                     │                                │       │                              │          │           │                 │      $Charset,                   │
│                     │                                │       │                              │          │           │                 │                                  │
│                     │                                │       │                              │          │           │                 │      [String]                    │
│                     │                                │       │                              │          │           │                 │      $EntryPoint,                │
│                     │                                │       │                              │          │           │                 │                                  │
│                     │                                │       │                              │          │           │                 │      [Switch]                    │
│                     │                                │       │                              │          │           │                 │      $SetLastError               │
│                     │                                │       │                              │          │           │                 │    )                             │
# ....
```

We get the flag just like that.

## 3. Solution ##
1. **Result:** The flag is `HTB{8Lu3_734m_F0r3v3R}`


