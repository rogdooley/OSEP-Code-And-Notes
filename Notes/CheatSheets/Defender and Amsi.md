
### Disable Defender

- Need to be an admin
```cmd
Set-MpPreference -DisableAntiSpywareUpdates $true
```

```cmd
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpywareUpdates /t REG_DWORD /d 1 /f
```

```powershell
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpywareUpdates -PropertyType DWORD -Value 1 -Force
```

