
Here's a table that outlines various attack techniques along with the corresponding permissions or privileges that are generally required to carry them out. This table includes process injection, dumping LSASS, AMSI bypass, MSSQL attacks, and others.

| **Attack Technique**              | **Required Privileges/Permissions**                                           | **Description**                                                                                                                                     |
|-----------------------------------|-------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------|
| **Process Injection**             | `SeDebugPrivilege`                                                            | Allows injection of code into another process. `SeDebugPrivilege` enables the manipulation of processes owned by other users.                        |
| **Dumping LSASS**                 | `SeDebugPrivilege`                                                            | Enables reading memory of the LSASS process to extract credentials. Requires `SeDebugPrivilege` to access the memory of sensitive system processes.  |
| **AMSI Bypass**                   | `SeDebugPrivilege` (for advanced techniques)                                  | Bypassing AMSI typically involves modifying process memory or patching AMSI-related code, often requiring `SeDebugPrivilege` for such modifications. |
| **MSSQL Code Execution**          | `sysadmin` role or `CONTROL SERVER` permission                                | To execute code or commands on a SQL Server, the attacker typically needs high privileges like `sysadmin` or `CONTROL SERVER`.                       |
| **Privilege Escalation (MSSQL)**  | `SeImpersonatePrivilege` or `sysadmin` role                                   | `SeImpersonatePrivilege` allows an attacker to impersonate other users, which can be exploited to escalate privileges within MSSQL.                  |
| **Token Impersonation**           | `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`                     | Allows the attacker to impersonate another user or process, which can be leveraged for privilege escalation.                                         |
| **NTLM Relay Attack**             | Network access, `SeImpersonatePrivilege`                                      | Often used with `SeImpersonatePrivilege` to relay NTLM authentication and impersonate users on the network.                                          |
| **CreateRemoteThread Injection**  | `SeDebugPrivilege`                                                            | Allows the creation of a remote thread in another process for code execution, often used in process injection attacks.                               |
| **DLL Injection**                 | `SeDebugPrivilege`                                                            | Requires `SeDebugPrivilege` to inject a DLL into another process.                                                                                     |
| **Service Creation (Persistence)**| `SeServiceLogonRight`, Administrative privileges                              | Creating a new service for persistence typically requires administrative privileges or the right to log on as a service.                             |
| **Creating Scheduled Tasks**      | Administrative privileges                                                     | Requires administrative privileges to create scheduled tasks for persistence.                                                                        |
| **SAM Database Dumping**          | `SeBackupPrivilege`, `SeDebugPrivilege`, Administrative privileges            | Extracting the SAM database requires high-level privileges to access and dump the contents.                                                          |
| **Pass-the-Hash**                 | `SeTcbPrivilege`, Administrative privileges                                   | Using a hash to authenticate requires privileges to extract the hash (e.g., from LSASS) and to authenticate using it.                                |
| **Registry Persistence**          | Administrative privileges, `SeBackupPrivilege`, `SeRestorePrivilege`          | Modifying registry keys for persistence typically requires administrative privileges.                                                                |
| **WMI Execution**                 | Administrative privileges, `SeRemoteShutdownPrivilege` (for remote execution) | Executing commands via WMI typically requires administrative privileges, especially when doing so remotely.                                          |
| **APC Injection**                 | `SeDebugPrivilege`                                                            | APC (Asynchronous Procedure Call) injection requires privileges to manipulate another process’s memory and queue APCs.                               |
| **Kernel Driver Loading**         | `SeLoadDriverPrivilege`                                                       | Loading unsigned drivers or performing kernel-level attacks requires `SeLoadDriverPrivilege`.                                                        |
| **UAC Bypass**                    | No special privileges required (depends on the technique)                     | Various UAC bypass techniques exist, some of which do not require special privileges beyond those of a standard user.                                |
| **Remote Desktop Shadowing**      | `SeRemoteInteractiveLogonRight`, Administrative privileges                    | Shadowing an existing RDP session typically requires administrative privileges.                                                                      |
| **Shellcode Injection**           | `SeDebugPrivilege`, Administrative privileges                                 | Injecting shellcode into a process generally requires `SeDebugPrivilege` or administrative rights to manipulate the process’s memory.                |
| **Token Duplication (Pass-the-Token)** | `SeAssignPrimaryTokenPrivilege`, `SeImpersonatePrivilege`                 | Allows the attacker to duplicate or manipulate access tokens for privilege escalation.                                                               |
| **Fileless Malware (Registry-based)** | `SeBackupPrivilege`, `SeRestorePrivilege`, Administrative privileges      | Storing and executing malware directly from the registry typically requires high-level privileges for access and execution.                           |
| **Remote Command Execution via MSSQL xp_cmdshell** | `sysadmin` role or equivalent permission | xp_cmdshell allows for command execution on SQL Server, but requires high-level privileges like `sysadmin` to enable and use.                        |
| **Bypassing WDAC (Windows Defender Application Control)** | Administrative privileges | Requires administrative privileges to modify or bypass application control policies set by WDAC.                                                     |

### Notes:

- **SeDebugPrivilege:** One of the most critical privileges for many process injection techniques, including dumping LSASS and injecting code into other processes.
- **SeImpersonatePrivilege:** Essential for privilege escalation techniques, particularly those involving impersonation or token manipulation.
- **Administrative Privileges:** Many of these attacks require administrative privileges to perform actions like creating services, scheduled tasks, or modifying registry keys.
- **sysadmin Role (MSSQL):** A highly privileged role in MSSQL that allows executing arbitrary commands and code within the SQL Server environment.

This table serves as a guide to understanding the privileges and permissions required for various attacks. Security professionals can use this knowledge to ensure that appropriate privilege management and least privilege principles are enforced in their environments.

Certainly! Below is a table that lists various Windows privileges that can be abused, along with the types of attacks that can be performed when an attacker has access to those privileges:

| **Windows Privilege**                  | **Possible Attacks/Abuses**                                                                                                                                                              |
|----------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **SeDebugPrivilege**                   | - **Process Injection:** Injecting malicious code into other processes. <br> - **Dumping LSASS:** Extracting credentials from the LSASS process. <br> - **APC Injection:** Queueing APCs in other processes. <br> - **DLL Injection:** Injecting DLLs into other processes. <br> - **Shellcode Injection:** Executing shellcode in the context of another process. <br> - **Creating Remote Threads:** Creating threads in remote processes to execute malicious code. <br> - **SAM Database Dumping:** Accessing and dumping the Security Accounts Manager (SAM) database. |
| **SeImpersonatePrivilege**             | - **Token Impersonation:** Impersonating other users, often used for privilege escalation. <br> - **NTLM Relay Attack:** Relaying NTLM authentication to impersonate users on the network. <br> - **Privilege Escalation:** Leveraging impersonation to escalate privileges within the system. <br> - **Token Duplication (Pass-the-Token):** Duplicating and using tokens to escalate privileges. |
| **SeAssignPrimaryTokenPrivilege**      | - **Token Impersonation:** Assigning a primary token to a process for impersonation. <br> - **Privilege Escalation:** Used in combination with SeImpersonatePrivilege to escalate privileges. |
| **SeTcbPrivilege (Act as Part of OS)** | - **Pass-the-Hash/Pass-the-Ticket:** Authenticating with hashed credentials. <br> - **Authentication Manipulation:** Creating or manipulating tokens for other users or services. |
| **SeBackupPrivilege**                  | - **SAM Database Dumping:** Accessing and dumping the SAM database. <br> - **Registry Persistence:** Modifying the registry for persistence. <br> - **File Manipulation:** Reading and backing up sensitive files or data without normal access controls. |
| **SeRestorePrivilege**                 | - **SAM Database Manipulation:** Restoring or modifying the SAM database. <br> - **Registry Manipulation:** Modifying the registry by restoring registry hives. <br> - **File Manipulation:** Restoring files or overriding access controls. |
| **SeLoadDriverPrivilege**              | - **Kernel Driver Loading:** Loading malicious or unsigned drivers to execute code at the kernel level. <br> - **Rootkit Installation:** Installing rootkits to maintain persistence and control over the system. |
| **SeServiceLogonRight**                | - **Service Creation (Persistence):** Creating malicious services to gain persistence on the system. <br> - **Service Exploitation:** Leveraging service misconfigurations or weaknesses to escalate privileges. |
| **SeRemoteShutdownPrivilege**          | - **Remote Shutdown:** Shutting down or restarting a remote system. <br> - **WMI Execution:** Remotely executing commands or scripts using WMI. |
| **SeIncreaseQuotaPrivilege**           | - **Process Injection:** Increasing the working set size of a process to facilitate code injection. <br> - **Memory Manipulation:** Increasing memory quotas to manipulate or allocate large amounts of memory for malicious purposes. |
| **SeTakeOwnershipPrivilege**           | - **File/Folder Takeover:** Taking ownership of files or folders to bypass access controls. <br> - **Privilege Escalation:** Escalating privileges by taking ownership of system-critical files or registry keys. |
| **SeManageVolumePrivilege**            | - **Volume Manipulation:** Directly managing volumes, including mounting, unmounting, or formatting disks. <br> - **Data Destruction:** Deleting or modifying volume information to destroy data. |
| **SeShutdownPrivilege**                | - **Forced System Shutdown:** Shutting down or rebooting the system, which could be used in denial-of-service attacks. |
| **SeAuditPrivilege**                   | - **Audit Manipulation:** Bypassing or manipulating audit logs to cover tracks. <br> - **Security Log Tampering:** Deleting or modifying security logs to remove evidence of malicious activities. |
| **SeIncreaseBasePriorityPrivilege**    | - **Priority Manipulation:** Increasing the base priority of a process to ensure it runs with higher priority, potentially leading to denial-of-service or resource exhaustion attacks. |
| **SeSystemEnvironmentPrivilege**       | - **Firmware Manipulation:** Modifying system firmware environment variables, which could be used to create persistent malware. |
| **SeTimeZonePrivilege**                | - **Time Manipulation:** Changing the system time or timezone, potentially to disrupt time-based security mechanisms (e.g., Kerberos tickets). |
| **SeCreatePagefilePrivilege**          | - **Pagefile Manipulation:** Creating or modifying pagefiles, which could be used to store malicious data or execute attacks involving virtual memory. |
| **SeProfileSingleProcessPrivilege**    | - **Process Profiling:** Profiling or monitoring the performance of a single process, which could be used to gather sensitive information from high-value processes. |
| **SeUndockPrivilege**                  | - **Undock System:** Undocking the system, which might be leveraged to cause disruption on systems that support docking/undocking. |
| **SeSecurityPrivilege**                | - **Security Descriptor Manipulation:** Modifying security descriptors for objects, potentially leading to unauthorized access. <br> - **Privilege Escalation:** Changing security settings to grant higher privileges. |
| **SeRemoteInteractiveLogonRight**      | - **Remote Desktop Hijacking:** Hijacking or shadowing a remote desktop session, potentially leading to unauthorized access or data exfiltration. |
| **SeSystemProfilePrivilege**           | - **System Profiling:** Profiling system performance, which could be used to gather information about running processes, memory usage, or system performance. |

### Summary:
- **Critical Privileges:** `SeDebugPrivilege`, `SeImpersonatePrivilege`, and `SeTcbPrivilege` are among the most powerful and frequently abused privileges.
- **Privilege Escalation:** Many of these privileges can be leveraged for privilege escalation, either by directly manipulating system resources or by impersonating higher-privilege users.
- **Persistence:** Certain privileges, like `SeServiceLogonRight` and `SeLoadDriverPrivilege`, are often used to achieve persistence on a compromised system.

This table is designed to help security professionals understand the relationship between Windows privileges and the types of attacks that can be performed when those privileges are abused. Proper management and restriction of these privileges are essential to maintaining system security.

## User Privileges

In Windows, privileges determine what actions a user can perform on the system, such as shutting down the system, loading device drivers, or taking ownership of files or objects. Privileges are different from permissions, as privileges are system-wide, while permissions apply to specific objects like files or registry keys.

To add privileges to a user account, you typically need administrative access. Here are several methods to add privileges to a user account in Windows:

### 1. **Using Local Security Policy (GUI Method)**
The Local Security Policy tool allows administrators to manage privileges and security settings for user accounts.

#### Steps:
1. **Open Local Security Policy**:
   - Press `Win + R`, type `secpol.msc`, and press `Enter`.
   
2. **Navigate to Local Policies**:
   - In the left pane, expand `Local Policies` and then click on `User Rights Assignment`.
   
3. **Find the Privilege to Modify**:
   - In the right pane, find the privilege you want to assign, such as "Debug programs" (which is associated with `SeDebugPrivilege`).

4. **Assign the Privilege**:
   - Double-click the privilege. In the dialog box that opens, click `Add User or Group`, then add the user or group to which you want to assign the privilege.

5. **Apply and Close**:
   - Click `OK` to apply the changes. The user will need to log out and back in, or restart the system, for the changes to take effect.

### 2. **Using `ntrights.exe` (Command Line Tool)**
The `ntrights.exe` tool is part of the Windows Server 2003 Resource Kit but can also be used on newer versions of Windows. This tool allows you to assign or revoke user rights from the command line.

#### Example:
1. **Download and Install Windows Server 2003 Resource Kit** (if not already installed).

2. **Assign Privileges**:
   - Open an elevated command prompt (Run as Administrator).
   - To add a privilege, use the following syntax:
     ```cmd
     ntrights +r SeDebugPrivilege -u <username>
     ```
   - Replace `<username>` with the actual username. For example, to add the `SeDebugPrivilege` to the user `john`, you would run:
     ```cmd
     ntrights +r SeDebugPrivilege -u john
     ```

3. **Verify the Change**:
   - You can verify that the privilege has been added by checking the user's privileges using the Local Security Policy or using other tools like PowerShell.

### 3. **Using PowerShell**
PowerShell allows for managing user privileges via the `secedit` or `ntrights` commands.

#### Example using `secedit`:
1. **Export the Security Policy**:
   - Open an elevated PowerShell or Command Prompt.
   - Run the following command to export the current security policy:
     ```cmd
     secedit /export /cfg C:\path\to\output.inf
     ```

2. **Edit the `.inf` File**:
   - Open the exported `.inf` file in a text editor.
   - Under `[Privilege Rights]`, add the privilege you want to assign, followed by the user or group. For example:
     ```
     SeDebugPrivilege = *S-1-5-32-544,*S-1-5-21-XXXXXX-YYYYYYYYY-ZZZZZZZZ-1001
     ```
     - `*S-1-5-32-544` is the SID for the Administrators group, and `*S-1-5-21-XXXXXX-YYYYYYYYY-ZZZZZZZZ-1001` is the SID for a specific user.
   
3. **Apply the Modified Security Policy**:
   - Re-import the security policy using the following command:
     ```cmd
     secedit /configure /db secedit.sdb /cfg C:\path\to\output.inf /areas USER_RIGHTS
     ```
   - This will apply the changes, granting the specified privilege to the user.

4. **Reboot**:
   - The user might need to log out and log back in, or the system might need to be restarted for the changes to take effect.

### 4. **Using Group Policy (GPO)**
In a domain environment, you can use Group Policy to assign privileges to users across multiple machines.

#### Steps:
1. **Open Group Policy Management**:
   - Open `Group Policy Management` on a domain controller.
   
2. **Edit an Existing GPO or Create a New One**:
   - Right-click on the appropriate Organizational Unit (OU) or domain and select `Create a GPO in this domain, and Link it here…`.

3. **Navigate to User Rights Assignment**:
   - Edit the GPO, and navigate to `Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > User Rights Assignment`.

4. **Add Privileges**:
   - Double-click on the privilege you want to assign and add the user or group.

5. **Deploy the GPO**:
   - Once applied, the GPO will grant the specified privileges to the user or group across the selected computers.

### Important Notes:
- **Administrative Privileges**: You typically need administrative privileges to modify user rights.
- **Security Implications**: Adding privileges, especially sensitive ones like `SeDebugPrivilege`, can significantly impact system security. Always ensure that privileges are granted with caution and only to trusted users.
- **Reboot/Logoff**: Some changes require the user to log off and back on, or the system to be rebooted, for them to take effect.

By using the methods outlined above, you can manage user privileges in Windows environments to control what actions users can perform on the system.

### SeManageVolumePrivs

- https://github.com/CsEnox/SeManageVolumeExploit.git