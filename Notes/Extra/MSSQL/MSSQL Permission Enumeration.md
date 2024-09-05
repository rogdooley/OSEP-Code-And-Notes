
Here’s a series of MSSQL statements that you can use to enumerate potential security risks related to database settings and server configurations that might be exploited for malicious behavior:

### 1. Check for Databases with the Trustworthy Property Set
The `TRUSTWORTHY` property allows certain privileged actions in the database. You should ensure that this property is not enabled unless absolutely necessary.

```sql
SELECT name, is_trustworthy_on
FROM sys.databases
WHERE is_trustworthy_on = 1;
```

### 2. Check if `xp_cmdshell` is Enabled
`xp_cmdshell` allows running operating system commands directly from SQL Server, which can be a significant security risk.

```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell';
```

### 3. Check for `CLR` Enabled
Enabling the CLR (Common Language Runtime) allows running .NET code inside SQL Server, which could be exploited if not managed correctly.

```sql
EXEC sp_configure 'clr enabled';
```

### 4. Check for Databases with `DB_CHAINING` Enabled
Database chaining allows cross-database access without explicit permissions. This can be dangerous if not properly controlled.

```sql
SELECT name, is_db_chaining_on
FROM sys.databases
WHERE is_db_chaining_on = 1;
```

### 5. Check for `OLE Automation` Procedures Enabled
`OLE Automation` procedures enable SQL Server to interact with COM objects, which could be used for malicious purposes.

```sql
EXEC sp_configure 'Ole Automation Procedures';
```

### 6. Check for Unrestricted `SQLCLR` Assemblies
Identify any SQLCLR assemblies that are marked as `UNSAFE` or `EXTERNAL_ACCESS`.

```sql
SELECT name, permission_set_desc
FROM sys.assemblies
WHERE permission_set_desc IN ('UNSAFE_ACCESS', 'EXTERNAL_ACCESS');
```

### 7. Check for Elevated Permissions on Logins
Identify logins that have sysadmin or other high-level server roles.

```sql
SELECT name, type_desc, is_disabled
FROM sys.server_principals
WHERE is_disabled = 0
AND (type_desc IN ('SQL_LOGIN', 'WINDOWS_LOGIN', 'WINDOWS_GROUP'))
AND name NOT LIKE 'NT AUTHORITY%';
```

### 8. Check for `PUBLIC` Role Permissions
Identify if the `PUBLIC` role has elevated permissions.

```sql
SELECT class_desc, permission_name
FROM sys.database_permissions
WHERE grantee_principal_id = DATABASE_PRINCIPAL_ID('public')
AND permission_name NOT IN ('CONNECT');
```

### 9. Check for Open Linked Servers
Identify linked servers that might allow an attacker to move laterally within the network.

```sql
SELECT name, is_linked
FROM sys.servers
WHERE is_linked = 1;
```

### 10. Check for Open Firewall Rules Allowing External Connections
Identify any firewall rules that allow external connections to SQL Server.

```sql
EXEC sp_helpserver;
```

## MSSQL Enumeration script

```powershell
# Parameters
$server = "YourServerName"    # Replace with your server name or IP
$database = "master"          # Using master to run server-wide queries
$outputFile = "SecurityCheckResults.txt"

# Connection String
$connectionString = "Server=$server;Database=$database;Integrated Security=True;"

# Define SQL queries
$queries = @"
-- Check for Databases with the Trustworthy Property Set
SELECT 'Trustworthy Property Set' AS [Check], name, is_trustworthy_on
FROM sys.databases
WHERE is_trustworthy_on = 1;

-- Check if xp_cmdshell is Enabled
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell';

-- Check for CLR Enabled
EXEC sp_configure 'clr enabled';

-- Check for Databases with DB_CHAINING Enabled
SELECT 'DB Chaining Enabled' AS [Check], name, is_db_chaining_on
FROM sys.databases
WHERE is_db_chaining_on = 1;

-- Check for OLE Automation Procedures Enabled
EXEC sp_configure 'Ole Automation Procedures';

-- Check for Unrestricted SQLCLR Assemblies
SELECT 'Unrestricted SQLCLR Assemblies' AS [Check], name, permission_set_desc
FROM sys.assemblies
WHERE permission_set_desc IN ('UNSAFE_ACCESS', 'EXTERNAL_ACCESS');

-- Check for Elevated Permissions on Logins
SELECT 'Elevated Permissions on Logins' AS [Check], name, type_desc, is_disabled
FROM sys.server_principals
WHERE is_disabled = 0
AND (type_desc IN ('SQL_LOGIN', 'WINDOWS_LOGIN', 'WINDOWS_GROUP'))
AND name NOT LIKE 'NT AUTHORITY%';

-- Check for PUBLIC Role Permissions
SELECT 'Public Role Permissions' AS [Check], class_desc, permission_name
FROM sys.database_permissions
WHERE grantee_principal_id = DATABASE_PRINCIPAL_ID('public')
AND permission_name NOT IN ('CONNECT');

-- Check for Open Linked Servers
SELECT 'Open Linked Servers' AS [Check], name, is_linked
FROM sys.servers
WHERE is_linked = 1;

-- Check for Open Firewall Rules Allowing External Connections
EXEC sp_helpserver;
"@

# Execute each query and write results to file
Add-Content -Path $outputFile -Value "SQL Server Security Check Results"

$queries.Split("`n`n") | ForEach-Object {
    $query = $_.Trim()
    if ($query) {
        Add-Content -Path $outputFile -Value "`n`nExecuting Query: $query"
        $result = Invoke-Sqlcmd -ConnectionString $connectionString -Query $query
        $result | Out-File -Append -FilePath $outputFile
    }
}

Write-Host "Security checks completed. Results saved to $outputFile"

```