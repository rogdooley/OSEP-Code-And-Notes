
## Enumeration with `setspn`

`setspn` is a command-line tool in Windows that is used to manage Service Principal Names (SPNs) for Active Directory (AD) objects, specifically for accounts in AD. An SPN is a unique identifier for a service instance, allowing a client application to request and authenticate a service. SPNs are essential in Kerberos authentication, where they help the Key Distribution Center (KDC) to locate the service and determine the account under which it runs.

### How `setspn` Works:
- **Managing SPNs:** Administrators use `setspn` to create, delete, or view the SPNs associated with AD accounts. This is crucial for services that use Kerberos authentication, as an incorrectly configured SPN can lead to authentication failures.

- **SPN Format:** An SPN is typically structured as `serviceclass/host:port/servicename`, where:
  - `serviceclass` is the type of service (e.g., `HTTP`, `MSSQLSvc`).
  - `host` is the FQDN (Fully Qualified Domain Name) of the host.
  - `port` is the port number (optional).
  - `servicename` is the name of the service (optional).

### `setspn` Usage:
- **View SPNs:** You can view the SPNs associated with a specific account using the following command:
  ```cmd
  setspn -L <accountname>
  ```
  This will list all SPNs registered to the specified account.

- **Add SPNs:** To add an SPN to an account, use:
  ```cmd
  setspn -A <SPN> <accountname>
  ```
  For example:
  ```cmd
  setspn -A HTTP/www.example.com DOMAIN\useraccount
  ```

- **Delete SPNs:** To remove an SPN from an account, use:
  ```cmd
  setspn -D <SPN> <accountname>
  ```

- **Set SPNs:** To set or replace SPNs for an account:
  ```cmd
  setspn -S <SPN> <accountname>
  ```

### Enumerating an AD Domain with `setspn`:
`setspn` can be leveraged in various ways to enumerate an AD domain:

1. **Listing SPNs for Domain Users or Computers:**
   By listing the SPNs for domain accounts (especially service accounts), you can identify which services are running on which hosts. For example, if you run:
   ```cmd
   setspn -L domain\service_account
   ```
   This could reveal critical services such as SQL servers, web servers, or other applications, along with the machines they are running on.

2. **Identifying Misconfigurations or Vulnerabilities:**
   - Misconfigured SPNs or those set on wrong accounts could expose the domain to Kerberos attacks, such as Kerberoasting. Attackers often enumerate SPNs to find accounts that can be targeted.
   - Using `setspn -Q <SPN>` allows you to search for specific SPNs in the domain, helping identify inconsistencies or duplicates.

3. **SPN-based Reconnaissance:**
   Attackers or administrators can search for all SPNs in the domain by running:
   ```cmd
   setspn -T <Domain> -Q */*
   ```
   This query returns all SPNs in the domain, which can be used to map out services and their associated accounts and machines.

In a security context, SPN enumeration is a common step during internal penetration tests or red team engagements. Identifying SPNs related to high-privilege accounts can provide attackers with targets for further exploitation, such as attempting to retrieve Kerberos tickets for offline cracking.

Service Principal Names (SPNs) are unique identifiers for services running on servers. In Active Directory, SPNs are used for Kerberos authentication. You can find SPNs using PowerShell or C#.

### Finding SPNs with PowerShell

You can use the `Get-ADUser` or `Get-ADComputer` cmdlet along with the `-Filter` and `-Properties` parameters to find SPNs.

#### 1. **Find SPNs for All Users**
```powershell
Get-ADUser -Filter * -Properties ServicePrincipalName | Where-Object { $_.ServicePrincipalName -ne $null } | Select-Object Name, ServicePrincipalName
```

#### 2. **Find SPNs for All Computers**
```powershell
Get-ADComputer -Filter * -Properties ServicePrincipalName | Where-Object { $_.ServicePrincipalName -ne $null } | Select-Object Name, ServicePrincipalName
```

#### 3. **Find Specific SPNs**
For example, if you are looking for SPNs related to MSSQL:
```powershell
Get-ADObject -Filter {servicePrincipalName -like "*MSSQL*"} -Properties servicePrincipalName | Select-Object Name, servicePrincipalName
```

### Finding SPNs with C#

If you prefer to use C#, you can leverage the `System.DirectoryServices` namespace to query Active Directory.

#### Example: Find SPNs for All Users or Computers
```csharp
using System;
using System.DirectoryServices;

class Program
{
    static void Main()
    {
        DirectoryEntry entry = new DirectoryEntry("LDAP://DC=example,DC=com");
        DirectorySearcher searcher = new DirectorySearcher(entry)
        {
            Filter = "(servicePrincipalName=*)"
        };

        searcher.PropertiesToLoad.Add("servicePrincipalName");

        foreach (SearchResult result in searcher.FindAll())
        {
            Console.WriteLine("Name: " + result.Properties["name"][0]);
            foreach (string spn in result.Properties["servicePrincipalName"])
            {
                Console.WriteLine("SPN: " + spn);
            }
        }
    }
}
```

### Explanation:

1. **PowerShell**:
   - The PowerShell commands query Active Directory for objects (users or computers) with SPNs and output their names along with the SPNs.
   - The `Where-Object` cmdlet filters out objects without SPNs.
   - The `Select-Object` cmdlet formats the output to show only the name and SPNs.

2. **C#**:
   - The C# example uses `DirectoryEntry` to connect to Active Directory.
   - `DirectorySearcher` is used to find all objects with SPNs (`servicePrincipalName`).
   - The results are printed out, showing both the object's name and its associated SPNs.

### Use Cases:

- **Kerberoasting**: Attackers often look for SPNs to perform Kerberoasting attacks.
- **Service Enumeration**: Admins may want to audit their environment to ensure that SPNs are correctly configured.
- **Troubleshooting**: Incorrect SPN settings can lead to Kerberos authentication issues, so finding SPNs can help in troubleshooting.

### List SPNs 

```powershell
```powershell
# Source / credit:
# https://social.technet.microsoft.com/wiki/contents/articles/18996.active-directory-powershell-script-to-list-all-spns-used.aspx
cls
$search = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
$search.filter = "(servicePrincipalName=*)"

## You can use this to filter for OU's:
## $results = $search.Findall() | `
## ?{ $_.path -like '*OU=whatever,DC=whatever,DC=whatever*' }
$results = $search.Findall()

foreach( $result in $results ) {
  $userEntry = $result.GetDirectoryEntry()
  Write-host "Object Name = " $userEntry.name -backgroundcolor "yellow" -foregroundcolor "black"
  Write-host "DN = " $userEntry.distinguishedName
  Write-host "Object Cat. = " $userEntry.objectCategory
  Write-host "servicePrincipalNames"

  $i=1
  foreach( $SPN in $userEntry.servicePrincipalName ) {
    Write-host "SPN ${i} =$SPN"
    $i+=1
  }
  Write-host ""
}
```


```cmd
dsquery * "ou=domain controllers,dc=yourdomain,dc=com" -filter "(&(objectcategory=computer)(servicePrincipalName=*))" -attr distinguishedName servicePrincipalName > spns.txt
```


## Common SPNs

Common Service Principal Names (SPNs) correspond to frequently used services within a Windows Active Directory environment. These SPNs are essential for Kerberos authentication and typically follow a standard format, depending on the service they represent. Here are some of the most common SPNs:

### 1. **HTTP/HTTPS Services**
   - **SPN Format:** `HTTP/<hostname>` or `HTTP/<hostname>:<port>`
   - **Examples:**
     - `HTTP/www.example.com`
     - `HTTP/intranet.example.com:8080`
   - **Usage:** Used for web services hosted on IIS or other web servers.

### 2. **Microsoft SQL Server**
   - **SPN Format:** `MSSQLSvc/<hostname>:<port>`
   - **Examples:**
     - `MSSQLSvc/sqlserver.example.com:1433`
     - `MSSQLSvc/sqlserver.example.com:1434`
   - **Usage:** Used for SQL Server instances. The port can be specified or omitted depending on whether it's the default instance or a named instance.

### 3. **File Services (SMB)**
   - **SPN Format:** `CIFS/<hostname>` or `HOST/<hostname>`
   - **Examples:**
     - `CIFS/fileserver.example.com`
     - `HOST/fileserver.example.com`
   - **Usage:** Used for file sharing services (SMB/CIFS). `HOST` is a generic SPN used for multiple services.

### 4. **LDAP Services**
   - **SPN Format:** `LDAP/<hostname>`
   - **Examples:**
     - `LDAP/dc.example.com`
     - `LDAP/dc1.example.com`
   - **Usage:** Used by Active Directory Domain Controllers for LDAP services.

### 5. **Kerberos Authentication**
   - **SPN Format:** `HOST/<hostname>` or `HOST/<hostname>.domain`
   - **Examples:**
     - `HOST/dc.example.com`
     - `HOST/dc1.example.com`
   - **Usage:** The `HOST` SPN is used as a default for Kerberos authentication across multiple services on a server, including RDP, SMB, and others.

### 6. **Remote Desktop Services**
   - **SPN Format:** `TERMSRV/<hostname>`
   - **Examples:**
     - `TERMSRV/rdserver.example.com`
   - **Usage:** Used for Remote Desktop Services, allowing clients to authenticate when connecting to a terminal server.

### 7. **Exchange Server**
   - **SPN Format:** `exchangeMDB/<hostname>`
   - **Examples:**
     - `exchangeMDB/exchange.example.com`
   - **Usage:** Used for Microsoft Exchange Mailbox Databases.

### 8. **IMAP and POP Services (Exchange)**
   - **SPN Format:** `IMAP/<hostname>` or `POP/<hostname>`
   - **Examples:**
     - `IMAP/mail.example.com`
     - `POP/mail.example.com`
   - **Usage:** Used for IMAP and POP services provided by Exchange.

### 9. **SMTP Services**
   - **SPN Format:** `SMTP/<hostname>`
   - **Examples:**
     - `SMTP/mail.example.com`
   - **Usage:** Used for Simple Mail Transfer Protocol (SMTP) services.

### 10. **Hyper-V Services**
   - **SPN Format:** `Hyper-V/<hostname>`
   - **Examples:**
     - `Hyper-V/hypervhost.example.com`
   - **Usage:** Used for Hyper-V virtualization services.

### 11. **IIS (Internet Information Services)**
   - **SPN Format:** `HTTP/<hostname>` (same as HTTP/HTTPS services)
   - **Examples:**
     - `HTTP/webserver.example.com`
   - **Usage:** Used for websites hosted on IIS.

### 12. **SQL Reporting Services**
   - **SPN Format:** `HTTP/<hostname>` or `RS/<hostname>`
   - **Examples:**
     - `HTTP/reportserver.example.com`
     - `RS/reportserver.example.com`
   - **Usage:** Used for SQL Server Reporting Services.

### 13. **Other Common SPNs**
   - **FTP Services:** `FTP/<hostname>`
   - **RPC Services:** `RPC/<hostname>`
   - **DNS Services:** `DNS/<hostname>`

### Importance in Security:
SPNs are crucial in a Kerberos environment, but they can also be exploited if not managed properly. For example, attackers can enumerate SPNs to identify service accounts that might be vulnerable to attacks like Kerberoasting, where Kerberos tickets are requested for a service and cracked offline to retrieve the service account's password. Proper management and auditing of SPNs are essential to maintain security within an AD environment.