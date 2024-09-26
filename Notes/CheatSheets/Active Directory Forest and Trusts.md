
Here’s a cheat sheet for **enumerating AD forests** using **PowerView**, **PowerShell**, and **.NET**, without assuming the AD PowerShell module is installed.

---

### **1. Enumerating Domains in the Forest**

#### **PowerView:**
- PowerView is a popular tool for AD enumeration. It’s part of the PowerSploit framework.

```powershell
# Enumerate all domains in the forest
Get-NetForestDomain
```

#### **PowerShell (using .NET):**
- You can use the **`[System.DirectoryServices.ActiveDirectory.Forest]`** class in .NET to enumerate domains.

```powershell
$forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
$forest.Domains | ForEach-Object { $_.Name }
```

---

### **2. Enumerating Trusts in the Forest**

#### **PowerView:**

```powershell
# Enumerate trusts within the forest
Get-NetForestTrust
```

#### **PowerShell (using .NET):**

```powershell
$forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
$forest.GetAllTrustRelationships() | ForEach-Object { $_.TargetName, $_.TrustType, $_.TrustDirection }
```

This will display the **target domain** and the **trust type/direction** for each trust.

---

### **3. Enumerating Domain Controllers in the Forest**

#### **PowerView:**

```powershell
# Get all domain controllers in the forest
Get-NetForestDomain | ForEach-Object { Get-NetDomainController -Domain $_ }
```

#### **PowerShell (using .NET):**

```powershell
$forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
$forest.Domains | ForEach-Object {
    $_.DomainControllers | ForEach-Object { $_.Name }
}
```

This will loop through all domains in the forest and list the domain controllers for each.

---

### **4. Enumerating Global Catalog Servers**

#### **PowerView:**

```powershell
# Get Global Catalog servers in the forest
Get-NetForestCatalog
```

#### **PowerShell (using .NET):**

```powershell
$forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
$forest.GlobalCatalogs | ForEach-Object { $_.Name }
```

---

### **5. Enumerating Forest Functional Level**

#### **PowerView:**

```powershell
# Get forest functional level
Get-NetForest | Select-Object ForestMode
```

#### **PowerShell (using .NET):**

```powershell
$forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
$forest.ForestMode
```

---

### **6. Enumerating Sites in the Forest**

#### **PowerView:**

```powershell
# Enumerate all AD sites in the forest
Get-NetForestSite
```

#### **PowerShell (using .NET):**

```powershell
$forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
$forest.Sites | ForEach-Object { $_.Name }
```

---

### **7. Enumerating Organizational Units (OUs)**

#### **PowerView:**

```powershell
# Enumerate all OUs in the current domain
Get-NetOU
```

#### **PowerShell (without AD module):**

Use `.NET`’s **`DirectorySearcher`** class to search for Organizational Units.

```powershell
$root = [ADSI] "LDAP://RootDSE"
$searcher = New-Object DirectoryServices.DirectorySearcher
$searcher.SearchRoot = "LDAP://$($root.defaultNamingContext)"
$searcher.Filter = "(objectCategory=organizationalUnit)"
$searcher.FindAll() | ForEach-Object { $_.Properties["distinguishedName"] }
```

---

### **8. Enumerating Users Across Domains in the Forest**

#### **PowerView:**

```powershell
# Get users across all domains in the forest
Get-NetForestDomain | ForEach-Object { Get-NetUser -Domain $_ }
```

#### **PowerShell (using .NET):**

```powershell
$forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
$forest.Domains | ForEach-Object {
    $domain = $_.Name
    $searcher = New-Object DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = "LDAP://$domain"
    $searcher.Filter = "(objectCategory=user)"
    $searcher.FindAll() | ForEach-Object { $_.Properties["samaccountname"] }
}
```

---

### **9. Enumerating Groups Across the Forest**

#### **PowerView:**

```powershell
# Get all groups across the domains in the forest
Get-NetForestDomain | ForEach-Object { Get-NetGroup -Domain $_ }
```

#### **PowerShell (using .NET):**

```powershell
$forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
$forest.Domains | ForEach-Object {
    $domain = $_.Name
    $searcher = New-Object DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = "LDAP://$domain"
    $searcher.Filter = "(objectCategory=group)"
    $searcher.FindAll() | ForEach-Object { $_.Properties["name"] }
}
```

---

### **10. Enumerating Service Principal Names (SPNs)**

#### **PowerView:**

```powershell
# Enumerate all SPNs across the forest
Get-NetForestDomain | ForEach-Object { Get-NetComputer -Domain $_ -SPN }
```

#### **PowerShell (using .NET):**

```powershell
$forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
$forest.Domains | ForEach-Object {
    $domain = $_.Name
    $searcher = New-Object DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = "LDAP://$domain"
    $searcher.Filter = "(servicePrincipalName=*)"
    $searcher.FindAll() | ForEach-Object { $_.Properties["servicePrincipalName"] }
}
```

---

### **11. Enumerating Group Policies (GPOs)**

#### **PowerView:**

```powershell
# Enumerate all GPOs in the domain
Get-NetGPO
```

#### **PowerShell (without AD module)**:

You can query Group Policy Objects (GPOs) by searching for objects with `objectCategory=groupPolicyContainer`.

```powershell
$root = [ADSI] "LDAP://RootDSE"
$searcher = New-Object DirectoryServices.DirectorySearcher
$searcher.SearchRoot = "LDAP://$($root.defaultNamingContext)"
$searcher.Filter = "(objectCategory=groupPolicyContainer)"
$searcher.FindAll() | ForEach-Object { $_.Properties["displayName"] }
```

---

### **12. Enumerating Computers Across the Forest**

#### **PowerView:**

```powershell
# Enumerate all computers across the forest
Get-NetForestDomain | ForEach-Object { Get-NetComputer -Domain $_ }
```

#### **PowerShell (using .NET):**

```powershell
$forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
$forest.Domains | ForEach-Object {
    $domain = $_.Name
    $searcher = New-Object DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = "LDAP://$domain"
    $searcher.Filter = "(objectCategory=computer)"
    $searcher.FindAll() | ForEach-Object { $_.Properties["name"] }
}
```

---

### **13. Getting Group Membership for Users or Computers**

#### **PowerView:**

```powershell
# Get group memberships for a specific user or computer
Get-NetGroupMember -GroupName <group_name>
```

#### **PowerShell (without AD module)**:

Use `.NET` to search for group memberships of specific users.

```powershell
$searcher = New-Object DirectoryServices.DirectorySearcher
$searcher.Filter = "(samaccountname=<username>)"
$user = $searcher.FindOne()

$user.Properties["memberof"]
```

---

