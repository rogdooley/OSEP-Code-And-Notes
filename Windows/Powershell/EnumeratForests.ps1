# Load PowerView into the current PowerShell session
Import-Module .\PowerView.ps1

# Use native PowerShell cmdlets to get forest information
Write-Output "Enumerating domain trusts with native PowerShell cmdlets..."

try {
    # Get forest information
    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $domains = $forest.Domains
    $trusts = $forest.GetAllTrustRelationships()

    # Display trusts
    foreach ($trust in $trusts) {
        $trust | Select-Object SourceName, TargetName, TrustType, TrustAttributes | Format-Table
    }
} catch {
    Write-Output "Error retrieving forest trust information: $_"
}



# 1. Find users with DCSync rights (GenericAll or GenericWrite)
Write-Output "Finding users with DCSync rights (GenericAll or GenericWrite)..."

# Retrieve the ACL entries and filter for users with high-level rights
$dcsyncUsers = Get-ObjectAcl -ResolveGUIDs | Where-Object {
    $_.ActiveDirectoryRights -match "GenericAll" -or $_.ActiveDirectoryRights -match "GenericWrite"
} | Select-Object SecurityIdentifier, ActiveDirectoryRights

# Convert SIDs to account names (usernames or group names)
$dcsyncUsernames = $dcsyncUsers | ForEach-Object {
    # Convert the Security Identifier (SID) to the corresponding username
    $sid = $_.SecurityIdentifier
    $username = ConvertFrom-SID -SID $sid
    
    # Create a custom object to display both the username and rights
    [PSCustomObject]@{
        Username = $username
        Rights   = $_.ActiveDirectoryRights
    }
}

# Output the results in a table
$dcsyncUsernames | Format-Table -AutoSize


# 2. Admin users
$adminGroups = Get-DomainGroupMember -Identity "Domain Admins", "Enterprise Admins" | Select-Object MemberName
$adminGroups | Format-Table

# 3. Service Accounts (SPNs)
Write-Output "Finding service accounts..."
$serviceAccounts = Get-DomainUser -SPN
$serviceAccounts | Format-Table

# 4. Sensitive Groups (Admins, DNS Admins, etc.)
Write-Output "Finding sensitive groups..."
$sensitiveGroups = Get-DomainGroup -Identity "Admins", "DNSAdmins", "Server Operators", "Account Operators" | Get-DomainGroupMember
$sensitiveGroups | Format-Table

# Summary of findings
Write-Output "High-value findings summary:"
Write-Output "1. DCSync Capable Users:"
$dcsyncUsers | Format-Table

Write-Output "2. Admin Groups:"
$adminGroups | Format-Table

Write-Output "3. Service Accounts:"
$serviceAccounts | Format-Table

Write-Output "4. Sensitive Groups:"
$sensitiveGroups | Format-Table


# Get the forest object
Write-Output "Enumerating all domains in the forest..."
$forest = Get-ADForest

# Enumerate all domains in the forest
$domains = $forest.Domains
Write-Output "Domains in the forest:"
$domains | ForEach-Object { $_ }

# Loop through each domain and list all groups
foreach ($domain in $domains) {
    Write-Output "Listing groups in domain: $domain"

    # Use PowerView to list groups in the current domain
    $groups = Get-DomainGroup -Domain $domain | Select-Object Name, SamAccountName
    
    # Output groups in table format
    $groups | Format-Table -AutoSize
}
