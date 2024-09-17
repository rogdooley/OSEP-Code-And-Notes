# Function to create an LDAP searcher
function Get-LdapSearcher {
    param (
        [string]$domain
    )
    
    $root = "LDAP://$domain"
    $directorySearcher = New-Object System.DirectoryServices.DirectorySearcher
    $directorySearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($root)
    $directorySearcher.PageSize = 1000
    return $directorySearcher
}

# Function to find computers with unconstrained delegation
function Get-UnconstrainedDelegation {
    param (
        [string]$domain
    )

    $searcher = Get-LdapSearcher -domain $domain
    $searcher.Filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))"
    $searcher.PropertiesToLoad.AddRange(@("cn", "userAccountControl"))
    
    $results = $searcher.FindAll()
    if ($results.Count -gt 0) {
        Write-Host "`n[+] Unconstrained Delegation Computers in domain: $domain"
        foreach ($result in $results) {
            $name = $result.Properties["cn"][0]
            Write-Host " - $name"
        }
    } else {
        Write-Host "`n[-] No computers with unconstrained delegation found in $domain."
    }
}

# Function to find computers with constrained delegation
function Get-ConstrainedDelegation {
    param (
        [string]$domain
    )

    $searcher = Get-LdapSearcher -domain $domain
    $searcher.Filter = "(&(objectCategory=computer)(msDS-AllowedToDelegateTo=*))"
    $searcher.PropertiesToLoad.AddRange(@("cn", "msDS-AllowedToDelegateTo"))
    
    $results = $searcher.FindAll()
    if ($results.Count -gt 0) {
        Write-Host "`n[+] Constrained Delegation Computers in domain: $domain"
        foreach ($result in $results) {
            $name = $result.Properties["cn"][0]
            $services = $result.Properties["msDS-AllowedToDelegateTo"] -join ", "
            Write-Host " - $name (Allowed to delegate to: $services)"
        }
    } else {
        Write-Host "`n[-] No computers with constrained delegation found in $domain."
    }
}

# Function to enumerate across all domains in a forest
function EnumerateDelegationAcrossDomains {
    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $domains = $forest.Domains
    foreach ($domain in $domains) {
        $domainName = $domain.Name
        Write-Host "`nEnumerating domain: $domainName"
        Get-UnconstrainedDelegation -domain $domainName
        Get-ConstrainedDelegation -domain $domainName
    }
}

# Main execution
EnumerateDelegationAcrossDomains
