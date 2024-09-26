# Unconstrained Delegation - searches for the 'trusted for delegation' flag (userAccountControl)
function Get-UnconstrainedDelegation {
    $searcher = New-Object DirectoryServices.DirectorySearcher
    $searcher.Filter = "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))"
    $searcher.PropertiesToLoad.Add("name") | Out-Null
    $searcher.PropertiesToLoad.Add("userAccountControl") | Out-Null
    $searcher.FindAll() | ForEach-Object {
        [PSCustomObject]@{
            Name = $_.Properties.name[0]
            DelegationType = "Unconstrained Delegation"
        }
    }
}

# Constrained Delegation - searches for msDS-AllowedToDelegateTo attribute
function Get-ConstrainedDelegation {
    $searcher = New-Object DirectoryServices.DirectorySearcher
    $searcher.Filter = "(&(objectClass=computer)(msDS-AllowedToDelegateTo=*))"
    $searcher.PropertiesToLoad.Add("name") | Out-Null
    $searcher.PropertiesToLoad.Add("msDS-AllowedToDelegateTo") | Out-Null
    $searcher.FindAll() | ForEach-Object {
        [PSCustomObject]@{
            Name = $_.Properties.name[0]
            DelegationType = "Constrained Delegation"
            Services = ($_.Properties.'msds-allowedtodelegateto' -join ', ')
        }
    }
}

# Resource-Based Constrained Delegation (RBCD) - searches for msDS-AllowedToActOnBehalfOfOtherIdentity attribute
function Get-RBCDDelegation {
    $searcher = New-Object DirectoryServices.DirectorySearcher
    $searcher.Filter = "(&(objectClass=computer)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))"
    $searcher.PropertiesToLoad.Add("name") | Out-Null
    $searcher.PropertiesToLoad.Add("msDS-AllowedToActOnBehalfOfOtherIdentity") | Out-Null
    $searcher.FindAll() | ForEach-Object {
        [PSCustomObject]@{
            Name = $_.Properties.name[0]
            DelegationType = "Resource-Based Constrained Delegation (RBCD)"
        }
    }
}

# Run all delegation checks and output results
$unconstrained = Get-UnconstrainedDelegation
$constrained = Get-ConstrainedDelegation
$rbcd = Get-RBCDDelegation

$unconstrained + $constrained + $rbcd | Format-Table -AutoSize

