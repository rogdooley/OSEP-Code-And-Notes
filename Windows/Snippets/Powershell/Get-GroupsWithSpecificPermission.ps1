Import-Module PowerView.ps1

function Get-GroupsWithSpecificPermission {
    param (
        [Parameter(Mandatory = $true)]
        [string]$PermissionType,
        [Parameter(Mandatory = $false)]
        [string]$OutputFile = "GroupPermissionsOutput.txt"
    )

    # Get all domain groups
    $groups = Get-DomainGroup

    # Create an array to hold output lines
    $outputLines = @()

    foreach ($group in $groups) {
        # Get the ACLs for each group
        $acls = Get-ObjectAcl -Identity $group.DistinguishedName -ResolveGUIDs

        # Create an empty array to hold accounts with the specified permission
        $accountsWithPermission = @()

        foreach ($acl in $acls) {
            # Check if the specified permission exists in the ACL
            if ($acl.ActiveDirectoryRights -match $PermissionType) {
                # Try to resolve the PrincipalIdentity, fall back to SID if necessary
                $SID = $acl.SecurityIdentifier
                $resolvedName = try {
                    $SID.Translate([System.Security.Principal.NTAccount]).Value
                } catch {
                    "Could not resolve SID: $SID"
                }

                # Add the resolved account or SID to the list
                $accountsWithPermission += $resolvedName
            }
        }

        # If any accounts were found with the specified permission, prepare the output for that group
        if ($accountsWithPermission.Count -gt 0) {
            $groupOutput = "Group Name: $($group.Name)`r`n" +
                           "Distinguished Name: $($group.DistinguishedName)`r`n" +
                           "Permission Type: $PermissionType`r`n" +
                           "Accounts: $($accountsWithPermission -join ', ')`r`n"

            # Add the formatted output for this group to the array
            $outputLines += $groupOutput
        }
    }

    # Save the output to the specified file
    $outputLines | Out-File -FilePath $OutputFile -Width 300
    Write-Host "Results saved to $OutputFile"
}

# Example Usage
# Get-GroupsWithSpecificPermission -PermissionType "GenericAll" -OutputFile "PermissionsReport.txt"