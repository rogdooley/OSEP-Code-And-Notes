Import-Module PowerView.ps1

function Get-UsersWithPermissionsOverOtherUsers {
    param (
        [Parameter(Mandatory = $true)]
        [string]$PermissionType,
        [Parameter(Mandatory = $false)]
        [string]$OutputFile = "UserToUserPermissionsOutput.txt"
    )

    # Get all domain users
    $targetUsers = Get-DomainUser

    # Create an array to hold output lines
    $outputLines = @()

    foreach ($targetUser in $targetUsers) {
        # Get the ACLs for each target user
        $acls = Get-ObjectAcl -Identity $targetUser.DistinguishedName -ResolveGUIDs

        # Create an empty array to hold accounts with the specified permission over this user
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

                # Add the resolved account or SID to the list if it's a user (filter non-users)
                if ($resolvedName -notmatch 'S-1-5-') {
                    $accountsWithPermission += $resolvedName
                }
            }
        }

        # If any accounts were found with the specified permission, prepare the output for that user
        if ($accountsWithPermission.Count -gt 0) {
            $userOutput = "User Target: $($targetUser.Name)`r`n" +
                          "Distinguished Name: $($targetUser.DistinguishedName)`r`n" +
                          "Permission Type: $PermissionType`r`n" +
                          "Accounts with Permission: $($accountsWithPermission -join ', ')`r`n"

            # Add the formatted output for this user to the array
            $outputLines += $userOutput
        }
    }

    # Save the output to the specified file
    $outputLines | Out-File -FilePath $OutputFile -Width 300
    Write-Host "Results saved to $OutputFile"
}

# Example Usage
# Get-UsersWithPermissionsOverOtherUsers -PermissionType "WriteDACL" -OutputFile "UserToUserPermissionsReport.txt"