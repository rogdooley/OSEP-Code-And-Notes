$windowsPath = "C:\Windows"
$writableExecutableDirectories = @()

function IsWritableExecutable {
    param (
        [string]$path
    )

    try {
        # Get the current user's identity
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $userSid = $currentUser.User.Value

        # Get the "Everyone" group SID
        $everyoneSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)

        # Get the ACL for the directory
        $acl = Get-Acl -Path $path
        $accessRules = $acl.Access

        $hasWritePermission = $false
        $hasExecutePermission = $false

        foreach ($rule in $accessRules) {
            $ruleSid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
            
            # Check if the rule applies to the current user or Everyone
            if ($ruleSid -eq $userSid -or $ruleSid -eq $everyoneSid.Value) {
                # Check if the rule allows write access
                if ($rule.AccessControlType -eq "Allow" -and ($rule.FileSystemRights -band "Write") -ne 0) {
                    $hasWritePermission = $true
                }

                # Check if the rule allows execute access
                if ($rule.AccessControlType -eq "Allow" -and ($rule.FileSystemRights -band "ExecuteFile") -ne 0) {
                    $hasExecutePermission = $true
                }

                # Exit early if both permissions are found
                if ($hasWritePermission -and $hasExecutePermission) {
                    return $true
                }
            }
        }
    } catch {
        Write-Error "Error accessing ACL for ${path}: $_"
    }

    return $false
}

# Get all directories inside C:\Windows
$directories = Get-ChildItem -Path $windowsPath -Directory -Recurse -ErrorAction SilentlyContinue

foreach ($directory in $directories) {
    if (IsWritableExecutable -path $directory.FullName) {
        $writableExecutableDirectories += $directory.FullName
    }
}

# Output writable and executable directories
if ($writableExecutableDirectories.Count -gt 0) {
    Write-Host "Writable and executable directories for the current user or Everyone inside ${windowsPath}:"
    $writableExecutableDirectories | ForEach-Object { Write-Host $_ }
} else {
    Write-Host "No writable and executable directories found for the current user or Everyone inside $windowsPath."
}