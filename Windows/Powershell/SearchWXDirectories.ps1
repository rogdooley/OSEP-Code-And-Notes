$windowsPath = "C:\Windows"
$writableExecutableDirectories = @()

# Function to check if a directory has writable and executable permissions
function IsWritableExecutable {
    param (
        [string]$path
    )

    try {
        # Get the ACL for the directory
        $acl = Get-Acl -Path $path
        $accessRules = $acl.Access

        $hasWritePermission = $false
        $hasExecutePermission = $false

        foreach ($rule in $accessRules) {
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
    Write-Host "Writable and executable directories inside ${windowsPath}:"
    $writableExecutableDirectories | ForEach-Object { Write-Host $_ }
} else {
    Write-Host "No writable and executable directories found inside $windowsPath."
}