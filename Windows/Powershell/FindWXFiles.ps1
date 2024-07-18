param (
    [string]$directoryPath
)
# 
# 
# $dir = 'C:\Program Files (x86)'
# $dir=(New-Object -com scripting.filesystemobject).getFolder($dir).ShortPath
#
# Function to check if a file has writable and executable permissions
function IsWritableExecutable {
    param (
        [string]$filePath
    )

    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $hasWritePermission = $false
    $hasExecutePermission = $false

    try {
        # Get the ACL for the file
        $acl = Get-Acl -Path $filePath
        $accessRules = $acl.Access

        foreach ($rule in $accessRules) {
            # Check if the rule applies to the current user or to a group the current user is in
            $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
            if ($rule.IdentityReference -eq $currentUser.User -or $rule.IdentityReference -eq $currentUser.Name -or $principal.IsInRole($rule.IdentityReference)) {
                # Check if the rule allows write access
                if ($rule.AccessControlType -eq "Allow" -and ($rule.FileSystemRights -band "Write") -ne 0) {
                    $hasWritePermission = $true
                }

                # Check if the rule allows execute access
                if ($rule.AccessControlType -eq "Allow" -and ($rule.FileSystemRights -band "ExecuteFile") -ne 0) {
                    $hasExecutePermission = $true
                }
            }
        }
    } catch {
        Write-Error "Error accessing ACL for $filePath: $_"
    }

    return ($hasWritePermission -and $hasExecutePermission)
}

# Check if the directory path is valid
if (-Not (Test-Path -Path $directoryPath -PathType Container)) {
    Write-Host "Invalid directory path: $directoryPath"
    exit 1
}

# Get all files in the specified directory
$files = Get-ChildItem -Path $directoryPath -File -Recurse -ErrorAction SilentlyContinue

$writableExecutableFiles = @()

foreach ($file in $files) {
    if (IsWritableExecutable -filePath $file.FullName) {
        $writableExecutableFiles += $file.FullName
    }
}

# Output writable and executable files
if ($writableExecutableFiles.Count -gt 0) {
    Write-Host "Writable and executable files in $directoryPath:"
    $writableExecutableFiles | ForEach-Object { Write-Host $_ }
} else {
    Write-Host "No writable and executable files found in $directoryPath."
}
