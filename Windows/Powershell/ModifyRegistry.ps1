 function ModifyRegistryKey {
    param (
        [string]$registryPath,
        [string]$keyName
    )

    # Check if the key exists
    if (Get-ItemProperty -Path "$registryPath" -Name "$keyName" -ErrorAction SilentlyContinue) {
        # If the key exists, delete it
        try {
            Remove-ItemProperty -Path $registryPath -Name $keyName
            Write-Host "AmsiEnable key deleted from $registryPath"
        } catch {
            Write-Host "Failed to delete the AmsiEnable key at $registryPath : $keyName"
        }
    } else {
        # If the key does not exist, create it and set its value to 0
        try {
            Set-ItemProperty -Path $registryPath -Name $keyName -Value 0 
            Write-Host "AmsiEnable key created with value 0 at $registryPath"
        } catch {
            Write-Host "Failed to create the AmsiEnable key at $registryPath : $keyName"
        }
    }

} 

