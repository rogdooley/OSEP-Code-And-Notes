# Script to enumerate AppLocker rules

# Check if AppLocker is enabled
$appLockerPolicy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue

if ($appLockerPolicy -eq $null) {
    Write-Host "AppLocker is not enabled on this system."
    exit
}

# Enumerate the rules
$rules = $appLockerPolicy.RuleCollections

if ($rules.Count -eq 0) {
    Write-Host "No AppLocker rules found."
} else {
    foreach ($ruleCollection in $rules) {
        Write-Host "`nRule Collection: $($ruleCollection.CollectionType)"

        foreach ($rule in $ruleCollection) {
            Write-Host "Name: $($rule.Name)"
            Write-Host "Description: $($rule.Description)"
            Write-Host "User: $($rule.UserOrGroupSid)"
            Write-Host "Action: $($rule.Action)"
            Write-Host "Conditions:"

            foreach ($condition in $rule.Conditions) {
                Write-Host "  Condition Type: $($condition.ConditionType)"

                if ($condition.ConditionType -eq "FilePathCondition") {
                    Write-Host "  Path: $($condition.Path)"
                } elseif ($condition.ConditionType -eq "FilePublisherCondition") {
                    Write-Host "  Publisher: $($condition.PublisherName)"
                    Write-Host "  Product Name: $($condition.ProductName)"
                    Write-Host "  Binary Name: $($condition.BinaryName)"
                } elseif ($condition.ConditionType -eq "FileHashCondition") {
                    Write-Host "  File Hash: $($condition.FileHash)"
                }
            }
            Write-Host ""
        }
    }
}

