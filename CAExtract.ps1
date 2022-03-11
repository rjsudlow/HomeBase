# Export Function

param(
    [parameter()]
    [String]$BackupPath
)

# Connect to Azure AD
Import-Module AzureAD -UseWindowsPowerShell
Connect-AzureAD
$AllPolicies = Get-AzureADMSConditionalAccessPolicy

foreach ($Policy in $AllPolicies) {
    Write-Output "Backing up $($Policy.DisplayName) to $BackupPath"
    $PolicyJSON = $Policy | ConvertTo-Json -Depth 6
    $PolicyJSON | Out-File "$BackupPath\$($Policy.Id).json"
}
