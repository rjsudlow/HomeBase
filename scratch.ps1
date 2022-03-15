

function Get-AuthToken {
  [cmdletbinding()]
  param
  ([Parameter(Mandatory=$true)]$User)
  $userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User
  $tenant = $userUpn.Host
  Write-Host "Checking for AzureAD module..."
  $AadModule = Get-Module -Name "AzureAD" -ListAvailable
  if ($AadModule -eq $null) {
    Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"
    $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable
  }
  if ($AadModule -eq $null) {
    write-host "AzureAD Powershell module not installed..." -f Red
    write-host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
    write-host "Script can't continue..." -f Red
    exit
  }

  # Getting path to ActiveDirectory Assemblies
  # If the module count is greater than 1 find the latest version
  if($AadModule.count -gt 1) {
    $Latest_Version = ($AadModule | select version | Sort-Object)[-1]
    $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }
    # Checking if there are multiple versions of the same module found

    if($AadModule.count -gt 1) {
      $aadModule = $AadModule | select -Unique
    }

    $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
    $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
  }

  else {
    $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
    $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
  }

  [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
  [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null
  $clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
  $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
  $resourceAppIdURI = "https://graph.microsoft.com"
  $authority = "https://login.microsoftonline.com/$Tenant"

  try {
    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
    # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
    # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession
    $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"
    $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")
    $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId).Result
    # If the accesstoken is valid then create the authentication header

    if($authResult.AccessToken) {
      # Creating header for Authorization token
      $authHeader = @{
        'Content-Type'='application/json'
        'Authorization'="Bearer " + $authResult.AccessToken
        'ExpiresOn'=$authResult.ExpiresOn
      }
      return $authHeader

    }

    else {
      Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
      break
    }
  }

  catch {
    write-host $_.Exception.Message -f Red
    write-host $_.Exception.ItemName -f Red
    write-host
    break
  }

}
####################################################

Function Add-MDMApplication(){
  [cmdletbinding()]
  param($JSON)
  $graphApiVersion = "Beta"
  $App_resource = "deviceAppManagement/mobileApps"
  Connect-MgGraph -Scopes "User.ReadWrite.All","Group.ReadWrite.All,Application.Read.All,Group.Read.All,Directory.Read.All,Policy.Read.All,Policy.Read.ConditionalAccess,Policy.ReadWrite.ConditionalAccess,RoleManagement.Read.All,RoleManagement.Read.Directory,User.Read.All,DeviceManagementApps.Read.All,DeviceManagementApps.ReadWrite.All"
  Write-Host "[+] Successfully connected with Microsoft Graph. `n" -ForegroundColor Green
  if(!$JSON) {
    write-host "No JSON was passed to the function, provide a JSON variable" -f Red
    break
  }

  Test-JSON -JSON $JSON
  $uri = "https://graph.microsoft.com/$graphApiVersion/$($App_resource)"
  Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/json" -Body $JSON -Headers $authToken
}
####################################################

Function Test-JSON(){
  param ($JSON)
  try {
    $TestJSON = ConvertFrom-Json $JSON -ErrorAction Stop
    $validJson = $true
  }

  catch {
    $validJson = $false
    $_.Exception
  }

  if (!$validJson) {
    Write-Host "Provided JSON isn't in valid JSON format" -f Red
    break
  }

}
####################################################

# Microsoft default authentication method. Checking if authToken exists before running authentication:
# Works for PowerShell 5.x; Not PowerShell 7.x

<#
if($global:authToken) {
  # Setting DateTime to Universal time to work in all timezones
  $DateTime = (Get-Date).ToUniversalTime()
  # If the authToken exists checking when it expires
  $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes
  if($TokenExpires -le 0) {
    write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
    # Defining User Principal Name if not present
    if($User -eq $null -or $User -eq ""){
      $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
    }
    $global:authToken = Get-AuthToken -User $User
  }
}

# Authentication doesn't exist, calling Get-AuthToken function
else {
  if($User -eq $null -or $User -eq "") {
    $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
  }
  # Getting the authorization token
  $global:authToken = Get-AuthToken -User $User
}
#>
#endregion

$MAMPath = (Get-Item .).FullName + "\MDMApplications-iOS"
$MAMPath

Get-ChildItem $MAMPath | Foreach-Object {
  Write-host "File name found: $_." -ForegroundColor Yellow
  $JSON_Data = Get-Content "$_"
  # Excluding entries that are not required - id,createdDateTime,lastModifiedDateTime,version
  $JSON_Convert = $JSON_Data | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id,createdDateTime,lastModifiedDateTime,version,"@odata.context",uploadState,packageId,appIdentifier,publishingState,usedLicenseCount,totalLicenseCount,productKey,licenseType,packageIdentityName
  $DisplayName = $JSON_Convert.displayName
  $JSON_Output = $JSON_Convert | ConvertTo-Json
  Write-Host "Adding MDM Application Policy $_." -ForegroundColor Yellow
  Add-MDMApplication -JSON $JSON_Output
  Write-host "'$_' uploaded." -ForegroundColor Cyan
}
