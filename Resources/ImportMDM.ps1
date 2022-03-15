<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

#>

####################################################

function Get-AuthToken {

<#
.SYNOPSIS
This function is used to authenticate with the Graph API REST interface
.DESCRIPTION
The function authenticate with the Graph API Interface with the tenant name
.EXAMPLE
Get-AuthToken
Authenticates you with the Graph API interface
.NOTES
NAME: Get-AuthToken
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    $User
)

$userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User

$tenant = $userUpn.Host

Write-Host "Checking for AzureAD module..."

    $AadModule = Get-Module -Name "AzureAD" -ListAvailable

    if ($AadModule -eq $null) {

        Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"
        $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable

    }

    if ($AadModule -eq $null) {
        write-host
        write-host "AzureAD Powershell module not installed..." -f Red
        write-host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
        write-host "Script can't continue..." -f Red
        write-host
        exit
    }

# Getting path to ActiveDirectory Assemblies
# If the module count is greater than 1 find the latest version

    if($AadModule.count -gt 1){

        $Latest_Version = ($AadModule | select version | Sort-Object)[-1]

        $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }

            # Checking if there are multiple versions of the same module found

            if($AadModule.count -gt 1){

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
        if($authResult.AccessToken){
        # Creating header for Authorization token
        $authHeader = @{
            'Content-Type'='application/json'
            'Authorization'="Bearer " + $authResult.AccessToken
            'ExpiresOn'=$authResult.ExpiresOn
            }
        return $authHeader
        }

        else {
        Write-Host
        Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
        Write-Host
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
Function Test-JSON(){

<#
.SYNOPSIS
This function is used to test if the JSON passed to a REST Post request is valid
.DESCRIPTION
The function tests if the JSON passed to the REST Post is valid
.EXAMPLE
Test-JSON -JSON $JSON
Test if the JSON is valid before calling the Graph REST interface
.NOTES
NAME: Test-AuthHeader
#>

param ($JSON)
    try {
    $TestJSON = ConvertFrom-Json $JSON -ErrorAction Stop
    $validJson = $true
    }

    catch {
    $validJson = $false
    $_.Exception
    }

    if (!$validJson){
    Write-Host "Provided JSON isn't in valid JSON format" -f Red
    break
    }
}

write-host
# Checking if authToken exists before running authentication
if($global:authToken){

    # Setting DateTime to Universal time to work in all timezones
    $DateTime = (Get-Date).ToUniversalTime()

    # If the authToken exists checking when it expires
    $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes

        if($TokenExpires -le 0){
        write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
        write-host

            # Defining User Principal Name if not present
            if($User -eq $null -or $User -eq ""){

            $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
            Write-Host

            }

        $global:authToken = Get-AuthToken -User $User

        }
}

# Authentication doesn't exist, calling Get-AuthToken function
else {
    if($User -eq $null -or $User -eq ""){
    $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
    Write-Host
    }

# Getting the authorization token
$global:authToken = Get-AuthToken -User $User
}
####################################################
Function Add-MDMApplication(){

<#
.SYNOPSIS
This function is used to add an MDM application using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds an MDM application from the itunes store
.EXAMPLE
Add-MDMApplication -JSON $JSON
Adds an application into Intune
.NOTES
NAME: Add-MDMApplication
#>

[cmdletbinding()]

param
(
    $JSON
)

$graphApiVersion = "Beta"
$App_resource = "deviceAppManagement/mobileApps"

    try {
        if(!$JSON){
        write-host "No JSON was passed to the function, provide a JSON variable" -f Red
        break
        }

        Test-JSON -JSON $JSON

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($App_resource)"
        Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/json" -Body $JSON -Headers $authToken

    }

    catch {
    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd();
    Write-Host "Response content:`n$responseBody" -f Red
    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break
    }
}
####################################################
Function Add-ManagedAppPolicy() {
<#
.SYNOPSIS
This function is used to add an Managed App policy using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a Managed App policy
.EXAMPLE
Add-ManagedAppPolicy -JSON $JSON
Adds a Managed App policy in Intune
.NOTES
NAME: Add-ManagedAppPolicy
#>

[cmdletbinding()]
param($JSON)
$graphApiVersion = "Beta"
$Resource = "deviceAppManagement/managedAppPolicies"
    try {
        if($JSON -eq "" -or $JSON -eq $null){
          write-host "No JSON specified, please specify valid JSON for a Managed App Policy..." -f Red
        }

        else {
          Test-JSON -JSON $JSON
          $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
          Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"
        }
    }

    catch {
      Write-Host
      $ex = $_.Exception
      $errorResponse = $ex.Response.GetResponseStream()
      $reader = New-Object System.IO.StreamReader($errorResponse)
      $reader.BaseStream.Position = 0
      $reader.DiscardBufferedData()
      $responseBody = $reader.ReadToEnd();
      Write-Host "Response content:`n$responseBody" -f Red
      Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
      write-host
      break
    }
}
####################################################

####################################################
Function Add-DeviceCompliancePolicy(){
<#
.SYNOPSIS
This function is used to add a device compliance policy using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a device compliance policy
.EXAMPLE
Add-DeviceCompliancePolicy -JSON $JSON
Adds an iOS device compliance policy in Intune
.NOTES
NAME: Add-DeviceCompliancePolicy
#>

[cmdletbinding()]

param
($JSON)

$graphApiVersion = "Beta"
$Resource = "deviceManagement/deviceCompliancePolicies"
    try {
        if($JSON -eq "" -or $JSON -eq $null){
          write-host "No JSON specified, please specify valid JSON for the iOS Policy..." -f Red
        }

        else {
          Test-JSON -JSON $JSON
          $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
          Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"
        }
    }

    catch {
      $ex = $_.Exception
      $errorResponse = $ex.Response.GetResponseStream()
      $reader = New-Object System.IO.StreamReader($errorResponse)
      $reader.BaseStream.Position = 0
      $reader.DiscardBufferedData()
      $responseBody = $reader.ReadToEnd();
      Write-Host "Response content:`n$responseBody" -f Red
      Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
      write-host
      break
    }
}

# Upload Compliance Policies from folder
$CompliancePolicyPath = "..\CompliancePolicies"
Get-ChildItem $CompliancePolicyPath | Foreach-Object {
  Write-host "File name found: $_ " -ForegroundColor Yellow
  $JSON_Data = Get-Content "$CompliancePolicyPath\$_"
  # Excluding entries that are not required - id,createdDateTime,lastModifiedDateTime,version
  $JSON_Convert = $JSON_Data | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id,createdDateTime,lastModifiedDateTime,version,"@odata.context",apps@odata.context,deployedAppCount
  $JSON_Apps = $JSON_Convert.apps | select * -ExcludeProperty id,version
  $JSON_Convert | Add-Member -MemberType NoteProperty -Name 'apps' -Value @($JSON_Apps) -Force
  $DisplayName = $JSON_Convert.displayName
  $JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 5
  Write-Host "Adding Compliance Policy $DisplayName" -ForegroundColor Yellow
  Add-DeviceCompliancePolicy -JSON $JSON_Output
  Write-host "'$DisplayName' uploaded." -ForegroundColor Cyan
}

# Upload MDMApplication from folder
# March 15 2022: Issue uploading all Android MDMApplication JSON files.
#
# {"error":{"code":"BadRequest","message":"{\r\n  \"_version\": 3,\r\n  \"Message\": \"An error has occurred - Operation ID (for customer support): 00000000-0000-0000-0000-000000000000 - Activity ID: 36d08b49-8070-4064-adb1-ee88213899fb - Url: https://fef.msua08.manage.microsoft.com/AppLifecycle_2202/StatelessAppMetadataFEService/deviceAppManagement/mobileApps?api-version=5021-11-17\",\r\n  \"CustomApiErrorPhrase\": \"\",\r\n  \"RetryAfter\": null,\r\n  \"ErrorSourceService\": \"\",\r\n  \"HttpHeaders\": \"{}\"\r\n}","innerError":{"date":"2022-03-15T13:50:50","request-id":"36d08b49-8070-4064-adb1-ee88213899fb","client-request-id":"36d08b49-8070-4064-adb1-ee88213899fb"}}}
# Add-MDMApplication : Request to https://graph.microsoft.com/Beta/deviceAppManagement/mobileApps failed with HTTP
# Status BadRequest Bad Request At C:\Tools\PS\kiss365\test.ps1:338 char:1
#

$MAMPath = "..\MDMApplications-iOS"
Get-ChildItem $MAMPath | Foreach-Object {
  Write-host "File name found: $_." -ForegroundColor Yellow
  $JSON_Data = Get-Content "$MAMPath\$_"
  # Excluding entries that are not required - id,createdDateTime,lastModifiedDateTime,version
  $JSON_Convert = $JSON_Data | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id,createdDateTime,lastModifiedDateTime,version,"@odata.context",uploadState,packageId,appIdentifier,publishingState,usedLicenseCount,totalLicenseCount,productKey,licenseType,packageIdentityName
  $DisplayName = $JSON_Convert.displayName
  $JSON_Output = $JSON_Convert | ConvertTo-Json
  Write-Host "Adding MDM Application Policy $_." -ForegroundColor Yellow
  Add-MDMApplication -JSON $JSON_Output
  Write-host "'$_' uploaded." -ForegroundColor Cyan
}

# Upload ManagedAppPolicy
$AppProtectionPath = "..\ManagedApplicationPolicies"
Get-ChildItem $AppProtectionPath | Foreach-Object {
  $JSON_Data = Get-Content "$AppProtectionPath\$_"
  # Excluding entries that are not required - id,createdDateTime,lastModifiedDateTime,version
  $JSON_Convert = $JSON_Data | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id,createdDateTime,lastModifiedDateTime,version,"@odata.context",apps@odata.context,deployedAppCount
  $JSON_Apps = $JSON_Convert.apps | select * -ExcludeProperty id,version
  $JSON_Convert | Add-Member -MemberType NoteProperty -Name 'apps' -Value @($JSON_Apps) -Force
  $DisplayName = $JSON_Convert.displayName
  $JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 5
  # May need to change to $_ instead of $DisplayName
  write-host "Application Protection Policy $DisplayName" -ForegroundColor Yellow
  Add-ManagedAppPolicy -JSON $JSON_Output
  Write-Host "'$DisplayName' uploaded." -ForegroundColor Cyan
}
