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
NAME: Test-JSON
#>

param (
$JSON
)
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

####################################################

Function Add-DeviceCompliancePolicy(){

<#
.SYNOPSIS
This function is used to add a device compliance policy using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a device compliance policy
.EXAMPLE
Add-DeviceCompliancePolicy -JSON $JSON
Adds an Android device compliance policy in Intune
.NOTES
NAME: Add-DeviceCompliancePolicy
#>

[cmdletbinding()]

param
(
    $JSON
)

$graphApiVersion = "v1.0"
$Resource = "deviceManagement/deviceCompliancePolicies"

    try {

        if($JSON -eq "" -or $JSON -eq $null){

        write-host "No JSON specified. Please select a policy..." -f Red

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

#region Authentication

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


# Default Android Compliance Policy
$JSON_Android = @"
    {
    "@odata.type":  "microsoft.graph.androidCompliancePolicy",
    "displayName":  "TEST: Android Compliance Policy",
    "description":  "Android Compliance Policy",
    "scheduledActionsForRule":[{"ruleName":"PasswordRequired","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":0,"notificationTemplateId":""}]}],
    "passwordRequiredType":  "deviceDefault",
    "passwordMinimumLength":  6,
    "passwordExpirationDays": null,
    "passwordMinutesOfInactivityBeforeLock":  15,
    "passwordPreviousPasswordBlockCount":  4,
    "passwordRequiredType":  "numeric",
    "passwordRequired":  true,
    "storageRequireEncryption":  true,
    "storageRequireRemovableStorageEncryption":  true,
    "deviceThreatProtectionEnabled":  true,
    "deviceThreatProtectionRequiredSecurityLevel":  "low",
    "requireAppVerify":  true,
    "securityBlockJailbrokenDevices":  true,
    "securityPreventInstallAppsFromUnknownSources":  true,
    "securityDisableUsbDebugging":  false
    }
"@

# Default iOS Compliance Policy
$JSON_iOS = @"
  {
  "@odata.type": "microsoft.graph.iosCompliancePolicy",
  "description": "iOS Compliance Policy",
  "displayName": "TEST: iOS Compliance Policy",
  "scheduledActionsForRule":[{"ruleName":"PasswordRequired","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":0,"notificationTemplateId":""}]}],
  "passcodeRequired": true,
  "passcodeBlockSimple": true,
  "passcodeExpirationDays": 65535,
  "passcodeMinimumLength": 6,
  "passcodeMinutesOfInactivityBeforeLock": 15,
  "passcodeMinutesOfInactivityBeforeScreenTimeout":  2,
  "passcodePreviousPasscodeBlockCount": 4,
  "passcodeMinimumCharacterSetCount": null,
  "passcodeRequiredType": "numeric",
  "securityBlockJailbrokenDevices": true,
  "securityRequireSafetyNetAttestationBasicIntegrity":  true,
  "securityRequireSafetyNetAttestationCertifiedDevice":  true,
  "securityRequireGooglePlayServices":  true,
  "securityRequireUpToDateSecurityProviders":  false,
  "securityRequireCompanyPortalAppIntegrity":  true,
  "deviceThreatProtectionEnabled": true,
  "deviceThreatProtectionRequiredSecurityLevel": "low"
  }
"@

# Default iOS Compliance Policy
$JSON_Windows = @"
  {
  "@odata.type": "microsoft.graph.windows10CompliancePolicy",
  "displayName": "TEST: Windows Compliance Policy",
  "description": "Windows Compliance Policy",
  "scheduledActionsForRule":[{"ruleName":"PasswordRequired","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":0,"notificationTemplateId":""}]}],
  "passwordRequired":  true,
  "passwordBlockSimple":  true,
  "passwordRequiredToUnlockFromIdle":  false,
  "passwordMinutesOfInactivityBeforeLock":  5,
  "passwordExpirationDays":  730,
  "passwordMinimumLength":  8,
  "passwordMinimumCharacterSetCount":  null,
  "passwordRequiredType":  "deviceDefault",
  "passwordPreviousPasswordBlockCount":  null,
  "requireHealthyDeviceReport":  false,
  "osMinimumVersion":  null,
  "osMaximumVersion":  null,
  "mobileOsMinimumVersion":  null,
  "mobileOsMaximumVersion":  null,
  "earlyLaunchAntiMalwareDriverEnabled":  true,
  "bitLockerEnabled":  true,
  "secureBootEnabled":  true,
  "codeIntegrityEnabled":  true,
  "storageRequireEncryption":  true,
  "activeFirewallRequired":  true,
  "defenderEnabled":  false,
  "defenderVersion":  null,
  "signatureOutOfDate":  false,
  "rtpEnabled":  true,
  "antivirusRequired":  true,
  "antiSpywareRequired":  true,
  "deviceThreatProtectionEnabled":  true,
  "deviceThreatProtectionRequiredSecurityLevel":  "low",
  "configurationManagerComplianceRequired":  false,
  "tpmRequired":  false,
  "deviceCompliancePolicyScript":  null
  }
"@

####################################################

Write-Host "Adding Android Compliance Policy from JSON..." -ForegroundColor Yellow
Add-DeviceCompliancePolicy -JSON $JSON_Android

Write-Host "Adding iOS Compliance Policy from JSON..." -ForegroundColor Yellow
Add-DeviceCompliancePolicy -JSON $JSON_iOS

Write-Host "Adding Windows 10/11 Compliance Policy from JSON..." -ForegroundColor Yellow
Add-DeviceCompliancePolicy -JSON $JSON_Windows

Write-Host
