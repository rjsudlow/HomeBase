#################################
##      Utility Functions      ##
#################################

Function Get-AuthToken {
  [cmdletbinding()]
  param
  ([Parameter(Mandatory=$true)]$User)
  $userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User
  $tenant = $userUpn.Host
  Write-Host "[*] Checking for AzureAD module..." -f Yellow
  $AadModule = Get-Module -Name "AzureAD" -ListAvailable
  if ($AadModule -eq $null) {
    Write-Host "[!] AzureAD PowerShell module not found, looking for AzureADPreview" -f Red
    $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable
  }
  if ($AadModule -eq $null) {
    write-host "[!] AzureAD Powershell module not installed..." -f Red
    write-host "[*] Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
    write-host "[!] Script can't continue..." -f Red
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
      Write-Host "[!] Authorization Access Token is null, please re-run authentication..." -f Red
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

Function Auth() {
  # Microsoft default authentication method. Checking if authToken exists before running authentication:
  # Works for PowerShell 5.x; Not PowerShell 5.x
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
}

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

Function Connect-MSGraph() {
	# Simple single connect function.
	Write-Host "[*] Connecting to Microsoft Graph. Please login with Admin credentials to guarantee deployment. `n" -ForegroundColor Yellow
	Connect-MgGraph -Scopes "User.ReadWrite.All","Group.ReadWrite.All,Application.Read.All,Group.Read.All,Directory.Read.All,Policy.Read.All,Policy.Read.ConditionalAccess,Policy.ReadWrite.ConditionalAccess,RoleManagement.Read.All,RoleManagement.Read.Directory,User.Read.All"
	Write-Host "[+] Successfully connected with Microsoft Graph. `n" -ForegroundColor Green
	#Connect-MsolService
	#Connect-AzureAD
	#Connect-MicrosoftTeams
}

#################################
##    Deployment Functions     ##
#################################

Function Create-User() {
	# Create Intune Test User
	# Reference: https://docs.microsoft.com/en-us/graph/api/user-post-users?view=graph-rest-1.0&tabs=powershell
	# Reference: https://docs.microsoft.com/en-us/powershell/module/microsoft.graph.users/get-mguser?view=graph-powershell-beta
	#Import-Module Microsoft.Graph.Users
	Write-Host "[*] Creating Pilot User with name of $PilotUserName@$Domain. `n" -ForegroundColor Yellow
	$params = @{
		AccountEnabled = $true
		DisplayName = $PilotDisplayName
		MailNickname = $PilotUserName
		UserPrincipalName = "$PilotUserName@$Domain"
		PasswordProfile = @{
			ForceChangePasswordNextSignIn = $true
			Password = "TempPass123**"
		}
	}
	New-MgUser -BodyParameter $params
	Write-Host "[*] Assigning $PilotUserName UID to variable... `n" -ForegroundColor Yellow
	# Appropriate way to get UID as variable:
	# $test = (Get-MgUser -Filter "displayName eq 'RJ Sudlow'" -Property Id).Id
	$PilotUID = (Get-MgUser -Filter "displayName eq '$PilotDisplayName'").Id
	$global:PilotUID = $PilotUID
	Write-Host "[+] UID for new user is: $PilotUID `n" -ForegroundColor Green
}

Function Create-Group() {
	#Import-Module Microsoft.Graph.Groups
	# Create Intune Pilot Group & Assign User to Group
	# Reference: https://docs.microsoft.com/en-us/graph/api/group-post-groups?view=graph-rest-1.0&tabs=powershell
	Write-Host "[*] Creating group..." -ForegroundColor Yellow
	#$MemberURL = "https://graph.microsoft.com/v1.0/users/$PilotUID"
	$params = @{
		Description = "Group for all users with Intune licenses."
		DisplayName = "$PilotGroup"
		GroupTypes = @(
		)
		MailEnabled = $false
		MailNickname = "$PilotGroupNickname"
		SecurityEnabled = $true
		"Owners@odata.bind" = @(
	    "https://graph.microsoft.com/v1.0/users/$PilotUID"
		)
		"Members@odata.bind" = @(
			"https://graph.microsoft.com/v1.0/users/$PilotUID")
	}
	New-MgGroup -BodyParameter $params
	# Need to find how to get Group ID
	$GroupID = (Get-MgGroup -Filter "displayName eq '$PilotGroup'").Id
	$global:GroupID = $GroupID
	Write-Host "[+] UID for group is: $GroupID `n" -ForegroundColor Green
}

Function Add-MDMApplication(){
  [cmdletbinding()]
  param($JSON)
  $graphApiVersion = "Beta"
  $App_resource = "deviceAppManagement/mobileApps"
  if(!$JSON) {
    write-host "[!] No JSON was passed to the function, provide a JSON variable" -f Red
    break
  }

  Test-JSON -JSON $JSON
  $uri = "https://graph.microsoft.com/$graphApiVersion/$($App_resource)"
  Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/json" -Body $JSON -Headers $authToken
}

Function MDMApplication() {
  # Upload iOS MDM applications
  $MAMPath = (Get-Item .).FullName + "\MDMApplications-iOS"
  Get-ChildItem $MAMPath | Foreach-Object {
    Write-host "[*] File name found: $MAMPath\$_." -f Yellow
    $JSON_Data = Get-Content "$MAMPath\$_"
    # Excluding entries that are not required - id,createdDateTime,lastModifiedDateTime,version
    $JSON_Convert = $JSON_Data | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id,createdDateTime,lastModifiedDateTime,version,"@odata.context",uploadState,packageId,appIdentifier,publishingState,usedLicenseCount,totalLicenseCount,productKey,licenseType,packageIdentityName
    $DisplayName = $JSON_Convert.displayName
    $JSON_Output = $JSON_Convert | ConvertTo-Json
    Write-Host "[*] Adding MDM Application Policy $_ ..." -f Yellow
    Add-MDMApplication -JSON $JSON_Output
    Write-host "[+] '$_' uploaded." -f Green
  }
}

Function Add-DeviceCompliancePolicy(){
  [cmdletbinding()]
  param($JSON)
  $graphApiVersion = "v1.0"
  $Resource = "deviceManagement/deviceCompliancePolicies"
  try {
    if($JSON -eq "" -or $JSON -eq $null){
      write-host "[!] No JSON specified. Please select a policy..." -f Red
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
    Write-Host "[!] Response content:`n$responseBody" -f Red
    Write-Error "[!] Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break
  }
}

Function DeviceCompliancePolicy () {
	# Upload Compliance Policies from folder
	$CompliancePolicyPath = (Get-Item .).FullName + ".\CompliancePolicies"
	Get-ChildItem $CompliancePolicyPath | Foreach-Object {
	  Write-host "[*] File name found: $CompliancePolicyPath\$_ " -f Yellow
	  $JSON_Data = Get-Content "$CompliancePolicyPath\$_"
	  # Excluding entries that are not required - id,createdDateTime,lastModifiedDateTime,version
	  $JSON_Convert = $JSON_Data | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id,createdDateTime,lastModifiedDateTime,version,"@odata.context",apps@odata.context,deployedAppCount
	  $JSON_Apps = $JSON_Convert.apps | select * -ExcludeProperty id,version
	  $JSON_Convert | Add-Member -MemberType NoteProperty -Name 'apps' -Value @($JSON_Apps) -Force
	  $DisplayName = $JSON_Convert.displayName
	  $JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 5
	  Write-Host "[*] Adding Device Compliance Policy $DisplayName ..." -f Yellow
	  Add-DeviceCompliancePolicy -JSON $JSON_Output
	  Write-host "[+] '$DisplayName' uploaded." -f Cyan
	}
}

Function Add-ManagedAppPolicy() {
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

Function ManagedAppPolicy() {
  # Upload ManagedAppPolicy
	$AppProtectionPath = (Get-Item .).FullName + ".\ManagedApplicationPolicies"
	Get-ChildItem $AppProtectionPath | Foreach-Object {
    Write-host "[*] File name found: $AppProtectionPath\$_ " -f Yellow
	  $JSON_Data = Get-Content "$AppProtectionPath\$_"
	  # Excluding entries that are not required - id,createdDateTime,lastModifiedDateTime,version
	  $JSON_Convert = $JSON_Data | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id,createdDateTime,lastModifiedDateTime,version,"@odata.context",apps@odata.context,deployedAppCount
	  $JSON_Apps = $JSON_Convert.apps | select * -ExcludeProperty id,version
	  $JSON_Convert | Add-Member -MemberType NoteProperty -Name 'apps' -Value @($JSON_Apps) -Force
	  $DisplayName = $JSON_Convert.displayName
	  $JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 5
	  # May need to change to $_ instead of $DisplayName
	  write-host "[*] Adding Application Protection Policy $DisplayName ..." -f Yellow
	  Add-ManagedAppPolicy -JSON $JSON_Output
	  Write-Host "[+] '$DisplayName' uploaded." -f Green
	}
}

Function Get-EndpointSecurityTemplate() {
  # Function gets available Endpoint Security Templates from Microsoft.
  $graphApiVersion = "Beta"
  $ESP_resource = "deviceManagement/templates?`$filter=(isof(%27microsoft.graph.securityBaselineTemplate%27))"
  try {
    $uri = "https://graph.microsoft.com/$graphApiVersion/$($ESP_resource)"
    (Invoke-RestMethod -Method Get -Uri $uri -Headers $authToken).value
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

Function Add-EndpointSecurityPolicy() {
  [cmdletbinding()]
  param
  ($TemplateId, $JSON)
  $graphApiVersion = "Beta"
  $ESP_resource = "deviceManagement/templates/$TemplateId/createInstance"
  Write-Verbose "Resource: $ESP_resource"
  try {
    if($JSON -eq "" -or $JSON -eq $null) {
      write-host "No JSON specified, please specify valid JSON for the Endpoint Security Policy..." -f Red
    }

    else {
      Test-JSON -JSON $JSON
      $uri = "https://graph.microsoft.com/$graphApiVersion/$($ESP_resource)"
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

Function EndpointSecurityPolicy() {
  $EndpointSecurityPath = (Get-Item .).FullName + ".\EndpointSecurityPolicies"
  Get-ChildItem $EndpointSecurityPath | Foreach-Object {
    $JSON_Data = Get-Content "$EndpointSecurityPath\$_"
    $JSON_Convert = $JSON_Data | ConvertFrom-Json
    $JSON_DN = $JSON_Convert.displayName
    $JSON_TemplateDisplayName = $JSON_Convert.TemplateDisplayName
    $JSON_TemplateId = $JSON_Convert.templateId
    Write-Host "[*] Endpoint Security Policy '$JSON_DN' found..." -f Yellow
    # Get all Endpoint Security Templates
    $Templates = Get-EndpointSecurityTemplate
    # Checking if templateId from JSON is a valid templateId
    $ES_Template = $Templates | ?  { $_.id -eq $JSON_TemplateId }
    # If template is a baseline Edge, MDATP or Windows, use templateId specified
    if(($ES_Template.templateType -eq "microsoftEdgeSecurityBaseline") -or ($ES_Template.templateType -eq "securityBaseline") -or ($ES_Template.templateType -eq "advancedThreatProtectionSecurityBaseline")) {
      $TemplateId = $JSON_Convert.templateId
    }

    # If not a baseline, check if template is deprecated
    elseif($ES_Template) {
      # if template isn't deprecated use templateId
      if($ES_Template.isDeprecated -eq $false) {
        $TemplateId = $JSON_Convert.templateId
      }

      # If template deprecated, look for lastest version
      elseif($ES_Template.isDeprecated -eq $true) {
        $Template = $Templates | ? { $_.displayName -eq "$JSON_TemplateDisplayName" }
        $Template = $Template | ? { $_.isDeprecated -eq $false }
        $TemplateId = $Template.id
      }
    }

    # Else If Imported JSON template ID can't be found check if Template Display Name can be used
    elseif($ES_Template -eq $null) {
      Write-Host "[!] Didn't find Template for file: $JSON_TemplateId." -f Red
      Write-Host "[*] Checking if template type '$JSON_TemplateDisplayName' can be used..." -f Yellow
      $ES_Template = $Templates | ?  { $_.displayName -eq "$JSON_TemplateDisplayName" }
      if($ES_Template) {
        if(($ES_Template.templateType -eq "securityBaseline") -or ($ES_Template.templateType -eq "advancedThreatProtectionSecurityBaseline")) {
          Write-Host "[!] TemplateID '$JSON_TemplateId' with template Name '$JSON_TemplateDisplayName' doesn't exist." -f Red
          Write-Host "[!] Importing using the updated template could fail as settings specified may not be included in the latest template..." -f Red
          Write-Host
          break
        }

        else {
          Write-Host "[+] Template '$JSON_TemplateDisplayName' found..." -f Green
          $Template = $ES_Template | ? { $_.isDeprecated -eq $false }
          $TemplateId = $Template.id
        }
      }

      else {
        Write-Host "[!] TemplateID '$JSON_TemplateId' with template Name '$JSON_TemplateDisplayName' doesn't exist..." -f Red
        Write-Host "[!] Import using the updated template could fail (Setting changes could have occurred between template releases)." -f Red
        break
      }
    }

  # Excluding certain properties from JSON that aren't required for import
  $JSON_Convert = $JSON_Convert | Select-Object -Property * -ExcludeProperty TemplateDisplayName,TemplateId,versionInfo
  $DisplayName = $JSON_Convert.displayName
  $JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 5
  $JSON_Output
  Write-Host "[*] Adding Endpoint Security Policy '$DisplayName'" -f Yellow
  Add-EndpointSecurityPolicy -TemplateId $TemplateId -JSON $JSON_Output
  Write-Host "[+] '$DisplayName' uploaded." -f Green
  }
}

Function Hardening() {
  Write-Host "[~] The VAST majority of these hardening techniques come from the guru's at Soteria themselves. Theses changes that are made are only those that will NOT break anything; additional changes may need to be made manually. `n" -f Cyan
	Write-Host "[~] To see Soteria's 365-Inspect script in action, download it from here: https://github.com/soteria-security/365Inspect `n" -f Cyan
  Write-Host "[*] Connecting to services..." -f Yellow
  Connect-MsolService
  Write-Host "[+] Connected to Exchange Online." -f Green
	Connect-AzureAD
  Write-Host "[+] Connected to AzureAD." -f Green
	Connect-MicrosoftTeams
  Write-Host "[+] Connected to Teams." -f Green

  # Restricting access to Company Settings via AAD PowerShell
	Write-Host "[*] Restricting AAD PowerShell Principal Agent." -f Yellow
	Set-MsolCompanySettings -UsersPermissionToCreateGroupsEnabled $false
	Set-MsolCompanySettings -UsersPermissionToUserConsentToAppEnabled $false
	Write-Host "[*] Restricting access to create groups." -f Yellow
	Set-MsolCompanySettings -UsersPermissionToCreateGroupsEnabled $false
	Write-Host "[*] Restricting access consent to apps on behalf of organisation." -f Yellow
	Set-MsolCompanySettings -UsersPermissionToUserConsentToAppEnabled $false
	Write-Host "[*] Restricting nosy user permissions." -f Yellow
	Set-MsolCompanySettings -UsersPermissionToReadOtherUsersEnabled $false
	Set-AzureADMSAuthorizationPolicy -DisplayName (Get-AzureADMSAuthorizationPolicy).id -AllowEmailVerifiedUsersToJoinOrganization $false
	Set-AzureADMSAuthorizationPolicy -DisplayName (Get-AzureADMSAuthorizationPolicy).id -AllowedToSignupEmailBasedSubscriptions $false
	Write-Host "[*] Disabling Teams P2P file transfer." -f Yellow
	Set-CsExternalUserCommunicationPolicy -EnableP2PFileTransfer $False
  Write-Host "[*] Additional manual hardening steps required. Run 365-Inspect for remediation steps." -f Yellow
  Write-Host "[+] Automated hardening complete." -f Green
}

#################################
##     Execution Functions     ##
#################################
$Banner = @"
888                                      888
888                                      888
888                                      888
88888b.   .d88b.  88888b.d88b.   .d88b.  88888b.   8888b.  .d8888b   .d88b.
888  88b d88  88b 888  888  88b d8P  Y8b 888  88b      88b 88K      d8P  Y8b
888  888 888  888 888  888  888 88888888 888  888 .d888888  Y8888b. 88888888
888  888 Y88..88P 888  888  888 Y8b.     888 d88P 888  888      X88 Y8b.
888  888  .Y88P.  888  888  888   Y8888  88888P    Y888888  88888P    Y8888
"@
Clear-Host
Write-Host
$Banner
Write-Host
Write-Host

Write-Host "[+] Welcome to HomeBase! Automated hardening program for all things M365/Azure." -f Green
Write-Host
Write-Host "[*] Connecting to services..." -f Yellow

#Auth
#MDMApplication
# DeviceCompliancePolicy
# ManagedAppPolicy
# EndpointSecurityPolicy
# Hardening
Write-Host "[*] Use Resources\Add-ConditinalAccessPolicy.ps1 to deploy " -f Yellow
Write-Host
Write-Host "[~] Script complete. Godspeed, friendo." -f Cyan
Write-Host
#>
