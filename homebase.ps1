<#
  .SYNOPSIS
  Deploys KISS Office 365 and AzureAD baselines.
  .DESCRIPTION
  Automate the deployment of new and existing Office 365 and Azure AD instances.
  .PARAMETER Domain
  Enter the domain in use.
  .PARAMETER PilotUserName
  Enter the pilot user's username.
  .PARAMETER PilotGroup
	Enter the pilot group's name.
  .INPUTS
  No inputs are available. Please select info during initial deployment.
  .OUTPUTS
  None. 365Inspect.ps1 does not generate any output.
  .EXAMPLE
  PS> .\insertpowershellnamehere.ps1
	.NOTES
	 Version:        0.1
	 Author:         RJ Sudlow
	 Creation Date:  24/02/2022
#>

param (
	[Parameter(Mandatory = $true,
		HelpMessage = '`nDomain name')]
	[string] $Domain,
	[Parameter(Mandatory = $true,
		HelpMessage = '`nPilot Full Name (with spaces)')]
	[string] $PilotDisplayName,
	[Parameter(Mandatory = $true,
		HelpMessage = '`nPilot Username (No Spaces)')]
	[string] $PilotUserName,
	[Parameter(Mandatory = $true,
		HelpMessage = '`nPilot group name')]
	[string] $PilotGroup,
	[Parameter(Mandatory = $true,
		HelpMessage = '`nPilot group mail nickname (No Spaces)')]
	[string] $PilotGroupNickname
)

Function Connect-MSGraph{
	# Simple single connect function.
	Write-Host "[*] Connecting to Microsoft Graph. Please login with Admin credentials to guarantee deployment. `n" -ForegroundColor Yellow
	Connect-MgGraph -Scopes "User.ReadWrite.All","Group.ReadWrite.All,Application.Read.All,Group.Read.All,Directory.Read.All,Policy.Read.All,Policy.Read.ConditionalAccess,Policy.ReadWrite.ConditionalAccess,RoleManagement.Read.All,RoleManagement.Read.Directory,User.Read.All"
	Write-Host "[+] Successfully connected with Microsoft Graph. `n" -ForegroundColor Green
}

Function Create-User{
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

Function Create-Group{
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

Function Test-JSON(){
	#Function taken from Microsoft PowerShell examples
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

Function Get-EndpointSecurityTemplate(){

	<#
	.SYNOPSIS
	This function is used to get all Endpoint Security templates using the Graph API REST interface
	.DESCRIPTION
	The function connects to the Graph API Interface and gets all Endpoint Security templates
	.EXAMPLE
	Get-EndpointSecurityTemplate
	Gets all Endpoint Security Templates in Endpoint Manager
	.NOTES
	NAME: Get-EndpointSecurityTemplate
	#>

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

Function Add-DeviceCompliancePolicy(){
	#Function taken from Microsoft PowerShell examples
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

Function DeployConditionalAccess{
	<#
	References:
	===========
	Permissions: https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference
	Grant Types: https://github.com/microsoftgraph/microsoft-graph-docs/blob/main/api-reference/v1.0/resources/conditionalaccessgrantcontrols.md
	CA Resource Types (1): https://github.com/Azure-Samples/azure-ad-conditional-access-apis/blob/main/01-configure/graphapi/readme.md
	CA Resource Types (2): https://docs.microsoft.com/en-us/graph/api/resources/conditionalaccessgrantcontrols?view=graph-rest-1.0

	RBAC ID's
	===========
	Application Administrator                 9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3
	Authentication Administrator              c4e39bd9-1100-46d3-8c65-fb160da0071f
	Billing Administrator                     b0f54661-2d74-4c50-afa3-1ec803f12efe
	Cloud App Security Administrator          892c5842-a9a6-463a-8041-72aa08ca3cf6
	Conditional Access Administrator          b1be1c3e-b65d-4f19-8427-f6fa0d97feb9
	Exchange Administrator                    29232cdf-9323-42fd-ade2-1d097af3e4de
	Global Administrator                      62e90394-69f5-4237-9190-012177145e10
	Helpdesk Administrator                    729827e3-9c14-49f7-bb1b-9608f156bbb8
	Password Administrator                    966707d0-3269-4727-9be2-8c3a10f19b9d
	Privileged Authentication Administrator   7be44c8a-adaf-4e2a-84d6-ab2649e08a13
	Privileged Role Administrator             e8611ab8-c189-46e8-94e1-60213ab1f814
	Security Administrator                    194ae4cb-b126-40b2-bd5b-6091b380977d
	SharePoint Administrator                  f28a1f50-f6e7-4571-818b-6a12f2af6b6c
	User Administrator                        fe930be7-5e62-47db-91af-98c3a49a38b1
	#>

	#Connect-MgGraph -Scopes "Application.Read.All,Group.Read.All,Directory.Read.All,Policy.Read.All,Policy.Read.ConditionalAccess,Policy.ReadWrite.ConditionalAccess,RoleManagement.Read.All,RoleManagement.Read.Directory,User.Read.All"
	Import-Module Microsoft.Graph.Identity.SignIns

	# Require MFA for all Adminsitrators
	$params = @{
		DisplayName = "TEST: Require MFA for All Administrators"
		State = "enabled"
		Conditions = @{
			ClientAppTypes = @(
				"All"
			)
			Applications = @{
				IncludeApplications = @(
					"All"
				)
			}
			Users = @{
				IncludeGroups = @(
					"$GroupID"
				)
				IncludeRoles = @(
					"9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
	        "c4e39bd9-1100-46d3-8c65-fb160da0071f",
	        "b0f54661-2d74-4c50-afa3-1ec803f12efe",
	        "892c5842-a9a6-463a-8041-72aa08ca3cf6",
	        "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
	        "29232cdf-9323-42fd-ade2-1d097af3e4de",
	        "62e90394-69f5-4237-9190-012177145e10",
	        "729827e3-9c14-49f7-bb1b-9608f156bbb8",
	        "966707d0-3269-4727-9be2-8c3a10f19b9d",
	        "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
	        "e8611ab8-c189-46e8-94e1-60213ab1f814",
	        "194ae4cb-b126-40b2-bd5b-6091b380977d",
	        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
	        "fe930be7-5e62-47db-91af-98c3a49a38b1"
				)
	      ExcludeUsers = @(
	        "7b5a017f-ec2b-4d4b-a600-429a4fcb9e3b" # Change this to breakglass account
	      )
			}
			Locations = @{
				IncludeLocations = @(
					"All"
				)
			}
		}
	  GrantControls = @{
			Operator = "OR"
			BuiltInControls = @(
				"mfa"
			)
		}
	}
	New-MgIdentityConditionalAccessPolicy -BodyParameter $params

	# Require MFA for users outside of Trusted Locations
	$params = @{
		DisplayName = "TEST: Require MFA for users outside of Trusted Locations"
		State = "enabled"
		Conditions = @{
			ClientAppTypes = @(
				"All"
			)
			Applications = @{
				IncludeApplications = @(
					"All"
				)
			}
			Users = @{
				IncludeGroups = @(
					"$GroupID"
				)
				IncludeUsers = @(
					"All"
				)
	      ExcludeUsers = @(
	        "7b5a017f-ec2b-4d4b-a600-429a4fcb9e3b" # Change this to breakglass account
	      )
			}
			Locations = @{
				IncludeLocations = @(
					"All"
				)
	    ExcludeLocations = @(
				"AllTrusted"
			)
	    }
		}
	  GrantControls = @{
			Operator = "OR"
			BuiltInControls = @(
				"mfa"
			)
		}
	}
	New-MgIdentityConditionalAccessPolicy -BodyParameter $params

	# Require App Protection policy for mobile devices
	$params = @{
		DisplayName = "TEST: Require App Protection policy for mobile devices"
		State = "enabled"
		Conditions = @{
			ClientAppTypes = @(
				"All"
			)
			Applications = @{
				IncludeApplications = @(
					"All"
				)
			}
			Users = @{
				IncludeGroups = @(
					"$GroupID"
				)
				IncludeUsers = @(
					"All"
				)
	      ExcludeUsers = @(
	        "7b5a017f-ec2b-4d4b-a600-429a4fcb9e3b" # Change this to breakglass account
	      )
			}
	    Platforms = @{
				IncludePlatforms = @(
					"iOS",
	        "Android"
				)
			}
	    Locations = @{
				IncludeLocations = @(
					"All"
				)
	    ExcludeLocations = @(
				"AllTrusted"
			)
	    }
		}
	  GrantControls = @{
			Operator = "OR"
			BuiltInControls = @(
				"compliantApplication"
			)
		}
	}
	New-MgIdentityConditionalAccessPolicy -BodyParameter $params

	# Disable legacy authentication
	$params = @{
		DisplayName = "TEST: Disable legacy authentication"
		State = "enabled"
		Conditions = @{
			ClientAppTypes = @(
				"exchangeActiveSync",
	      "other"
			)
			Applications = @{
				IncludeApplications = @(
					"All"
				)
			}
			Users = @{
				IncludeGroups = @(
					"$GroupID"
				)
				IncludeUsers = @(
					"All"
				)
	      ExcludeUsers = @(
	        "7b5a017f-ec2b-4d4b-a600-429a4fcb9e3b" # Change this to breakglass account
	      )
			}
	    Platforms = @{
				IncludePlatforms = @(
					"All"
				)
			}
	    Locations = @{
				IncludeLocations = @(
					"All"
				)
	    }
		}
	  GrantControls = @{
			Operator = "OR"
			BuiltInControls = @(
				"block"
			)
		}
	}
	New-MgIdentityConditionalAccessPolicy -BodyParameter $params

	# Disable AAD for non-administrators
	$params = @{
		DisplayName = "TEST: Restrict access to AAD for non-administrators"
		State = "enabledForReportingButNotEnforced"
		Conditions = @{
			ClientAppTypes = @(
				"All"
			)
			Applications = @{
				IncludeApplications = @(
					"797f4846-ba00-4fd7-ba43-dac1f8f63013" # Microsoft Azure Management
				)
			}
			Users = @{
				IncludeGroups = @(
					"$GroupID"
							)
				IncludeUsers = @(
					"All"
				)
	      ExcludeUsers = @(
	        "7b5a017f-ec2b-4d4b-a600-429a4fcb9e3b" # Change this to breakglass account
	      )
			}
	    Platforms = @{
				IncludePlatforms = @(
					"All"
				)
			}
	    Locations = @{
				IncludeLocations = @(
					"All"
				)
	    }
		}
	  GrantControls = @{
			Operator = "OR"
			BuiltInControls = @(
				"block"
			)
		}
	}
	New-MgIdentityConditionalAccessPolicy -BodyParameter $params
}

Function Apply-Hardening(){

}

Function Apply-EndpointSecurity() {
	# Export function found here: https://github.com/microsoftgraph/powershell-intune-samples/blob/master/EndpointSecurity/EndpointSecurityPolicy_Export.ps1
	  [cmdletbinding()]
	  param
	  (
	      $TemplateId,
	      $JSON
	  )

	  $graphApiVersion = "Beta"
	  $ESP_resource = "deviceManagement/templates/$TemplateId/createInstance"
	  Write-Verbose "Resource: $ESP_resource"

	      try {
	          if($JSON -eq "" -or $JSON -eq $null){
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

Connect-MSGraph
<#
Create-User
Create-Group
DeployConditionalAccess

# Upload Compliance Policies from folder
$CompliancePolicyPath = ".\CompliancePolicies"
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
$MAMPath = ".\MDMApplications-iOS"
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
$AppProtectionPath = ".\ManagedApplicationPolicies"
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
#>

# Get Templates for Endpoint Security policies
Function Get-EndpointSecurityTemplate(){

	<#
	.SYNOPSIS
	This function is used to get all Endpoint Security templates using the Graph API REST interface
	.DESCRIPTION
	The function connects to the Graph API Interface and gets all Endpoint Security templates
	.EXAMPLE
	Get-EndpointSecurityTemplate
	Gets all Endpoint Security Templates in Endpoint Manager
	.NOTES
	NAME: Get-EndpointSecurityTemplate
	#>


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

####################################################

Function Add-EndpointSecurityPolicy(){

  <#
  .SYNOPSIS
  This function is used to add an Endpoint Security policy using the Graph API REST interface
  .DESCRIPTION
  The function connects to the Graph API Interface and adds an Endpoint Security  policy
  .EXAMPLE
  Add-EndpointSecurityDiskEncryptionPolicy -JSON $JSON -TemplateId $templateId
  Adds an Endpoint Security Policy in Endpoint Manager
  .NOTES
  NAME: Add-EndpointSecurityPolicy
  #>

  [cmdletbinding()]

  param
  (
      $TemplateId,
      $JSON
  )

  $graphApiVersion = "Beta"
  $ESP_resource = "deviceManagement/templates/$TemplateId/createInstance"
  Write-Verbose "Resource: $ESP_resource"

      try {

          if($JSON -eq "" -or $JSON -eq $null){

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

<#
$JSON_Data = gc "$ImportPath"
$JSON_Convert = $JSON_Data | ConvertFrom-Json
$JSON_DN = $JSON_Convert.displayName
$JSON_TemplateDisplayName = $JSON_Convert.TemplateDisplayName
$JSON_TemplateId = $JSON_Convert.templateId

Write-Host
Write-Host "Endpoint Security Policy '$JSON_DN' found..." -ForegroundColor Cyan
Write-Host "Template Display Name: $JSON_TemplateDisplayName"
Write-Host "Template ID: $JSON_TemplateId"
#>
####################################################

# Get all Endpoint Security Templates
$Templates = Get-EndpointSecurityTemplate

####################################################

# Checking if templateId from JSON is a valid templateId
$ES_Template = $Templates | ?  { $_.id -eq $JSON_TemplateId }

####################################################

# If template is a baseline Edge, MDATP or Windows, use templateId specified
if(($ES_Template.templateType -eq "microsoftEdgeSecurityBaseline") -or ($ES_Template.templateType -eq "securityBaseline") -or ($ES_Template.templateType -eq "advancedThreatProtectionSecurityBaseline")){

    $TemplateId = $JSON_Convert.templateId

}

####################################################

# Else If not a baseline, check if template is deprecated
elseif($ES_Template){

    # if template isn't deprecated use templateId
    if($ES_Template.isDeprecated -eq $false){

        $TemplateId = $JSON_Convert.templateId

    }

    # If template deprecated, look for lastest version
    elseif($ES_Template.isDeprecated -eq $true) {

        $Template = $Templates | ? { $_.displayName -eq "$JSON_TemplateDisplayName" }

        $Template = $Template | ? { $_.isDeprecated -eq $false }

        $TemplateId = $Template.id

    }

}

####################################################

# Else If Imported JSON template ID can't be found check if Template Display Name can be used
elseif($ES_Template -eq $null){

    Write-Host "Didn't find Template with ID $JSON_TemplateId, checking if Template DisplayName '$JSON_TemplateDisplayName' can be used..." -ForegroundColor Red
    $ES_Template = $Templates | ?  { $_.displayName -eq "$JSON_TemplateDisplayName" }

    If($ES_Template){

        if(($ES_Template.templateType -eq "securityBaseline") -or ($ES_Template.templateType -eq "advancedThreatProtectionSecurityBaseline")){

            Write-Host
            Write-Host "TemplateID '$JSON_TemplateId' with template Name '$JSON_TemplateDisplayName' doesn't exist..." -ForegroundColor Red
            Write-Host "Importing using the updated template could fail as settings specified may not be included in the latest template..." -ForegroundColor Red
            Write-Host
            break

        }

        else {

            Write-Host "Template with displayName '$JSON_TemplateDisplayName' found..." -ForegroundColor Green

            $Template = $ES_Template | ? { $_.isDeprecated -eq $false }

            $TemplateId = $Template.id

        }

    }

    else {

        Write-Host
        Write-Host "TemplateID '$JSON_TemplateId' with template Name '$JSON_TemplateDisplayName' doesn't exist..." -ForegroundColor Red
        Write-Host "Importing using the updated template could fail as settings specified may not be included in the latest template..." -ForegroundColor Red
        Write-Host
        break

    }

}

####################################################


# Upload Endpoint Security Policies
$EndpointSecurityPath = ".\EndpointSecurityPolicies"
Get-ChildItem $EndpointSecurityPath | Foreach-Object {
	$JSON_Data = Get-Content "$EndpointSecurityPath\$_"
	$JSON_Convert = $JSON_Data | ConvertFrom-Json
	$JSON_DN = $JSON_Convert.displayName
	$JSON_TemplateDisplayName = $JSON_Convert.TemplateDisplayName
	$JSON_TemplateId = $JSON_Convert.templateId
	Write-Host "Endpoint Security Policy '$JSON_DN' found..." -ForegroundColor Cyan
	# Excluding certain properties from JSON that aren't required for import
	$JSON_Convert = $JSON_Convert | Select-Object -Property * -ExcludeProperty TemplateDisplayName,TemplateId,versionInfo
	$DisplayName = $JSON_Convert.displayName
	$JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 5
	Write-Host "Adding Endpoint Security Policy '$DisplayName'" -ForegroundColor Yellow
	Add-EndpointSecurityPolicy -TemplateId $TemplateId -JSON $JSON_Output
}
