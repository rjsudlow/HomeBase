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

#################################
##      Utility Functions      ##
#################################

Function Test-JSON() {
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
}

#################################
##    End Utility Functions    ##
#################################

Function Connect-MSGraph() {
	# Simple connect function for all cascading flows.
	Write-Host "[*] Connecting to Microsoft Graph. Please login with Admin credentials to guarantee deployment. `n" -ForegroundColor Yellow
	Connect-MgGraph -Scopes "User.ReadWrite.All","Group.ReadWrite.All,Application.Read.All,Group.Read.All,Directory.Read.All,Policy.Read.All,Policy.Read.ConditionalAccess,Policy.ReadWrite.ConditionalAccess,RoleManagement.Read.All,RoleManagement.Read.Directory,User.Read.All"
	Write-Host "[+] Successfully connected with Microsoft Graph. `n" -ForegroundColor Green
	#Connect-MsolService
	#Connect-AzureAD
	#Connect-MicrosoftTeams
}

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

Function Add-DeviceCompliancePolicy() {
	#Function taken from Microsoft PowerShell examples
	[cmdletbinding()]
	param($JSON)
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
	}
  break
}

Connect-MSGraph

#################################
##       Upload from JSON      ##
#################################

# Executes from: Add-DeviceCompliancePolicy
$CompliancePolicyPath = ".\CompliancePolicies"
Get-ChildItem $CompliancePolicyPath | Foreach-Object {
  Write-host "File name found: $_ " -ForegroundColor Yellow
  $JSON_Data = Get-Content "$_"
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
