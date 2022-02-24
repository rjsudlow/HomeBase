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
#>

param (
	[Parameter(Mandatory = $true,
		HelpMessage = 'Domain name')]
	[string] $Domain,
	[Parameter(Mandatory = $true,
		HelpMessage = 'Pilot Full Name (with spaces)')]
	[string] $PilotDisplayName,
	[Parameter(Mandatory = $true,
		HelpMessage = 'Pilot Username')]
	[string] $PilotUserName,
	[Parameter(Mandatory = $true,
		HelpMessage = 'Pilot group name')]
	[string] $PilotGroup
	#[string[]] $SelectedInspectors = @(),
	#[string[]] $ExcludedInspectors = @()
)

Function Green
{
    process { Write-Host $_ -ForegroundColor Green }
}

Function Red
{
    process { Write-Host $_ -ForegroundColor Red }
}

Function Blue
{
    process { Write-Host $_ -ForegroundColor Blue }
}


Function Connect-MSGraph{
	Write-Output "[*] Connecting to Microsoft Graph. Please login with Admin credentials to guarantee deployment. `n" | Blue
	Connect-MgGraph -Scopes "User.ReadWrite.All","Group.ReadWrite.All"
	Write-Output "[+] Successfully connected with Microsoft Graph. `n" | Green
}

Function Create-PilotUser{
# Create Intune Test User
# Reference: https://docs.microsoft.com/en-us/graph/api/user-post-users?view=graph-rest-1.0&tabs=powershell
# Reference: https://docs.microsoft.com/en-us/powershell/module/microsoft.graph.users/get-mguser?view=graph-powershell-beta
	Write-Output "[*] Creating Pilot User with name of $PilotUserName@$Domain. `n" | Blue
	Import-Module Microsoft.Graph.Users
	$params = @{
		AccountEnabled = $true
		DisplayName = $PilotDisplayName
		MailNickname = $PilotUserName
		UserPrincipalName = "TestUser@$Domain"
		PasswordProfile = @{
			ForceChangePasswordNextSignIn = $true
			Password = "TempPass123**"
		}
	}
	New-MgUser -BodyParameter $params
	Write-Output "[*] Assigning $PilotUserName UID to variable... `n" | Blue
	$PilotUID = Get-MgUser -Filter "displayName eq 'RJ Sudlow'" -Property Id | Format-List ID | cut -d " " -f3
	$PilotUID = '$PilotUID'
	Write-Output "[+] Test User UID is: $PilotUID `n" | Blue
}


Function Create-PilotGroup{
# Create Intune Pilot Group & Assign User to Group
# Reference: https://docs.microsoft.com/en-us/graph/api/group-post-groups?view=graph-rest-1.0&tabs=powershell
	Write-Output "[*] Creating Pilot Group with name of $PilotGroup." | Blue
	Import-Module Microsoft.Graph.Groups
	# Error thrown when trying to apply the MemberURL to the Group via UID
	$MemberURL = 'https://graph.microsoft.com/v1.0/users/'
	$MemberAdded = -join($MemberURL,$PilotUID)
	$MemberAdded
	<#
	$params = @{
		Description = "Group for all users with Intune licenses."
		DisplayName = "Intune Users"
		GroupTypes = @(
		)
		MailEnabled = $false
		SecurityEnabled = $true
		"Members@odata.bind" = @(
			"https://graph.microsoft.com/v1.0/users/"+$PilotUID)
	}
	New-MgGroup -BodyParameter $params
}
#>
}
Connect-MSGraph
Create-PilotUser
Create-PilotGroup
