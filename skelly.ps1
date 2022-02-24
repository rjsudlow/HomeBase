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

Function Create-User{
	# Create Intune Test User
	# Reference: https://docs.microsoft.com/en-us/graph/api/user-post-users?view=graph-rest-1.0&tabs=powershell
	# Reference: https://docs.microsoft.com/en-us/powershell/module/microsoft.graph.users/get-mguser?view=graph-powershell-beta
	#Import-Module Microsoft.Graph.Users
	Write-Output "[*] Creating Pilot User with name of $PilotUserName@$Domain. `n" | Blue
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
	Write-Output "[*] Assigning $PilotUserName UID to variable... `n" | Blue
	# Appropriate way to get UID as variable:
	# $test = (Get-MgUser -Filter "displayName eq 'RJ Sudlow'" -Property Id).Id
	$PilotUID = (Get-MgUser -Filter "displayName eq '$PilotDisplayName'").Id
	$global:PilotUID = $PilotUID
	Write-Output "[+] UID for new user is: $PilotUID `n" | Green
}

Function Create-Group{
	#Import-Module Microsoft.Graph.Groups
	# Create Intune Pilot Group & Assign User to Group
	# Reference: https://docs.microsoft.com/en-us/graph/api/group-post-groups?view=graph-rest-1.0&tabs=powershell
	Write-Output "[*] Creating group..." | Blue
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
	$GroupID = (Get-MgGroup -Filter "displayName eq '$PilotGroupNickname'").Id
	$global:GroupID = $GroupID
	Write-Output "[+] UID for group is: $GroupID `n" | Green
}

Function Import-ComplianceJSON{

}

Connect-MSGraph
Create-User
Create-Group
