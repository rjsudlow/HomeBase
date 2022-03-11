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
	Connect-MgGraph -Scopes "User.ReadWrite.All","Group.ReadWrite.All,Application.Read.All,Group.Read.All,Directory.Read.All,Policy.Read.All,Policy.Read.ConditionalAccess,Policy.ReadWrite.ConditionalAccess,RoleManagement.Read.All,RoleManagement.Read.Directory,User.Read.All"
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
	$GroupID = (Get-MgGroup -Filter "displayName eq '$PilotGroup'").Id
	$global:GroupID = $GroupID
	Write-Output "[+] UID for group is: $GroupID `n" | Green
}

Function Import-ComplianceJSON{

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
	Global Administrator                       62e90394-69f5-4237-9190-012177145e10
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

Connect-MSGraph
Create-User
Create-Group
DeployConditionalAccess
