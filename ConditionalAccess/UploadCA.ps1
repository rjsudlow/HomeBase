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

Connect-MgGraph -Scopes "Application.Read.All,Group.Read.All,Directory.Read.All,Policy.Read.All,Policy.Read.ConditionalAccess,Policy.ReadWrite.ConditionalAccess,RoleManagement.Read.All,RoleManagement.Read.Directory,User.Read.All"
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
