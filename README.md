# Home Base
![Screenshot](./misc/built-with-powershell.png)
![feature-not-a-bug](./misc/it's-a-feature-not-a-bug.png)

Powershell script used to deploy baseline configurations & best practice hardening for O365, Azure AD, and Azure Tenants. This includes:
* Conditional Access Policies
* Exchange Online Protection Policies
* Intune MDM & MAM
* Application Protection Policies
* Best practice hardening

The script can be used to deploy baseline changes in Greenfield or Brownfield deployment. The process flow creates a test user and group, assigns the test user to the created group, and will deploy all appropriate protections against the created group. This process is completed to prevent any disruption to business operations and locking people out.

Special thanks to Soteria for the great 365-Inspect tool to help identify best practice improvements in all things 365.

## :arrow_down: Download
```
git clone https://github.com/rjsudlow/homebase
```

## :computer: Setup
Setup will check for dependencies at runtime. If any are missing, they will be installed.

## :rocket: Usage
```
.\homebase.ps1
```
You may need to run additional scripts/manually upload to apply baselines. As it stands currently, you will need to perform the current actions:
* Manually create Android MDM Application Protections (iOS works fine and uploads automatically on script execution)
* Use `Resources\ImportSecurityPolicies.ps1` to upload the 3 files located in `EndpointSecurityPolicies`.


## :compass: Roadmap

### AzureAD
* Apply 365Inspect Controls
* :white_check_mark: Create Pilot User (AzureAD)
* :white_check_mark: Create Pilot Group (AzureAD)
* :white_check_mark: Apply Conditional Access (AzureAD)

### Endpoint Manager
* :white_check_mark: Apply Compliance Baselines
  * :white_check_mark: Windows 10
  * :white_check_mark: Android
  * :white_check_mark: iOS
* :white_check_mark: Apply Configuration Policies
* :white_check_mark: Apply MDM/MAM Policies
  * :white_check_mark: iOS
  * :white_check_mark: Android
* :white_check_mark: Apply Application Protection Policies
  * :white_check_mark: iOS
  * :white_check_mark: Android


### M365/Azure/SharePoint/Teams
* Apply 365Inspect Controls


### To Do
* Assign policies and templates to group created as part of script.
* Upload Endpoint Security Policies from folder.


## Disclaimer
>This should go without saying, but this tool is for academic purposes only. I'm not responsible if you want to use this
for nefarious deeds. Please pay special attention to all local, state, and federal laws. Remember:
"With great power comes great responsibility."

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
