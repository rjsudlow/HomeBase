Process flow:
##1. AzureAD
* Apply 365Inspect Controls
* :white_check_mark: Create Pilot User (AzureAD)
* :white_check_mark: Create Pilot Group (AzureAD)
* Apply Conditional Access (AzureAD)
  * Upload JSON file
  * Get ID from Policy
  * Apply Policy to Pilot Group ID
* Apply Compliance Policies
  * Upload JSON file
  * Get ID from Policy
  * Apply Policy to Pilot Group ID
* Apply Configuration Policies
  * Upload JSON file
  * Get ID from Policy
  * Apply Policy to Pilot Group ID

##2. Endpoint Manager
* Apply Compliance Baselines
* Apply Configuration Policies
* Apply MDM
  * Corporate (Android)
  * Corporate (iOS)
  * BOYD (Android)
  * BYOD (iOS)
