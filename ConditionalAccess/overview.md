# Conditional Access

## Require MFA for all Administrators
Users:
Cloud Apps:
Conditions -
    Client Apps:
    Device Platforms:
    Locations:
Block Access

## Require MFA for users outside of Trusted Locations
Users:
Cloud Apps:
Conditions -
    Client Apps:
    Device Platforms:
    Locations:
Block Access

## Require App Protection Policy for Mobile Devices
Users:
Cloud Apps:
Conditions -
    Client Apps:
    Device Platforms:
    Locations:
Block Access

## Disable Legacy Authentication
Users: All (Create exclusions as needed)
Cloud Apps: Office 365 Exchange Online
Conditions -
    Client Apps : Select Exchange ActiveSync Clients, Select Other Clients
    Device Platforms: Any
    Locations: Any
Block Access

## Restrict Access to AAD for Non-Administrators
Users: All and Exclude Directory Role Global Administrator (and/or other admin roles)
Cloud Apps: Microsoft Azure Management
Conditions —
    Device Platforms — Any
    Locations — Any
Block Access
