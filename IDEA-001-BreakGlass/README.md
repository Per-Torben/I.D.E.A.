# I.D.E.A. 001 - Break-Glass Emergency Access Accounts

## Overview
Automated creation and configuration of break-glass emergency access accounts in Microsoft Entra ID. Break-glass accounts are critical backup administrator accounts used for emergency access when normal administrative access is compromised or unavailable.

## Scripts

### Create-BreakGlassAccounts.ps1
Complete automated setup of break-glass accounts with interactive menu-driven configuration.

**Key Features:**
- Interactive menu for flexible account management
- Detects existing break-glass accounts or creates new ones
- Selective configuration: FIDO2 keys, CA exclusions, Global Admin role, RMAU protection
- Password complexity validation (16+ characters)
- Registers multiple FIDO2 security keys per account for passwordless authentication
- Automatically excludes accounts from Conditional Access policies
- Assigns Global Administrator role when needed
- Adds accounts to Restricted Management Administrative Units (RMAU) for protection
- Comprehensive logging with automatic cleanup and retention policies
- WhatIf support for safe testing

**Security Benefits:**
- Provides reliable emergency access bypassing Conditional Access restrictions
- Uses multiple authentication factors (password + FIDO2 keys)
- RMAU protection prevents unauthorized account modifications
- Follows Microsoft's recommended break-glass account practices
- Prevents potential lockout scenarios in tenant security configurations

## Prerequisites
- Microsoft Graph PowerShell SDK
- DSInternals.Passkeys module (auto-installed)
- Physical FIDO2 security keys for registration
- Global Administrator permissions in the tenant
- Required Graph API permissions (automatically requested)

## Usage

### Basic Interactive Setup
```powershell
.\Create-BreakGlassAccounts.ps1
```

### Custom Configuration
```powershell
# Create 3 accounts with 1 FIDO2 key each
.\Create-BreakGlassAccounts.ps1 -AccountCount 3 -KeysPerAccount 1

# Test run without making changes
.\Create-BreakGlassAccounts.ps1 -WhatIf

# Skip FIDO2 registration
.\Create-BreakGlassAccounts.ps1 -SkipFIDO2
```

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `AccountCount` | int | 2 | Number of break-glass accounts to create |
| `KeysPerAccount` | int | 2 | Number of FIDO2 keys to register per account |
| `AccountPrefix` | string | "breakglass-ga" | Prefix for the account names |
| `WhatIf` | switch | - | Show what would be done without making changes |
| `SkipFIDO2` | switch | - | Skip FIDO2 key registration |
| `ConfigFile` | string | - | Path to configuration file |

## Best Practices
- Create at least 2 break-glass accounts for redundancy
- Store passwords securely in a physical safe or secure location
- Register multiple FIDO2 keys per account
- Test emergency access procedures regularly
- Document account details in a secure, offline location
- Exclude from ALL Conditional Access policies
- Enable RMAU protection to prevent unauthorized modifications
- Monitor account usage for security incidents

## Security Considerations
- These accounts have Global Administrator privileges - protect accordingly
- Passwords should be complex (16+ characters) and stored securely offline
- FIDO2 keys should be stored in secure, physically separate locations
- Regular auditing of break-glass account usage is essential
- Consider alerting on any break-glass account sign-in activity

## Author
Per-Torben Sørensen with contributions from Github Copilot

## Version
2.0 - Last Updated: January 2, 2026

## References
- [Microsoft Emergency Access Best Practices](https://docs.microsoft.com/en-us/azure/active-directory/roles/security-emergency-access)
