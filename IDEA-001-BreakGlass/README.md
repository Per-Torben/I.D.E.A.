# I.D.E.A. 001 - Break-Glass Emergency Access Accounts

## Overview
Automated creation and configuration of break-glass emergency access accounts in Microsoft Entra ID. Break-glass accounts are critical backup administrator accounts used for emergency access when normal administrative access is compromised or unavailable.

## Scripts

### Create-BreakGlassAccounts.ps1
Complete automated setup of break-glass accounts with interactive menu-driven configuration.

**Key Features:**
- Interactive menu-driven configuration for flexible account management
- Configurable settings menu (account count, FIDO2 keys per account, account prefix)
- Detects existing break-glass accounts or creates new ones
- Selective configuration: FIDO2 keys, CA exclusions, Global Admin role, RMAU protection
- Password complexity validation (16+ characters)
- Registers multiple FIDO2 security keys per account for passwordless authentication
- Automatically excludes accounts from Conditional Access policies
- Assigns Global Administrator role when needed
- Adds accounts to Restricted Management Administrative Units (RMAU) for protection
- Comprehensive logging with automatic cleanup and retention policies

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

### Interactive Setup
```powershell
.\Create-BreakGlassAccounts.ps1
```

The script guides you through:
1. **Settings Configuration** - Configure account count (1-10), FIDO2 keys per account (1-5), and account prefix
2. **Account Detection/Creation** - Find existing break-glass accounts or create new ones
3. **Configuration Menu** - Selectively configure FIDO2 keys, CA exclusions, GA role, and RMAU protection

### Configuration Options

All settings are configured interactively via menus:
- **Account Count**: 1-10 accounts (default: 2)
- **Keys Per Account**: 1-5 FIDO2 keys per account (default: 2)
- **Account Prefix**: Alphanumeric prefix for account names (default: "breakglass-ga")

### Configuration Steps

Select from the menu:
- `[1]` Register FIDO2 security keys
- `[2]` Exclude from Conditional Access policies
- `[3]` Assign Global Administrator role
- `[4]` Add to Restricted Management Administrative Unit (RMAU)
- `[A]` Run all configuration steps in recommended order
- `[Q]` Quit without configuring

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
