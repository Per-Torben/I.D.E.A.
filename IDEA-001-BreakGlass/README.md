# I.D.E.A. 001 – Break‑Glass Emergency Access Accounts

## Overview
Automated creation and configuration of break‑glass emergency access accounts in Microsoft Entra ID.  
These accounts provide guaranteed administrative access when normal access paths are unavailable or compromised.

## Scripts

### `Create-BreakGlassAccounts.ps1`
Complete automated setup of break‑glass accounts with an interactive, menu‑driven workflow.

**Key Features**
- Interactive configuration (account count, FIDO2 keys, account prefix)  
- Detects existing break‑glass accounts or creates new ones  
- Selective configuration: FIDO2 keys, CA exclusions, GA role, RMAU protection  
- Password complexity validation (24+ characters)  
- Registers multiple FIDO2 keys per account  
- Automatically excludes accounts from all Conditional Access policies  
- Assigns Global Administrator role  
- Adds accounts to Restricted Management Administrative Units (RMAU)  
- Comprehensive logging with automatic cleanup and retention  

**Security Benefits**
- Ensures reliable emergency access bypassing Conditional Access  
- Supports password + FIDO2 multi‑factor authentication  
- RMAU protection prevents unauthorized modifications  
- Aligns with Microsoft’s recommended break‑glass practices  
- Reduces risk of tenant lockout  

## Prerequisites
- Microsoft Graph PowerShell SDK  
- `DSInternals.Passkeys` module (auto‑installed)  
- Physical FIDO2 security keys  
- Global Administrator permissions  
- Required Graph API permissions (automatically requested)  

## Usage

### Interactive Setup
```powershell
.\Create-BreakGlassAccounts.ps1
```

The script guides you through:
1. **Settings Configuration** – account count, FIDO2 keys per account, account prefix  
2. **Account Detection/Creation** – find or create break‑glass accounts  
3. **Configuration Menu** – FIDO2 keys, CA exclusions, GA role, RMAU protection  

### Configuration Options
- **Account Count:** 1–10 (default: 2)  
- **Keys Per Account:** 1–5 (default: 2)  
- **Account Prefix:** alphanumeric (default: `breakglass-ga`)  

### Configuration Steps
- `[1]` Register FIDO2 security keys  
- `[2]` Exclude from Conditional Access policies  
- `[3]` Assign Global Administrator role  
- `[4]` Add to RMAU  
- `[A]` Run all recommended steps  
- `[Q]` Quit  

## Logging

The script creates detailed logs of all operations:

**Log Location:** `.\Logs\BreakGlass-YYYY-MM-DD-HHmmss.log`

**Log Features:**
- Timestamped entries for all operations
- Color-coded console output (Info, Success, Warning, Error)
- Automatic log rotation (30-day retention)
- Maximum log size: 10 MB per file
- Logs include: account creation, FIDO2 registration, CA policy updates, role assignments, RMAU operations

**Example Log Entry:**
```
[2026-01-05 12:18:45] [Success] Successfully connected to Microsoft Graph
[2026-01-05 12:19:33] [Info] User confirmed using found break-glass accounts
[2026-01-05 12:29:37] [Info] User exited configuration menu
```

## Best Practices
- Maintain at least two break‑glass accounts  
- Store passwords securely offline  
- Register multiple FIDO2 keys per account  
- [Test emergency access procedures regularly](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access#validate-accounts-regularly)  
- Document account details securely  
- Exclude from **all** Conditional Access policies  
- Enable RMAU protection  
- Monitor sign‑ins for anomalies  

## Security Considerations
- Accounts have Global Administrator privileges  
- Passwords must be at least 24 characters and stored securely offline  
- FIDO2 keys should be stored securely and separately  
- Audit usage regularly  
- Consider alerting on any break‑glass sign‑in  

## Author
Per‑Torben Sørensen with contributions from GitHub Copilot

## Version
2.0 — Last Updated: January 5, 2026

## References
- Microsoft Emergency Access Best Practices  
