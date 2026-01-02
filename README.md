# I.D.E.A.
A curated collection of small, practical Identity Engineering Artifacts (I.D.E.A.) for Entra and identity security. Each artifact is a self-contained script with clear documentation, secure defaults, and real-world usefulness.

## Repository Structure
Each I.D.E.A. is organized in its own folder with:
- One or more PowerShell scripts
- Detailed README.md with usage examples
- Clear documentation of prerequisites and security considerations

## Available I.D.E.A.s

### [I.D.E.A. 001 - Break-Glass Emergency Access Accounts](IDEA-001-BreakGlass/)
Automated creation and configuration of break-glass emergency access accounts in Microsoft Entra ID.

**Key Features:**
- Interactive menu-driven configuration
- FIDO2 security key registration for passwordless authentication
- Automatic Conditional Access policy exclusions
- Global Administrator role assignment
- Restricted Management Administrative Unit (RMAU) protection
- Comprehensive logging and validation

**Use Case:** Ensure reliable emergency access to your tenant when normal admin access is compromised or unavailable.

[📖 Full Documentation](IDEA-001-BreakGlass/README.md)

---

## Getting Started
1. Browse the I.D.E.A. folders above
2. Read the specific README.md for prerequisites and usage
3. Run scripts with appropriate permissions
4. Follow security best practices outlined in each I.D.E.A.

## Prerequisites
- PowerShell 7.0 or later
- Microsoft Graph PowerShell SDK
- Appropriate permissions in Microsoft Entra ID

## Contributing
Each I.D.E.A. is developed with security and practical utility in mind. Scripts include:
- Comprehensive error handling
- WhatIf support for safe testing
- Detailed logging
- Interactive configuration options

## Author
Per-Torben Sørensen with contributions from Github Copilot

## License
Use at your own risk. Review and test thoroughly before production use.
