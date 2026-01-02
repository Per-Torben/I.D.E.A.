# I.D.E.A.
A curated collection of small, practical Identity Engineering Artifacts (I.D.E.A.) for Entra and identity security. Each artifact is a self-contained script with clear documentation, secure defaults, and real-world usefulness.

## Repository Structure
Each I.D.E.A. is organized in its own folder with:
- One or more PowerShell scripts
- Detailed README.md with usage examples
- Clear documentation of prerequisites and security considerations

## Available I.D.E.A.s

### [I.D.E.A. 001 - Break-Glass Emergency Access Accounts](IDEA-001-BreakGlass/)
Interactive menu-driven tool to create and configure break-glass emergency access accounts in Microsoft Entra ID. Break-glass accounts are critical backup administrator accounts that provide emergency access when normal administrative access is compromised or unavailable.

**Key Capabilities:**
- Settings menu for account count, FIDO2 keys, and naming configuration
- Detects existing break-glass accounts or creates new ones with secure passwords
- FIDO2 security key registration for passwordless multi-factor authentication
- Automatic exclusion from all Conditional Access policies to ensure accessibility
- Global Administrator role assignment with validation
- Restricted Management Administrative Unit (RMAU) protection to prevent unauthorized changes

**Use Case:** Prevents tenant lockout scenarios by ensuring at least one reliable administrative access path bypasses all Conditional Access restrictions.

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
- Detailed logging and validation
- Interactive menu-driven configuration
- Secure defaults and best practice implementations

## Author
Per-Torben Sørensen with contributions from Github Copilot

## License
Use at your own risk. Review and test thoroughly before production use.
