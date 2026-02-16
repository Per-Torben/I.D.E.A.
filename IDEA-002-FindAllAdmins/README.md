# I.D.E.A. 002 – Find All Admins

## Overview
Comprehensive discovery and reporting of all administrative role assignments in Microsoft Entra ID.  
Identifies users with elevated privileges to help maintain security hygiene and comply with least privilege principles.

## Scripts

### `Find-AllAdmins.ps1`
Complete discovery of all Entra ID role assignments with flexible reporting options.

**Key Features**
- Discovers all directory role assignments (built-in and custom roles)
- Includes PIM (Privileged Identity Management) eligible assignments
- Identifies group-based role assignments
- Exports to multiple formats (CSV, JSON, console)
- Filters by role name or privilege level
- Shows last sign-in activity for admin accounts
- Identifies dormant or stale admin accounts
- Comprehensive logging

**Security Benefits**
- Visibility into all elevated privilege assignments
- Helps identify excessive admin permissions
- Supports regular admin access reviews
- Aids in compliance and audit reporting
- Detects potential security risks (dormant admins, over-privileged accounts)

## Prerequisites
- Microsoft Graph PowerShell SDK
- Required Graph API permissions (automatically requested):
  - `RoleManagement.Read.Directory`
  - `Directory.Read.All`
  - `AuditLog.Read.All` (for sign-in activity)
- Security Reader or higher permissions

## Usage

### Basic Discovery
```powershell
# Discover all admin role assignments
.\Find-AllAdmins.ps1

# Export to CSV
.\Find-AllAdmins.ps1 -ExportPath ".\exports\admins.csv"

# Include PIM eligible assignments
.\Find-AllAdmins.ps1 -IncludePIM

# Filter by specific roles
.\Find-AllAdmins.ps1 -RoleFilter "Global Administrator","Privileged Role Administrator"

# Find dormant admin accounts (no sign-in in 90 days)
.\Find-AllAdmins.ps1 -ShowDormant -DormantDays 90
```

### Interactive Mode
```powershell
.\Find-AllAdmins.ps1 -Interactive
```

The script guides you through:
1. **Scope Selection** – All roles or specific roles
2. **Output Options** – Console, CSV, JSON, or HTML
3. **Filters** – PIM, dormant accounts, group-based assignments

## Output

### Console Display
- Formatted table showing: User, Role, Assignment Type, Last Sign-In
- Summary statistics (total admins, roles, dormant accounts)

### CSV Export
- Full details for import into Excel or other tools
- Columns: UserPrincipalName, DisplayName, RoleName, AssignmentType, LastSignIn, AccountEnabled

### JSON Export
- Machine-readable format for automation and integration
- Complete assignment details including PIM settings

## Security Considerations
- Run regularly to maintain admin hygiene
- Review dormant admin accounts for potential removal
- Validate group-based assignments follow least privilege
- Monitor PIM eligible assignments for appropriate justification
- Use results for periodic access reviews
- Consider revoking unnecessary admin privileges

## Configuration Options
- **Role Filters**: Focus on specific critical roles
- **Dormant Threshold**: Define inactive period (default: 90 days)
- **Export Path**: Customize output location
- **Include Groups**: Show group-based role assignments
- **PIM Details**: Expand eligible assignment settings

## Examples

### Find all Global Administrators
```powershell
.\Find-AllAdmins.ps1 -RoleFilter "Global Administrator" -ExportPath ".\ga-admins.csv"
```

### Security audit - find dormant admins
```powershell
.\Find-AllAdmins.ps1 -ShowDormant -DormantDays 60 -ExportPath ".\dormant-admins.csv"
```

### Complete PIM report
```powershell
.\Find-AllAdmins.ps1 -IncludePIM -ExportFormat JSON -ExportPath ".\pim-assignments.json"
```

## Notes
- Sign-in activity requires AuditLog.Read.All permission
- PIM data requires additional PIM read permissions
- Large tenants may take several minutes to complete discovery
- Results are point-in-time snapshots

## Author
Per-Torben Sørensen with contributions from GitHub Copilot

## Version
1.0 - Initial Release

## Last Updated
February 16, 2026
