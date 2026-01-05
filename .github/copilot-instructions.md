# GitHub Copilot Instructions

- No sugarcoating, always be direct and honest.
- Be concise and direct. Minimal context unless troubleshooting.
- Focus on essential technical facts only.
- Avoid excessive explanations, lists, or detailed summaries.

## Git Workflow Expectations
- **ALWAYS work in local feature branches** - never commit directly to main
- **NEVER push feature branches** to remote - keep them local only
- Only merge to main locally when work is complete and tested
- Only push to origin/main when ready to publish changes
- Copilot executes git operations (add, commit, push, branch, merge) when explicitly requested
- Commands like "push to git", "commit changes", "create branch" trigger git operations
- Always use descriptive commit messages summarizing the changes
- Test scripts thoroughly before merging to main
- Never suggest pushing untested code

### Standard Workflow Pattern
```powershell
# 1. Create local feature branch
git checkout -b feature/description

# 2. Work and commit locally (branch stays local)
git add .
git commit -m "Descriptive message"

# 3. Test thoroughly
.\Your-Script.ps1
Invoke-Pester -Path .\tests -Output Detailed

# 4. When complete, merge to main locally
git checkout main
git merge feature/description

# 5. Only push main when ready to publish
git push origin main

# 6. Delete local feature branch
git branch -d feature/description
```

### Branch Naming Conventions
- Features: `feature/description`
- Bug fixes: `fix/description`
- Documentation: `docs/description`
- Examples: `feature/add-teams-module`, `fix/ca-policy-validation`, `docs/update-readme`

## Repository Structure

This repository contains Identity Engineering Artifacts (I.D.E.A.) - self-contained PowerShell scripts for Entra ID administration.

### I.D.E.A. Organization Pattern
Each I.D.E.A. must be in its own numbered folder:

```
I.D.E.A/
├── README.md                          # Main catalog listing all I.D.E.A.s
├── IDEA-001-BreakGlass/
│   ├── Create-BreakGlassAccounts.ps1  # One or more scripts
│   └── README.md                       # Detailed documentation
├── IDEA-002-ConditionalAccess/
│   ├── Script1.ps1
│   ├── Script2.ps1
│   └── README.md
└── ...
```

### I.D.E.A. Folder Requirements
- **Naming**: `IDEA-XXX-Description/` (e.g., `IDEA-001-BreakGlass/`)
- **Scripts**: One or more `.ps1` files with descriptive names
- **README.md**: Must include:
  - Overview of the I.D.E.A.
  - Script descriptions and features
  - Prerequisites
  - Usage examples with parameters
  - Security considerations
  - Author and version information
- **Root README.md**: Update with new I.D.E.A. entry including link and description

### When Creating New I.D.E.A.s
1. Determine next sequential number (e.g., if 001 exists, create 002)
2. Create folder: `IDEA-XXX-Description/`
3. Add script(s) to the folder
4. Create comprehensive `IDEA-XXX-Description/README.md`
5. Update root `README.md` with new I.D.E.A. entry and link
6. Work in feature branch, test thoroughly, merge to main when complete

## Reference Resources
- **Graph API Overview**: https://learn.microsoft.com/graph/api/overview
- **Conditional Access API**: https://learn.microsoft.com/graph/api/resources/conditionalaccesspolicy
- **PowerShell Best Practices**: https://learn.microsoft.com/powershell/scripting/developer/cmdlet/required-development-guidelines
- **Microsoft Graph PowerShell SDK**: https://learn.microsoft.com/powershell/microsoftgraph/
- **Entra Identity Governance**: https://learn.microsoft.com/entra/id-governance/

## Script Development and Testing Requirements

### CRITICAL: Test Before Claiming Complete
- **NEVER EVER claim a script is "ready", "complete", "working", or "corrected" without ACTUALLY TESTING it first**
- **NEVER say "The script is now fixed" or "All set to 21 days" without running it end-to-end**
- All new scripts MUST be tested in the actual environment before delivery
- All modified scripts MUST be re-tested completely after ANY code change
- If a script fails during testing, fix it and re-test until it works
- Document any assumptions, limitations, or known issues discovered during testing
- **VIOLATION OF THIS RULE IS UNACCEPTABLE AND WASTES USER TIME**

### Testing Workflow
1. **Create** the script with proper error handling
2. **Write Pester tests** for reusable functions (see Pester Testing Standards below)
3. **Test** the script by running it in the terminal
4. **Run Pester tests** if applicable: `Invoke-Pester -Path .\tests -Output Detailed`
5. **Fix** any errors or issues discovered
6. **Re-test** until the script executes successfully and all tests pass
7. **Document** usage and any special requirements in README
8. **Only then** claim the script is ready for use

### What to Test
- **Script execution**: Does it run without errors?
- **Required modules**: Are they available or auto-installed?
- **Authentication**: Does the auth method actually work?
- **Core functionality**: Does it perform the intended task?
- **Error handling**: Do errors produce helpful messages?
- **Edge cases**: Token expiration, missing files, permission issues
- **Pester tests**: Do all unit tests pass for reusable functions?

### Testing Examples
```powershell
# Good: Test the script immediately after creation
.\New-Script.ps1

# If it fails, fix and re-test
.\New-Script.ps1

# Test with different parameters
.\New-Script.ps1 -CustomParam "value"
```

### Red Flags - Do NOT Skip Testing
- Scripts using APIs you haven't verified work
- Authentication methods not previously validated
- Complex token extraction or manipulation logic
- Module requirements without version verification
- Assumptions about SDK behavior without confirmation

### CRITICAL: Validation Anti-Patterns - Prevent False Positives

**The "Premature Celebration" Anti-Pattern**
The most dangerous error handling pattern is showing success messages when operations actually failed. This creates false confidence and wastes user time.

**❌ WRONG - False Positive Pattern:**
```powershell
# This shows "✓ Success" even after throwing errors!
try {
    Connect-MgGraph -AccessToken $token
    try {
        $test = Get-MgOrganization -ErrorAction Stop
        if (!$test) { throw "Failed to get organization" }
    }
    catch {
        throw "Connection test failed: $_"
    }
    # This executes even after the inner throw!
    Write-Host "✓ Successfully connected to Microsoft Graph" -ForegroundColor Green
}
catch {
    Write-Host "Error: $_" -ForegroundColor Red
    exit 1
}
```

**✅ CORRECT - Validate Before Success:**
```powershell
# Only show success after validating all operations completed
try {
    Connect-MgGraph -AccessToken $token -NoWelcome -ErrorAction Stop
    
    # Validate context exists
    $context = Get-MgContext
    if (-not $context -or -not $context.TenantId) {
        throw "Connection failed - unable to establish Microsoft Graph context"
    }
    
    # Validate actual connectivity
    $testOrg = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
    if (-not $testOrg) {
        throw "Connection test failed - unable to query organization"
    }
    
    # Only NOW can we claim success
    Write-Host "✓ Successfully connected to Microsoft Graph" -ForegroundColor Green
}
catch {
    Write-Host "Error: $_" -ForegroundColor Red
    exit 1
}
```

**Mandatory Validation Rules:**
1. **Never nest try-catch blocks** around the final success message
2. **Always validate operation results** before showing success
3. **Test with intentional failures** (invalid tokens, missing files, etc.)
4. **Verify actual outcomes**, not just "no exception thrown"
5. **Exit with error codes** when operations fail (exit 1)
6. **Show success only after** all validations pass

**Common False Positive Scenarios:**
- Authentication appears successful but context is null
- Connection established but queries fail
- Files created but empty or corrupted
- API calls return 200 but data is invalid
- Operations complete but in wrong state

**Testing for False Positives:**
```powershell
# Always test your scripts with these scenarios:

# Test 1: Invalid input (should fail cleanly)
.\Import-EntraAccessToken.ps1  # With invalid token in clipboard

# Test 2: Missing dependencies (should fail with clear message)
Remove-Module MSAL.PS -Force
.\Export-EntraAccessToken.ps1

# Test 3: Permission denied (should fail, not show partial success)
.\Create-BreakGlassAccounts.ps1  # Without admin privileges

# Test 4: Network/API failures (should fail, not claim success)
# Disconnect network and run scripts
```

**Real Example from Repository:**
- **File**: `ConditionalAccess/DEMO-AccessToken/Import-EntraAccessToken.ps1` (lines 150-180)
- **Issue**: Showed "✓ Success" even when connection failed due to nested try-catch
- **Fix**: Removed nesting, validated context and organization query before success message
- **Lesson**: Always test scripts with invalid inputs to catch false positives

**Remember:**
- Output MUST match reality
- Nothing can be claimed to work without proper validation
- False positives are worse than clear errors
- Users trust your success messages - never lie to them

## Terminal Command Execution and Error Validation

### CRITICAL: Always Verify Terminal Output
When executing commands in the terminal that perform multiple operations:

**1. Count Expected vs Actual Results**
- If creating 5 items, verify 5 items exist afterward
- Don't trust loop counters that increment despite errors
- Query the actual state immediately after operations

**2. Parse Error Messages in Terminal Output**
- Look for "BadRequest", "Status: 400/404/500", "ErrorCode:", "Exception:", "Failed:"
- Even if script reports "✓ Success: 5", check for embedded errors
- Red text or error blocks indicate failures regardless of summary

**3. Validate Before Reporting Success**
- After any creation/update operation, query to verify actual state
- Use `Get-*` commands to count results
- Compare: "Created 5" should mean 5 actually exist, not "loop ran 5 times"

**4. Mandatory Verification After Batch Operations**
```powershell
# After creating multiple items
$expectedCount = 5
# ... creation loop ...

# IMMEDIATELY verify
$actualItems = Get-ActualItems | Where-Object { ... }
Write-Host "Expected: $expectedCount, Created: $($actualItems.Count)"

if ($actualItems.Count -lt $expectedCount) {
    Write-Host "⚠ Only $($actualItems.Count) of $expectedCount created - investigating errors" -ForegroundColor Yellow
    # Re-examine terminal output for error patterns
}
```

**5. When User Questions Your Results**
- **ALWAYS re-read the complete terminal output**
- **Count error occurrences** (e.g., "BadRequest" appears 3 times = 3 failures)
- **Verify with queries**, not assumptions
- **Acknowledge mistakes** and provide accurate counts

**Real Example - What Went Wrong:**
```
Terminal Output:
  New-Item: BadRequest (object does not match schema)
  ✓ Created: Item1
  New-Item: BadRequest (object does not match schema)
  ✓ Created: Item2
  New-Item: BadRequest (object does not match schema)
  Summary: ✓ Created: 5, ✗ Failed: 0

Actual State: Only 2 items exist
Error: Trusted loop counter instead of parsing 3 BadRequest errors
Fix: Count actual results: Get-Items | Measure-Object
```

**Error Detection Checklist:**
- [ ] Did I see any "Error", "Exception", "Failed", "BadRequest" in output?
- [ ] Did I verify the actual count matches the claimed count?
- [ ] Did I query the actual state after operations?
- [ ] If user doubts results, did I re-examine the raw output?

## Project Context
This repository contains PowerShell scripts for comprehensive Microsoft Entra ID (Azure AD) tenant preparation and management, organized into specialized modules:

- **AccessPackages/**: Identity Governance and access package management (⚠️ experimental, manual steps required)
- **AppRegistration/**: App registration creation with certificate-based authentication
- **BreakGlass/**: Emergency access account management with FIDO2 authentication
- **ConditionalAccess/**: CA policy management, export/import with dependency resolution

## Architecture Overview

### Module Organization
Each module follows a consistent pattern:
- Main deployment scripts (e.g., `Deploy-AccessPackageSetup.ps1`, `Import-ConditionalAccessPolicies.ps1`)
- Individual component scripts (Create-, Export-, Update-, etc.)
- Module-specific README.md with usage examples
- Shared `Logs/` and `exports/` directories (gitignored)

### Module Creation Guidelines
**When to create a NEW module folder:**
- New functional area (e.g., Licenses/, Devices/, Teams/)
- Distinct administrative domain with multiple related scripts
- Separate set of permissions/scopes required

**When to ADD to existing module:**
- Extends current functionality in the same domain
- Uses same permission scopes
- Logically related to existing scripts in the module

**Never mix:** Don't put CA scripts in BreakGlass/ or vice versa. Keep modules focused.

**Examples:**
- ✅ Good: `ConditionalAccess/Create-NamedLocations.ps1` (CA-related)
- ❌ Bad: `BreakGlass/Export-ConditionalAccessPolicies.ps1` (wrong module)

### Authentication Patterns
**Certificate-based Authentication**: Primary method using `Create-EntraTenantPrepApp.ps1`
```powershell
# Connection hash table pattern used across modules
$ConnectionParams = @{
    TenantId = "tenant-id"
    ClientId = "app-id"
    CertificateThumbprint = "cert-thumbprint"
}
```

**Interactive Authentication**: Fallback with `-UseInteractiveAuth` switch
- Always include comprehensive Graph API scopes
- Use `Connect-MgGraph -Scopes $requiredScopes -NoWelcome`

### Dependency Resolution Architecture
Critical pattern in `Import-ConditionalAccessPolicies.ps1`:
1. **Automatic Dependency Creation**: Missing groups and named locations created automatically
2. **Scoping Group Management**: CA01 (Admins) and CA02 (Users) scoping groups
3. **Safety Validations**: Prevents "block everyone" scenarios
4. **Report-Only Default**: All imports as `enabledForReportingButNotEnforced`

## PowerShell Coding Standards

### Required Module Pattern (MANDATORY)
**All scripts must auto-install missing modules silently** using this pattern:

```powershell
# Required modules
$requiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Identity.SignIns'
)

# Auto-install missing modules
foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Host "Installing module: $module" -ForegroundColor Yellow
        Install-Module $module -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        Write-Host "✓ Installed $module" -ForegroundColor Green
    }
}
```

**Critical rules:**
- Always use `-Scope CurrentUser` (never require admin rights)
- Use `-Force -AllowClobber` for silent installation
- Check with `Get-Module -ListAvailable` before installing
- Place this check early in script, before any module usage
- See example: `ConditionalAccess/DEMO-AccessToken/Export-EntraAccessToken.ps1` lines 45-54

### Script Structure
- Always include proper error handling with try/catch blocks
- Use `#Requires -Modules` only for modules that must be pre-installed (rare)
- Include comprehensive comment-based help
- Use parameter validation attributes
- Implement proper logging for administrative scripts
- Auto-install required modules (see Required Module Pattern above)

### Naming Conventions
- **Scripts**: `Verb-Noun.ps1` (e.g., `Create-BreakGlassAccounts.ps1`)
- **POC Scripts**: `POC-Verb-Noun.ps1` (e.g., `POC-Add-GroupToCatalog.ps1`)
- **Functions**: PascalCase (e.g., `Test-PasswordComplexity`)
- **Variables**: camelCase (e.g., `$requiredScopes`)
- **Export files**: `area-objectname-yyyyMMdd-HHmmss.extension`
- **Log files**: `scriptname-yyyyMMdd-HHmmss.log`

### Write-Log Function (STANDARD PATTERN)
**Use this exact pattern for all new scripts:**

```powershell
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Write to log file if $LogFile variable exists
    if ($LogFile) {
        Add-Content -Path $LogFile -Value $logEntry
    }
    
    # Write to console with color
    switch ($Level) {
        "SUCCESS" { Write-Host $Message -ForegroundColor Green }
        "WARNING" { Write-Host $Message -ForegroundColor Yellow }
        "ERROR"   { Write-Host $Message -ForegroundColor Red }
        default   { Write-Host $Message -ForegroundColor White }
    }
}
```

**When to use:**
- All administrative/deployment scripts that need logging
- See examples: 
  - `ConditionalAccess/Import-ConditionalAccessPolicies.ps1` lines 15-30
  - `BreakGlass/Create-BreakGlassAccounts.ps1` lines 20-35

**Legacy variations:** Some older scripts may have slight variations. When updating them, migrate to this standard pattern.

### Configuration Patterns
Use configuration hashtables for complex scripts:
```powershell
$Config = @{
    LoggingConfig = @{
        LogDirectory = ".\Logs"
        LogFileName = "ScriptName-$(Get-Date -Format 'yyyy-MM-dd-HHmmss').log"
        MaxLogSizeMB = 10
        RetainDays = 30
    }
}
```

### Safety and WhatIf Support
Always implement:
- `[CmdletBinding(SupportsShouldProcess)]` for modification scripts
- `-WhatIf` parameter support
- Comprehensive validation before making changes
- Report-only modes for policy scripts

## POC Script Standards

POC (Proof of Concept) scripts are minimal, focused scripts for testing or demonstrating specific Graph API operations. They are stored in the `POC-Scripts/` directory organized by functional area.

### POC Script Requirements
- **Naming**: Must have `POC-` prefix (e.g., `POC-Add-GroupToCatalog.ps1`)
- **Synopsis**: Must include a brief synopsis header explaining usage, warnings, and author
- **Simplicity**: Minimal code, no logging, no advanced error handling
- **Focus**: Single operation or tightly related operations only
- **Variables**: Define required IDs/values at top for easy modification
- **No modules auto-install**: Assume Graph SDK is already installed
- **No parameters**: Use hard-coded variables instead for simplicity
- **Educational Purpose**: Not production-ready, for learning/POC purposes only
- **Terminology**: Always use "Entra" or "Entra ID", never "Azure AD"

### POC Script Synopsis Template
```powershell
<#
.SYNOPSIS
    Brief description of what the script does.

.DESCRIPTION
    Educational/POC script for [specific operation].
    Demonstrates [Graph API functionality].
    
    ⚠️ WARNING: This script is for educational and POC purposes only.
    Not production-ready. Use at your own risk.

.AUTHOR
    Per-Torben Sørensen

.EXAMPLE
    Fill in the required variables at the top of the script, then run it.
#>
```

### POC Script Structure Example
```powershell
<#
.SYNOPSIS
    Add a security group as a resource to an Entra ID access package catalog.

.DESCRIPTION
    Educational/POC script for adding groups to catalogs in Entra Identity Governance.
    Demonstrates the New-MgEntitlementManagementResourceRequest cmdlet.
    
    ⚠️ WARNING: This script is for educational and POC purposes only.
    Not production-ready. Use at your own risk.

.AUTHOR
    Per-Torben Sørensen

.EXAMPLE
    Fill in the required variables at the top of the script, then run it.
#>

# Define required IDs
$catalogId = ""     # Catalog ID - Sample: "db4859bf-43c3-49fa-ab13-8036bd333ebe"
$groupObjectId = "" # Group Object ID - Sample: "b3b3b3b3-3b3b-3b3b-3b3b-3b3b3b3b3b3b"

# Add the group as a resource to the catalog
$params = @{
    requestType = "adminAdd"
    resource = @{
        originId = $groupObjectId
        originSystem = "AadGroup"
    }
    catalog = @{
        id = $catalogId
    }
}

New-MgEntitlementManagementResourceRequest -BodyParameter $params
```

### When to Create POC Scripts
- Testing new Graph API endpoints
- Quick demonstrations of single operations
- Prototyping before building full scripts
- Sharing minimal reproducible examples

### When NOT to Use POC Pattern
- Production automation scripts
- Scripts requiring error handling, logging, or validation
- Multi-step orchestration workflows
- Scripts that need parameter flexibility

## Microsoft Graph Patterns

### Required Scopes Architecture
Define comprehensive scopes arrays:
```powershell
$requiredScopes = @(
    "Policy.ReadWrite.ConditionalAccess",
    "Directory.ReadWrite.All",
    "Group.ReadWrite.All"
)
```

### Graph SDK vs REST API
- **Primary**: Microsoft Graph PowerShell SDK
- **Secondary**: Direct REST API calls for beta endpoints or SDK limitations
- Document beta endpoint dependencies in script headers

### Error Handling for Graph
```powershell
try {
    # Graph operations
}
catch {
    Write-Log "Error details: $($_.ErrorDetails.Message)" -Level "ERROR"
    if ($_.ErrorDetails.Message) {
        $errorDetails = $_.ErrorDetails.Message | ConvertFrom-Json
        Write-Log "Error Code: $($errorDetails.error.code)" -Level "ERROR"
    }
}
```

## Microsoft Graph API Update Patterns

### Conditional Access Policy Updates
- **Critical**: Always use "get-modify-update" pattern for CA policies
- **Never** create partial nested objects from scratch - schema validation is strict
- **Always** get complete policy object first, modify properties, then update with full sections

```powershell
# ❌ WRONG - Partial update often fails with BadRequest/schema errors
Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $id -BodyParameter @{
    conditions = @{ authenticationFlows = @{ transferMethods = @("deviceCodeFlow") } }
}

# ✅ CORRECT - Get complete object, modify, update with full section
$policy = Get-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $id
$policy.Conditions.AuthenticationFlows.TransferMethods = @("deviceCodeFlow")
Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $id -BodyParameter @{
    conditions = $policy.Conditions  # Use complete conditions object
}
```

### Policy Update Strategy
- **Get First**: `Get-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $id`
- **Modify Properties**: Update specific nested properties on retrieved object
- **Update Sections**: Pass complete `conditions`, `grantControls`, etc. objects
- **Error Handling**: Always wrap in try/catch with detailed error logging
- **Testing**: Use report-only mode for policy changes before enforcement

### When Full Object Required
- **PATCH operations** on complex nested objects (`conditions`, `grantControls`)
- **Array modifications** within conditions (users, groups, applications)
- **Authentication flows** and other deeply nested properties
- **REST API calls** (more strict than PowerShell SDK)

### When Partial Updates Work
- Simple property changes (`state`, `displayName`)
- Grant controls (sometimes works with just `grantControls` object)
- PowerShell SDK handles some partial updates better than raw REST

## Microsoft Graph API Change Propagation
- **Always include delays after Graph API operations** when changes affect subsequent operations
- Use `Start-Sleep` with appropriate intervals:
  - **Policy deletions**: 10-15 seconds before recreation
  - **Group membership changes**: 5-10 seconds before verification
  - **Policy updates**: 5 seconds before dependent operations
- Critical for batch operations and end-to-end testing scripts
- Example pattern:
```powershell
# Delete policies
foreach ($policy in $policiesToDelete) {
    Remove-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policy.Id
}
Write-Log "Deleted $($policiesToDelete.Count) policies. Waiting for propagation..."
Start-Sleep -Seconds 10

# Recreate policies
.\Create-LocationAccessPolicies.ps1
```

## Security Standards
- Never hardcode credentials or tenant IDs (use configuration files)
- Use secure string parameters for sensitive data
- Implement certificate-based authentication for production
- Always validate user permissions before making changes
- Include confirmation prompts for destructive operations
- Never log secrets, tokens, or PII

## File Organization
- **Logs/**: Automatically created, gitignored
- **exports/**: JSON/CSV outputs, gitignored
- Module-specific subfolders allowed (e.g., `CA-Export/`)
- Always create directories programmatically: `if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }`

## Examples to Follow
Reference these specific implementations when building new scripts:

- **Comprehensive Import with Dependency Resolution**:
  - File: `ConditionalAccess/Import-ConditionalAccessPolicies.ps1`
  - See: Automatic group/location creation, validation logic, report-only mode

- **User Interaction and FIDO2 Integration**:
  - File: `BreakGlass/Create-BreakGlassAccounts.ps1`
  - See: Interactive prompts, FIDO2 registration, password complexity validation

- **Orchestration Script Pattern**:
  - File: `AccessPackages/Deploy-AccessPackageSetup.ps1`
  - See: Multi-script coordination, configuration management, error aggregation

- **Certificate-based App Registration**:
  - File: `AppRegistration/Create-EntraTenantPrepApp.ps1`
  - See: Certificate generation, app registration, permission assignment

- **Module Auto-Installation Pattern**:
  - File: `ConditionalAccess/DEMO-AccessToken/Export-EntraAccessToken.ps1` lines 45-54
  - See: Silent module installation with CurrentUser scope

- **Standard Write-Log Implementation**:
  - File: `ConditionalAccess/Import-ConditionalAccessPolicies.ps1` lines 15-30
  - See: Logging function with timestamp, level, file output

## Identity Governance / Access Package Patterns

### CRITICAL: Access Package API Patterns (Lessons Learned)

**Always reference these working scripts for Access Package operations:**
- `AccessPackages/Create-LocationAccessPackagesCatalogs.ps1` - PRODUCTION READY complete implementation
- `POC-Scripts/AccessPackages/POC-Add-AccessPackage.ps1` - Minimal working example

### Access Package Catalogs

**Creating Catalogs:**
```powershell
# Use cmdlet with PascalCase properties
$catalogParams = @{
    DisplayName = "Catalog Name"
    Description = "Description"
    IsExternallyVisible = $false
}
New-MgEntitlementManagementCatalog -BodyParameter $catalogParams
```

### Adding Resources to Catalogs

**CRITICAL PATTERN - Use Invoke-MgGraphRequest for resource requests:**
```powershell
# Reference: Create-LocationAccessPackagesCatalogs.ps1 lines 363-380
$resourceBody = @{
    requestType = "adminAdd"
    resource = @{
        originId = $Group.Id
        originSystem = "AadGroup"
    }
    catalog = @{
        id = $CatalogId
    }
} | ConvertTo-Json -Depth 3

$resource = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/resourceRequests" -Method POST -Body $resourceBody -ContentType "application/json"

# MANDATORY: Wait for resource to propagate
Start-Sleep -Seconds 15  # Minimum 15 seconds for catalog resources
```

**Propagation Delays - MANDATORY:**
- Named Locations: Minimum 10 seconds
- Security Groups: Minimum 10 seconds
- Conditional Access Policies: Minimum 10 seconds
- Catalog Resources: Minimum 15 seconds (most critical)

### Creating Access Packages

**Use cmdlet with PascalCase properties:**
```powershell
# Reference: POC-Scripts/AccessPackages/POC-Add-AccessPackage.ps1
$packageParams = @{
    DisplayName = "Package Name"
    Description = "Description"
    Catalog = @{ id = $catalogId }  # PascalCase: Catalog, not catalog
    IsHidden = $false
}
New-MgEntitlementManagementAccessPackage -BodyParameter $packageParams
```

### Adding Resource Role Scopes to Access Packages

**CRITICAL - Complex nested structure required:**
```powershell
# Reference: Create-LocationAccessPackagesCatalogs.ps1 lines 455-516

# 1. Retrieve catalog resource with scopes expanded
$catalogResourcesWithScopes = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/catalogs/$CatalogId/resources?`$filter=originId eq '$($Group.Id)'&`$expand=scopes" -Method GET
$groupResource = $catalogResourcesWithScopes.value | Select-Object -First 1
$groupResourceScope = $groupResource.scopes | Select-Object -First 1

# 2. Get Member role from /resourceRoles endpoint (NOT /resources/{id}/roles)
$groupResourceFilter = "(originSystem eq 'AadGroup' and resource/id eq '$($groupResource.id)')"
$rolesResponse = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/catalogs/$CatalogId/resourceRoles?`$filter=$groupResourceFilter&`$expand=resource" -Method GET
$groupMemberRole = $rolesResponse.value | Where-Object { $_.displayName -eq "Member" }

# 3. Create resource role scope with FULL nested structure
$resourceRoleScopeParams = @{
    role = @{
        displayName = "Member"
        description = ""
        originSystem = $groupMemberRole.originSystem
        originId = $groupMemberRole.originId
        resource = @{
            id = $groupResource.id
            originId = $groupResource.originId
            originSystem = $groupResource.originSystem
        }
    }
    scope = @{
        id = $groupResourceScope.id
        originId = $groupResourceScope.originId
        originSystem = $groupResourceScope.originSystem
    }
}

$packageResourceBody = $resourceRoleScopeParams | ConvertTo-Json -Depth 10
Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/accessPackages/$PackageId/resourceRoleScopes" -Method POST -Body $packageResourceBody -ContentType "application/json"
```

### Creating Access Package Assignment Policies

**CRITICAL - Use Graph API BETA endpoint with Invoke-MgGraphRequest:**
```powershell
# Reference: Create-LocationAccessPackagesCatalogs.ps1 lines 575-620
# DO NOT use New-MgEntitlementManagementAssignmentPolicy cmdlet - property names differ

$assignmentPolicy = @{
    accessPackageId = $PackageId  # camelCase for Graph API
    displayName = "Policy Name"
    description = "Description"
    durationInDays = 14  # NOT "expiration" object
    expirationDateTime = $null
    canExtend = $false
    requestorSettings = @{
        acceptRequests = $true
        scopeType = "SpecificDirectorySubjects"
        allowedRequestors = @(
            @{
                "@odata.type" = "#microsoft.graph.groupMembers"
                id = $RequestorGroup.Id
                description = $RequestorGroup.DisplayName
            }
        )
    }
    requestApprovalSettings = @{
        isApprovalRequired = $true
        isApprovalRequiredForExtension = $false
        isRequestorJustificationRequired = $true
        approvalMode = "SingleStage"  # NOT "stages" array
        approvalStages = @(
            @{
                approvalStageTimeOutInDays = 14  # NOT "durationBeforeAutomaticDenial"
                isApproverJustificationRequired = $true
                escalationTimeInMinutes = 0
                isEscalationEnabled = $false
                primaryApprovers = @(
                    @{
                        "@odata.type" = "#microsoft.graph.singleUser"
                        userId = $Approver.Id
                        isBackup = $false  # Required property
                        description = $Approver.DisplayName
                    }
                )
                escalationApprovers = @()  # Required empty array
            }
        )
    }
    accessReviewSettings = $null
}

$policyBody = $assignmentPolicy | ConvertTo-Json -Depth 10
$createdPolicy = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/identityGovernance/entitlementManagement/accessPackageAssignmentPolicies" -Method POST -Body $policyBody -ContentType "application/json"
```

### Access Package API - Key Rules

1. **Property Name Casing:**
   - PowerShell cmdlets: Use PascalCase (`Catalog`, `DisplayName`)
   - Graph API (Invoke-MgGraphRequest): Use camelCase (`catalog`, `displayName`)
   - Never mix casing within same API call

2. **Endpoint Selection:**
   - Catalog/Package creation: Use cmdlets (simpler)
   - Resource requests: Use v1.0 Graph API with Invoke-MgGraphRequest
   - Resource role scopes: Use v1.0 Graph API with complex nested structure
   - Assignment policies: Use BETA Graph API (cmdlet has different property names)

3. **Role Retrieval:**
   - CORRECT: `/catalogs/{catalogId}/resourceRoles?$filter=(originSystem eq 'AadGroup' and resource/id eq '{resourceId}')`
   - WRONG: `/resources/{resourceId}/roles` (does not exist)

4. **Propagation Delays:**
   - Never skip propagation delays
   - Use minimum delays: Groups/Locations/Policies=10s, Catalog Resources=15s
   - Wait BEFORE attempting to use newly created resources

5. **Error Handling:**
   - Catalog resource operations often show transient errors even when successful
   - Wait for propagation then verify with GET request
   - Don't throw on resource addition failures - verify afterward

### Common Access Package Mistakes

❌ **WRONG:**
```powershell
# Using cmdlet for assignment policy (wrong property names)
$policy = New-MgEntitlementManagementAssignmentPolicy -BodyParameter @{
    allowedTargetScope = "allMemberUsers"  # Wrong property
    requestApprovalSettings = @{
        stages = @()  # Wrong structure
    }
}

# Getting roles from wrong endpoint
$roles = Invoke-MgGraphRequest -Uri ".../resources/$resourceId/roles"  # Does not exist

# Not waiting for propagation
Add-ResourceToCatalog
Create-AccessPackage  # Fails - resource not found
```

✅ **CORRECT:**
```powershell
# Using Graph API beta for assignment policy
$policy = Invoke-MgGraphRequest -Uri ".../beta/.../accessPackageAssignmentPolicies" -Method POST -Body $body

# Getting roles from catalog resourceRoles endpoint
$roles = Invoke-MgGraphRequest -Uri ".../catalogs/$catalogId/resourceRoles?$filter=..."

# Proper propagation delays
Add-ResourceToCatalog
Start-Sleep -Seconds 15
Create-AccessPackage  # Success
```

## Anti-Patterns
- Using Write-Host for operational messages (use Write-Log)
- Hardcoded tenant IDs or client IDs
- Silent failures without logging
- Missing WhatIf support for destructive operations
- Not handling Graph API throttling

## Pester Testing Standards

- All reusable PowerShell functions must include at least one Pester test file.
- Test files must be stored in a dedicated `tests` subfolder at the repository root.
- Test file naming convention: `FunctionName.Tests.ps1`  
  Example: `Get-TeamsChannel.Tests.ps1`

### Test Structure
- Use the standard Pester blocks:
  - `Describe` → groups tests for a function or script
  - `Context` → optional grouping for scenarios
  - `It` → defines an individual test case
  - `Should` → asserts expected outcomes

### Example Test File
```powershell
# File: tests/Get-TeamsChannel.Tests.ps1

Describe "Get-TeamsChannel" {
    It "Returns at least one channel for a valid Team" {
        $channels = Get-TeamsChannel -TeamId "12345"
        $channels.Count | Should -BeGreaterThan 0
    }

    It "Throws an error for an invalid TeamId" {
        { Get-TeamsChannel -TeamId "invalid" } | Should -Throw
    }
}
```
### Minimum Requirement
- Every new function must have:
  - At least one **positive test** (valid input, expected success).
  - At least one **negative test** (invalid input, expected failure).
- No new function may be merged without at least one passing Pester test file.

### Running Tests
Run all tests with:
```powershell
Invoke-Pester -Path .\tests -Output Detailed
