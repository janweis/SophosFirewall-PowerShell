# Sophos Firewall PowerShell Module Suite

Comprehensive PowerShell module collection for Sophos XGS/SFOS firewall management. 21 modules with 474+ cmdlets for complete API coverage.

## Quick Start

```powershell
# 1. Install from PowerShell Gallery
Install-Module SophosFirewall.Core -Repository PSGallery -Scope CurrentUser
Install-Module SophosFirewall.HostAndServices -Repository PSGallery -Scope CurrentUser

# 2. Connect to firewall
$cred = Get-Credential
Connect-SfosFirewall -Firewall "192.168.1.1" -Port 4444 -Credential $cred -SkipCertificateCheck

# 3. Use modules
Get-SfosIpHost
New-SfosIpHost -Name "Server1" -IpAddress "10.0.0.5"
```

## Available Modules

### Published (v1.0.0)

| Module | Functions | Purpose |
|--------|-----------|---------|
| **SophosFirewall.Core** | 7 | Session management, API, XML security |
| **SophosFirewall.HostAndServices** | 53 | Host and service management |

### Coming Q1-Q2 2026

**CONFIGURE** (145 functions): Network, Authentication, Routing, VPN, SystemServices  
**PROTECT** (235 functions): Firewall, Web, Applications, EmailMTA, Wireless, WebServer, IntrusionPrevention, ActiveThreatResponse  
**SYSTEM** (28 functions): Administration, BackupFirmware, Certificates, Profiles, Diagnostics  
**ANALYSE** (6 functions): ZeroDayProtection

## Documentation

- [SophosFirewall.Core README](Modules/SophosFirewall.Core/README.md) - Foundation module details
- [SophosFirewall.HostAndServices README](Modules/SophosFirewall.HostAndServices/README.md) - Host/service management

## Key Features

- ✅ **474+ Functions** - Complete Sophos Firewall API coverage
- ✅ **PowerShell 5.1+** - Full version compatibility
- ✅ **Session Management** - One connection for all modules
- ✅ **Pipeline Support** - Fluent cmdlet chaining
- ✅ **Safety Features** - WhatIf/Confirm for write operations
- ✅ **XML Security** - Automatic injection prevention
- ✅ **Self-Signed Certs** - Test environment support

## Requirements

- PowerShell 5.1 or higher
- HTTPS network access to firewall (port 4444)
- Valid firewall admin account
- SFOS 21.5, 22.0+

## Examples

### Host Management
```powershell
# List all hosts
Get-SfosIpHost

# Create host
New-SfosIpHost -Name "WebServer" -IpAddress "10.0.0.5" -Description "Web server"

# Update host
Set-SfosIpHost -Name "WebServer" -Description "Updated"

# Delete host
Remove-SfosIpHost -Name "WebServer" -Confirm
```

### Service Management
```powershell
# Create service
New-SfosService -Name "CustomHTTPS" -Protocol "TCP" -Port "8443"

# List services
Get-SfosService | Format-Table -AutoSize
```

## Module Organization

| Category | Modules | Functions |
|----------|---------|-----------|
| CONFIGURE | Network, Authentication, Routing, VPN, SystemServices | 145 |
| PROTECT | Firewall, Web, Applications, EmailMTA, Wireless, WebServer, IntrusionPrevention, ActiveThreatResponse | 235 |
| SYSTEM | Administration, BackupFirmware, Certificates, Profiles, Diagnostics | 28 |
| ANALYSE | ZeroDayProtection | 6 |

## Architecture

- **CRUD Operations**: Get, New, Set, Remove for all objects
- **Consistent Parameters**: Reusable connection across modules
- **Pipeline Support**: Objects flow between cmdlets
- **Safety**: WhatIf/Confirm on write operations
- **Error Handling**: Descriptive error messages

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Connection fails | Check IP/port, verify network connectivity |
| SSL error | Use `-SkipCertificateCheck` parameter |
| Auth fails (502) | Verify admin credentials |
| "No active connection" | Run `Connect-SfosFirewall` first |

## License

MIT License - Copyright (c) 2025 Jan Weis

## Version

1.0.0 - Production Release (January 2026)

---

For API details, see [Sophos Firewall API Documentation](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/).
