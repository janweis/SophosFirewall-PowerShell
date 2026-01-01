# SophosFirewall.HostAndServices Module

## Overview

The **HostAndServices** module provides comprehensive PowerShell cmdlets for managing network objects on Sophos XGS / SFOS 21.5, 22.0+ firewalls. With 53 functions, it enables definition and management of IP hosts, FQDN hosts, MAC hosts, services, service groups, and country groups used throughout firewall policies and rules.

## Features

- **IP Host Objects**: Create, update, and manage IP-based host definitions
- **IP Host Groups**: Organize IP hosts into logical groups for policy management
- **FQDN Host Objects**: Manage hostname/DNS-based host definitions
- **FQDN Host Groups**: Organize FQDN hosts with bulk deletion support
- **MAC Host Objects**: MAC address-based host definitions
- **Country Host Groups**: Geographic-based access control groups
- **Service Objects**: Define custom TCP/UDP services with single ports or port ranges
- **Service Groups**: Group related services for simplified policy assignment
- **Import/Export**: Bulk import and export for all object types
- **Bulk Operations**: Mass delete operations for FQDN hosts
- **Comments**: Add descriptive metadata to all objects
- **API Integration**: Full integration with Sophos XGS/SFOS firewall REST API

## Installation

```powershell
Import-Module -Name SophosFirewall.HostAndServices
```

Or with explicit path:

```powershell
Import-Module -Path "C:\Path\To\SophosFirewall.IPHostAndServices.psd1"
```

## Requirements

- PowerShell 5.1 or higher (Windows PowerShell)
- PowerShell 7.0+ (PowerShell Core) recommended
- SophosFirewall.Core module (automatically loaded as dependency)
- Network access to Sophos XGS / SFOS firewall (versions 21.5, 22.0+)
- API credentials with appropriate permissions

## Quick Start

### Establish Connection

```powershell
Connect-SfosFirewall -Firewall "192.168.1.1" -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck
```

### IP Host Management

```powershell
# Get all IP hosts
Get-SfosIpHost

# Get specific IP host
Get-SfosIpHost -Name "CORP-WEB-01"

# Create IP host
New-SfosIpHost -Name "CORP-WEB-01" -IpAddress "192.168.1.10" -Description "Production Web Server"

# Create IP network/subnet
New-SfosIpHost -Name "InternalNetwork" -IpAddress "192.168.0.0" -Description "Internal subnet"

# Update IP host
Set-SfosIpHost -Name "CORP-WEB-01" -Description "Updated: Primary web server"

# Delete IP host
Remove-SfosIpHost -Name "CORP-WEB-01"

# Export all IP hosts
Export-SfosIpHosts -FilePath "c:\backups\ip_hosts.csv"

# Import IP hosts
Import-SfosIpHosts -FilePath "c:\backups\ip_hosts.csv"
```

### IP Host Group Management

```powershell
# Get all IP host groups
Get-SfosIpHostGroup

# Create IP host group
New-SfosIpHostGroup -Name "WebServers" -Description "Production web tier"

# Add member to group
Add-SfosIpHostGroupMember -GroupName "WebServers" -MemberName "CORP-WEB-01"
Add-SfosIpHostGroupMember -GroupName "WebServers" -MemberName "CORP-WEB-02"

# Update group
Set-SfosIpHostGroup -Name "WebServers" -Description "Updated: All production web servers"

# Remove member from group
Remove-SfosIpHostGroupMember -GroupName "WebServers" -MemberName "CORP-WEB-03"

# Delete group
Remove-SfosIpHostGroup -Name "WebServers"

# Export/Import groups
Export-SfosIpHostGroups -FilePath "c:\backups\ip_host_groups.csv"
Import-SfosIpHostGroups -FilePath "c:\backups\ip_host_groups.csv"
```

### FQDN Host Management

```powershell
# Get all FQDN hosts
Get-SfosFqdnHost

# Create FQDN host
New-SfosFqdnHost -Name "MailServer" -Hostname "mail.company.com" -Description "Corporate Mail"

# Update FQDN host
Set-SfosFqdnHost -Name "MailServer" -Description "Updated mail server"

# Delete FQDN host
Remove-SfosFqdnHost -Name "MailServer"

# Delete multiple FQDN hosts in bulk
Remove-SfosFqdnHostMass -Names "OldHost1", "OldHost2", "OldHost3"

# Export/Import FQDN hosts
Export-SfosFqdnHosts -FilePath "c:\backups\fqdn_hosts.csv"
Import-SfosFqdnHosts -FilePath "c:\backups\fqdn_hosts.csv"
```

### FQDN Host Group Management

```powershell
# Get all FQDN host groups
Get-SfosFqdnHostGroup

# Create FQDN host group
New-SfosFqdnHostGroup -Name "MailServers" -Description "Mail infrastructure"

# Add member to group
Add-SfosFqdnHostGroupMember -GroupName "MailServers" -MemberName "MailServer"

# Update group
Set-SfosFqdnHostGroup -Name "MailServers" -Description "Updated: Corporate mail systems"

# Remove member from group
Remove-SfosFqdnHostGroupMember -GroupName "MailServers" -MemberName "OldMailServer"

# Delete group
Remove-SfosFqdnHostGroup -Name "MailServers"

# Export/Import FQDN groups
Export-SfosFqdnHostGroups -FilePath "c:\backups\fqdn_host_groups.csv"
Import-SfosFqdnHostGroups -FilePath "c:\backups\fqdn_host_groups.csv"
```

### MAC Host Management

```powershell
# Get all MAC hosts
Get-SfosMacHost

# Create MAC host
New-SfosMacHost -Name "PrinterDevice" -MacAddress "00:1A:2B:3C:4D:5E" -Description "Network Printer"

# Update MAC host
Set-SfosMacHost -Name "PrinterDevice" -Description "Updated: Main floor printer"

# Delete MAC host
Remove-SfosMacHost -Name "PrinterDevice"

# Export/Import MAC hosts
Export-SfosMacHosts -FilePath "c:\backups\mac_hosts.csv"
Import-SfosMacHosts -FilePath "c:\backups\mac_hosts.csv"
```

### Country Host Group Management

```powershell
# Get all country host groups
Get-SfosCountryHostGroup

# Create country group for geo-blocking
New-SfosCountryHostGroup -Name "HighRiskCountries" -Countries "CN", "KP", "IR" -Description "Restricted countries"

# Update country group
Set-SfosCountryHostGroup -Name "HighRiskCountries" -Description "Updated: Countries for blocking"

# Delete country group
Remove-SfosCountryHostGroup -Name "HighRiskCountries"
```

### Service Management

```powershell
# Get all services
Get-SfosService

# Create TCP service
New-SfosService -Name "HTTPS" -Protocol "TCP" -Port "443" -Description "HTTPS traffic"

# Create service with port range
New-SfosService -Name "AppServer-Ports" -Protocol "TCP" -PortRange "8000-9000" -Description "Custom app ports"

# Create UDP service
New-SfosService -Name "DNS" -Protocol "UDP" -Port "53" -Description "DNS service"

# Update service
Set-SfosService -Name "HTTPS" -Description "Updated: HTTPS service definition"

# Delete service
Remove-SfosService -Name "OldService"

# Export/Import services
Export-SfosServices -FilePath "c:\backups\services.csv"
Import-SfosServices -FilePath "c:\backups\services.csv"
```

### Service Group Management

```powershell
# Get all service groups
Get-SfosServiceGroup

# Create service group
New-SfosServiceGroup -Name "WebServices" -Description "HTTP/HTTPS services"

# Add service to group
Add-SfosServiceGroupMember -GroupName "WebServices" -MemberName "HTTPS"
Add-SfosServiceGroupMember -GroupName "WebServices" -MemberName "HTTP"

# Update group
Set-SfosServiceGroup -Name "WebServices" -Description "Updated: All web-related services"

# Remove service from group
Remove-SfosServiceGroupMember -GroupName "WebServices" -MemberName "OldService"

# Delete group
Remove-SfosServiceGroup -Name "WebServices"

# Export/Import service groups
Export-SfosServiceGroups -FilePath "c:\backups\service_groups.csv"
Import-SfosServiceGroups -FilePath "c:\backups\service_groups.csv"
```

## Available Cmdlets (53 total)

### IP Host Management (6 functions)
- `Get-SfosIpHost` - Retrieve all IP hosts
- `New-SfosIpHost` - Create new IP host with IP address/network
- `Set-SfosIpHost` - Update existing IP host properties
- `Remove-SfosIpHost` - Delete IP host from firewall
- `Export-SfosIpHosts` - Export IP hosts to file
- `Import-SfosIpHosts` - Import IP hosts from file

### IP Host Group Management (8 functions)
- `Get-SfosIpHostGroup` - Retrieve all IP host groups and members
- `New-SfosIpHostGroup` - Create new IP host group
- `Set-SfosIpHostGroup` - Update existing IP host group properties
- `Remove-SfosIpHostGroup` - Delete IP host group from firewall
- `Add-SfosIpHostGroupMember` - Add host to IP host group
- `Remove-SfosIpHostGroupMember` - Remove host from IP host group
- `Export-SfosIpHostGroups` - Export IP host groups to file
- `Import-SfosIpHostGroups` - Import IP host groups from file

### FQDN Host Management (7 functions)
- `Get-SfosFqdnHost` - Retrieve all FQDN hosts
- `New-SfosFqdnHost` - Create new FQDN host with hostname
- `Set-SfosFqdnHost` - Update existing FQDN host properties
- `Remove-SfosFqdnHost` - Delete FQDN host from firewall
- `Remove-SfosFqdnHostMass` - Delete multiple FQDN hosts in bulk
- `Export-SfosFqdnHosts` - Export FQDN hosts to file
- `Import-SfosFqdnHosts` - Import FQDN hosts from file

### FQDN Host Group Management (8 functions)
- `Get-SfosFqdnHostGroup` - Retrieve all FQDN host groups and members
- `New-SfosFqdnHostGroup` - Create new FQDN host group
- `Set-SfosFqdnHostGroup` - Update existing FQDN host group properties
- `Remove-SfosFqdnHostGroup` - Delete FQDN host group from firewall
- `Add-SfosFqdnHostGroupMember` - Add host to FQDN host group
- `Remove-SfosFqdnHostGroupMember` - Remove host from FQDN host group
- `Export-SfosFqdnHostGroups` - Export FQDN host groups to file
- `Import-SfosFqdnHostGroups` - Import FQDN host groups from file

### MAC Host Management (6 functions)
- `Get-SfosMacHost` - Retrieve all MAC-based hosts
- `New-SfosMacHost` - Create new MAC host with MAC address
- `Set-SfosMacHost` - Update existing MAC host properties
- `Remove-SfosMacHost` - Delete MAC host from firewall
- `Export-SfosMacHosts` - Export MAC hosts to file
- `Import-SfosMacHosts` - Import MAC hosts from file

### Country Host Group Management (4 functions)
- `Get-SfosCountryHostGroup` - Retrieve all country host groups
- `New-SfosCountryHostGroup` - Create new country host group with countries
- `Set-SfosCountryHostGroup` - Update existing country host group properties
- `Remove-SfosCountryHostGroup` - Delete country host group from firewall

### Service Management (6 functions)
- `Get-SfosService` - Retrieve all service definitions
- `New-SfosService` - Create new service (TCP/UDP with port or port range)
- `Set-SfosService` - Update existing service properties
- `Remove-SfosService` - Delete service from firewall
- `Export-SfosServices` - Export services to file
- `Import-SfosServices` - Import services from file

### Service Group Management (8 functions)
- `Get-SfosServiceGroup` - Retrieve all service groups and members
- `New-SfosServiceGroup` - Create new service group
- `Set-SfosServiceGroup` - Update existing service group properties
- `Remove-SfosServiceGroup` - Delete service group from firewall
- `Add-SfosServiceGroupMember` - Add service to service group
- `Remove-SfosServiceGroupMember` - Remove service from service group
- `Export-SfosServiceGroups` - Export service groups to file
- `Import-SfosServiceGroups` - Import service groups from file


## Error Handling

```powershell
try {
    # Connect with proper error handling
    Connect-SfosFirewall -Firewall "192.168.1.1" -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck
    
    # Retrieve specific IP host with error handling
    $host = Get-SfosIpHost -Name "CORP-WEB-01" -ErrorAction Stop
    Write-Output "Found host: $($host.Name) - IP: $($host.IpAddress)"
} catch {
    Write-Error "Failed to retrieve IP host: $_"
    $_.Exception
} finally {
    Disconnect-SfosFirewall
}
```

## Troubleshooting

- **Connection Issues**: Ensure firewall IP, port (4444 default), and credentials are correct
- **Object Not Found**: Use `Get-SfosIpHost | Select-Object Name` to list all available objects
- **Permission Denied**: Verify API user has proper role assignments on the firewall
- **Invalid Parameters**: Check exact parameter names - functions are type-specific (IpHost, FqdnHost, MacHost)

## See Also

- [SophosFirewall.Core](../SophosFirewall.Core/README.md) - Core connectivity functions (Connect-SfosFirewall, Disconnect-SfosFirewall, Invoke-SfosApi)
- [Sophos API Documentation](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/) - Official Sophos firewall REST API reference
- [PowerShell Gallery](https://www.powershellgallery.com/packages/SophosFirewall.HostAndServices) - Download module from PSGallery

## Author

Jan Weis - www.it-explorations.de

## License

