#requires -Version 5.1
#requires -Modules SophosFirewall.Core

<#
        .SYNOPSIS
        Manages IP hosts, FQDN hosts, MAC hosts, host groups, services, and service groups on Sophos Firewall.

        .DESCRIPTION
        PowerShell module for comprehensive management of Sophos XGS / SFOS 21.5+ firewall 
        hosts and services via XML REST API.
    
        This module provides functions to create, read, update, and delete:
        - IP Hosts (single IPs, networks, ranges, lists)
        - IP Host Groups (with member management)
        - FQDN Hosts and FQDN Host Groups (with member management)
        - MAC Hosts
        - Country Host Groups
        - Services (TCP/UDP, IP protocols, ICMP/ICMPv6)
        - Service Groups (with member management)
    
        All functions support pipeline input, filtering, and connection context management.
        Use Connect-SfosFirewall once, then call functions without connection parameters.

        .EXAMPLE
        # Connect to firewall and retrieve all IP hosts
        Connect-SfosFirewall -Firewall "192.168.1.1" -Credential (Get-Credential) -SkipCertificateCheck
        Get-SfosIpHost

        .EXAMPLE
        # Create a new IP host and add it to a host group
        New-SfosIpHost -Name "WebServer01" -IPAddress "10.0.1.100" -HostType IP -Description "Production Web Server"
        Add-SfosIpHostGroupMember -Name "WebServers" -Members "WebServer01"

        .EXAMPLE
        # Find all hosts matching a pattern
        Get-SfosIpHost -NameLike "Web*" -IPAddressLike "10.0.*"
        Get-SfosFqdnHost -FqdnLike "*.example.com"

        .EXAMPLE
        # Create a TCP service and add to service group
        New-SfosService -Name "CustomHTTPS" -Protocol TCP -DstPort 8443 -SrcPort "1:65535" -Description "Custom HTTPS Port"
        Add-SfosServiceGroupMember -ServiceGroupName "WebServices" -Members "CustomHTTPS"

        .EXAMPLE
        # Create IP network and range hosts
        New-SfosIpHost -Name "Office-Network" -HostType Network -IPAddress "192.168.10.0" -Subnet "255.255.255.0"
        New-SfosIpHost -Name "DHCP-Range" -HostType IPRange -StartIPAddress "192.168.10.100" -EndIPAddress "192.168.10.200"

        .EXAMPLE
        # Pipeline operations for bulk removal (with WhatIf safety)
        Get-SfosIpHost -NameLike "OldServer*" | Remove-SfosIpHost -WhatIf
        Get-SfosService -NameLike "Deprecated*" | Remove-SfosService -WhatIf

        .EXAMPLE
        # Work with service groups
        $webServices = Get-SfosServiceGroup -NameLike "Web*"
        $webServices | ForEach-Object { $_.ServiceList }

        .NOTES
        Module Name: SophosFirewall.HostAndServices
        Author: Jan Weis
        Homepage: https://www.it-explorations.de
        Version: 1.0.0
        PowerShell Version: 5.1+
    
        Dependencies:
        - SophosFirewall.Core module (provides Connect-SfosFirewall, Invoke-SfosApi, etc.)
    
        API Compatibility:
        - Sophos SFOS 21.5+
        - Sophos XGS Firewall Series
    
        Total Functions: 39
        - 8 IP Host functions (Get, New, Set, Remove, Group operations)
        - 6 IP Host Group functions (including Add/Remove members)
        - 4 FQDN Host functions (including mass removal)
        - 6 FQDN Host Group functions (including Add/Remove members)
        - 4 MAC Host functions
        - 4 Country Host Group functions
        - 4 Service functions (supports TCP/UDP, IP protocols, ICMP/ICMPv6)
        - 3 Service Group functions (including Add/Remove members)
    
        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
    
        .LINK
        Connect-SfosFirewall
    
        .LINK
        Get-SfosIpHost
    
        .LINK
        Get-SfosService
#>

# Helper functions are provided by SophosFirewall.Core module
# Module dependency is handled via RequiredModules in .psd1

#region IPHost

<#
        .SYNOPSIS
        Retrieves IpHost objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for IpHost objects. By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.
    
        Note: Sophos GET responses can be inconsistent regarding status elements. This cmdlet is designed to return an empty result when no records are found.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER NameLike
        Optional name filter. In Sophos SFOS, 'like' behaves as a substring match (the supplied value may match anywhere in the object name).

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .PARAMETER AsXml
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve all objects
        Get-SfosIpHost

        .EXAMPLE
        # Filter by name (substring match)
        Get-SfosIpHost -NameLike "Example"

        .EXAMPLE
        # Return raw XML for troubleshooting
        Get-SfosIpHost -NameLike "Example" -AsXml

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/21.5/api/
#>
function Get-SfosIpHost 
{
    [CmdletBinding()]
    param(
        # Functional parameters
        [ValidateLength(1, 60)]
        [string]$NameLike,

        [ValidateLength(1, 255)]
        [string]$DescriptionLike,
        
        [ValidateLength(1, 15)]
        [string]$IPAddressLike,

        [ValidateSet('IP', 'Network', 'IPRange', 'IPList')]
        [string]$HostTypeLike,
        
        [ValidateLength(1, 15)]
        [string]$SubnetLike,
        
        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        
        # Output parameters
        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Build server-side filter criteria
    $filterXml = ''
    if($NameLike) 
    {
        $nameLikeEsc = ConvertTo-SfosXmlEscaped -Text $NameLike
        $filterXml = ('<key name="Name" criteria="like">{0}</key>' -f $nameLikeEsc)
    }
    
    if($DescriptionLike) 
    {
        $descLikeEsc = ConvertTo-SfosXmlEscaped -Text $DescriptionLike
        $filterXml += ('<key name="Description" criteria="like">{0}</key>' -f $descLikeEsc)
    }

    if($IPAddressLike) 
    {
        $ipLikeEsc = ConvertTo-SfosXmlEscaped -Text $IPAddressLike
        $filterXml += ('<key name="IPAddress" criteria="like">{0}</key>' -f $ipLikeEsc)
    }
    
    $xmlFilterAdvanced = ''
    if($filterXml)
    {
        $xmlFilterAdvanced = @"
<Filter>
    $filterXml
</Filter>
"@
    }

    # Client-side filter for subnet/host type (API supports exact match only)
    if($SubnetLike -or $HostTypeLike) 
    {
        $ipHostList = Get-SfosIpHost

        $filteredList = @()
        if($SubnetLike) 
        {
            $filteredList += $ipHostList | Where-Object -FilterScript {
                $_.Subnet -like $SubnetLike
            }
        }

        if($HostTypeLike) 
        {
            $filteredList += $ipHostList | Where-Object -FilterScript {
                $_.HostType -eq $HostTypeLike
            }
        }

        $filteredIpHostList = $filteredList | Sort-Object -Property Name -Unique

        return $filteredIpHostList
    }

    # Build XML body for the API call
    $inner = @"
<Get>
  <IPHost>
    $xmlFilterAdvanced
  </IPHost>
</Get>
"@
    # Execute API call
    try 
    {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch 
    {
        throw "Failed to retrieve IPHost objects: $($_.Exception.Message)"
    }
    $XmlResponse = [xml]($response.Content)

    # Extract IPHost nodes
    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/IPHost[Name]' | ForEach-Object -Process {
        $_.Node
    }

    # Return raw nodes when -AsXml is used
    if ($AsXml) 
    {
        return @($nodes)
    }

    # Build PSObjects
    $ipHostObjects = @()
    foreach ($node in $nodes) 
    {
        if(-not $node) 
        {
            continue
        }

        $ipHostObjects += [PSCustomObject]@{
            Name           = $node.Name
            IPFamily       = $node.IPFamily
            HostType       = $node.HostType
            IPAddress      = $node.IPAddress
            Subnet         = $node.Subnet
            Description    = $node.Description
            StartIPAddress = $node.StartIPAddress
            EndIPAddress   = $node.EndIPAddress
            HostGroupList  = if ($node.HostGroupList -and $node.HostGroupList.HostGroup) 
            {
                @($node.HostGroupList.HostGroup)
            }
            else 
            {
                @()
            }
        }
    }

    return $ipHostObjects
}

<#
        .SYNOPSIS
        Creates a new IP host object on the Sophos Firewall.

        .DESCRIPTION
        Creates an IP host object using the Sophos Firewall XML API. Supports four host types:
        - IP: Single IP address
        - Network: Network address with subnet mask
        - IPRange: IP address range (start to end)
        - IPList: Comma-separated list of IP addresses
        
        The cmdlet validates input and escapes XML special characters automatically.

        .PARAMETER Name
        Name of the IP host object (1-50 characters, no commas).

        .PARAMETER HostType
        Type of IP host: 'IP', 'Network', 'IPRange', or 'IPList'.

        .PARAMETER IPAddress
        IP address (required for HostType 'IP' and 'Network').

        .PARAMETER Subnet
        Subnet mask (required for HostType 'Network'). Example: 255.255.255.0

        .PARAMETER StartIPAddress
        Starting IP address (required for HostType 'IPRange').

        .PARAMETER EndIPAddress
        Ending IP address (required for HostType 'IPRange').

        .PARAMETER ListOfIPAddresses
        Array of IP addresses (required for HostType 'IPList').

        .PARAMETER IPFamily
        IP address family: 'IPv4' or 'IPv6'. Default: 'IPv4'.

        .PARAMETER Description
        Optional description (max 255 characters).

        .PARAMETER HostGroupList
        Optional array of host group names to add this host to.

        # Connection parameters (optional - use stored context if not provided)
        
        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses stored connection context.

        .PARAMETER Port
        Management/API port number. If omitted, uses stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation.

        .OUTPUTS
        None. Throws an exception if creation fails.

        .EXAMPLE
        # Create a single IP host
        New-SfosIpHost -Name "WebServer01" -HostType IP -IPAddress "10.0.1.100" -Description "Production Web Server"

        .EXAMPLE
        # Create a network host
        New-SfosIpHost -Name "Office-LAN" -HostType Network -IPAddress "192.168.10.0" -Subnet "255.255.255.0"

        .EXAMPLE
        # Create an IP range for DHCP pool
        New-SfosIpHost -Name "DHCP-Pool" -HostType IPRange -StartIPAddress "192.168.10.100" -EndIPAddress "192.168.10.200"

        .EXAMPLE
        # Create an IP list with multiple addresses
        New-SfosIpHost -Name "DMZ-Servers" -HostType IPList -ListOfIPAddresses @("10.1.1.10", "10.1.1.20", "10.1.1.30")

        .EXAMPLE
        # Create host and add to group
        New-SfosIpHost -Name "DB-Server" -HostType IP -IPAddress "10.0.2.50" -HostGroupList @("DatabaseServers", "Production")

        .NOTES
        Minimum supported PowerShell version: 5.1
        This function uses parameter sets to enforce correct parameter combinations.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
        
        .LINK
        Get-SfosIpHost
        
        .LINK
        Set-SfosIpHost
        
        .LINK
        Remove-SfosIpHost
#>
function New-SfosIpHost 
{
    [CmdletBinding(DefaultParameterSetName = 'IP')]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [ValidateSet('IPv4', 'IPv6')]
        [string]$IPFamily = 'IPv4',
        
        [ValidateLength(0, 255)]
        [string]$Description,
        
        [Parameter(Mandatory, ParameterSetName = 'IP')]
        [Parameter(Mandatory, ParameterSetName = 'Network')]
        [Parameter(Mandatory, ParameterSetName = 'IPRange')]
        [Parameter(Mandatory, ParameterSetName = 'IPList')]
        [Parameter(Mandatory)]
        [ValidateSet('IP','Network','IPRange','IPList')]
        [string]$HostType,

        # --- IP ---
        [Parameter(Mandatory, ParameterSetName = 'IP')]
        [Parameter(Mandatory, ParameterSetName = 'Network')]
        [IPAddress]$IPAddress,
        
        # --- NETWORK ---
        [Parameter(Mandatory, ParameterSetName = 'Network')]
        [string]$Subnet,

        # --- IPRange ---
        [Parameter(Mandatory, ParameterSetName = 'IPRange')]
        [IPAddress]$StartIPAddress,

        [Parameter(Mandatory, ParameterSetName = 'IPRange')]
        [IPAddress]$EndIPAddress,

        # --- IPList ---
        [Parameter(Mandatory, ParameterSetName = 'IPList')]
        [IPAddress[]]$ListOfIPAddresses,
        
        [string[]]$HostGroupList,
        
        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    # Preparations
    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

    # Setup Description XML
    $xmlDescription = ''
    if ($Description) 
    {
        $descEsc = ConvertTo-SfosXmlEscaped -Text $Description
        $xmlDescription = "<Description>$descEsc</Description>"
    }
    
    # Setup HostGroup XML
    $xmlHostGroupList = ''
    if ($HostGroupList) 
    {
        $hostGroupXml = ''
        foreach ($hostGroupItem in $HostGroupList) 
        {
            if (-not $hostGroupItem) 
            {
                continue
            }
            if ($hostGroupItem.Length -gt 50) 
            {
                throw "HostGroup entry '$hostGroupItem' must be at most 50 characters."
            }
            if ($hostGroupItem -match '^[#,]') 
            {
                throw "HostGroup entry '$hostGroupItem' must not start with '#' or ','."
            }
            if ($hostGroupItem -match ',') 
            {
                throw "HostGroup entry '$hostGroupItem' must not contain a comma."
            }
            $hgEsc = ConvertTo-SfosXmlEscaped -Text $hostGroupItem
            $hostGroupXml += "<HostGroup>$hgEsc</HostGroup>"
        }
        
        $xmlHostGroupList = @"
<HostGroupList>
    $hostGroupXml
</HostGroupList>
"@
    }


    # Build Data IP/Network/IPRange/IPList Data XML
    $xmlIpHost = @()
    switch ($PSCmdlet.ParameterSetName) {
        'IP' 
        {
            $xmlIpHost += "<IPAddress>$($IPAddress.IPAddressToString)</IPAddress>"
        }
        'Network' 
        {
            $xmlIpHost += "<IPAddress>$($IPAddress.IPAddressToString)</IPAddress>"
            $xmlIpHost += "<Subnet>$Subnet</Subnet>"
        }
        'IPRange' 
        {
            $xmlIpHost += "<StartIPAddress>$($StartIPAddress.IPAddressToString)</StartIPAddress>"
            $xmlIpHost += "<EndIPAddress>$($EndIPAddress.IPAddressToString)</EndIPAddress>"
        }
        'IPList' 
        {
            $joinedIPs = ($ListOfIPAddresses | ForEach-Object -Process {
                    $_.IPAddressToString
            }) -join ','
            $xmlIpHost = "<ListOfIPAddresses>$joinedIPs</ListOfIPAddresses>"
        }
    }

    # Build final XML
    $inner = @"
<Set operation="add">
    <IPHost>
        <Name>$nameEsc</Name>
        <IPFamily>$IPFamily</IPFamily>
        $xmlDescription
        <HostType>$HostType</HostType>
        $xmlIpHost
        $xmlHostGroupList
    </IPHost>
</Set>
"@

    # Send API command
    try 
    {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch 
    {
        throw "Failed to update IPHost object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Validate responses
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'IPHost' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Updates an existing IpHost object on the Sophos Firewall.

        .DESCRIPTION
        Updates a IpHost object using the Sophos Firewall XML API. You can supply the target object name directly or via the pipeline (when supported by the function's parameters).

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER IPFamily
        IP address or CIDR value, depending on the cmdlet.

        .PARAMETER HostGroup
        Parameter used by this cmdlet.

        .PARAMETER Description
        Optional description text.

        .PARAMETER IPAddress
        IP address or CIDR value, depending on the cmdlet.

        .PARAMETER NetworkAddress
        Parameter used by this cmdlet.

        .PARAMETER CIDR
        CIDR prefix length.

        .PARAMETER StartIPAddress
        IP address or CIDR value, depending on the cmdlet.

        .PARAMETER EndIPAddress
        IP address or CIDR value, depending on the cmdlet.

        .PARAMETER ListOfIPAddresses
        IP address or CIDR value, depending on the cmdlet.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Update an object by name
        Set-SfosIpHost -Name "Example"

        .EXAMPLE
        # Update using pipeline input
        Get-SfosIpHost -NameLike "Example" | Set-SfosIpHost  # when pipeline is supported

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/21.5/api/
#>
function Set-SfosIpHost 
{
    [CmdletBinding(DefaultParameterSetName = 'IP')]
    param(
        [Parameter(Mandatory, ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('IPv4', 'IPv6')]
        [string]$IPFamily = 'IPv4',
        
        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(0, 255)]
        [string]$Description,
        
        [Parameter(ValueFromPipelineByPropertyName)]
        [Parameter(Mandatory, ParameterSetName = 'IP')]
        [Parameter(Mandatory, ParameterSetName = 'Network')]
        [Parameter(Mandatory, ParameterSetName = 'IPRange')]
        [Parameter(Mandatory, ParameterSetName = 'IPList')]
        [Parameter(Mandatory)]
        [ValidateSet('IP','Network','IPRange','IPList')]
        [string]$HostType,

        # --- IP ---
        [Parameter(ValueFromPipelineByPropertyName)]
        [Parameter(Mandatory, ParameterSetName = 'IP')]
        [Parameter(Mandatory, ParameterSetName = 'Network')]
        [IPAddress]$IPAddress,
        
        # --- NETWORK ---
        [Parameter(ValueFromPipelineByPropertyName)]
        [Parameter(Mandatory, ParameterSetName = 'Network')]
        [string]$Subnet,

        # --- IPRange ---
        [Parameter(ValueFromPipelineByPropertyName)]
        [Parameter(Mandatory, ParameterSetName = 'IPRange')]
        [IPAddress]$StartIPAddress,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Parameter(Mandatory, ParameterSetName = 'IPRange')]
        [IPAddress]$EndIPAddress,

        # --- IPList ---
        [Parameter(ValueFromPipelineByPropertyName)]
        [Parameter(Mandatory, ParameterSetName = 'IPList')]
        [IPAddress[]]$ListOfIPAddresses,
        
        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]$HostGroupList,
        
        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    # Preparations
    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

    # Setup Description XML
    $xmlDescription = ''
    if ($Description) 
    {
        $descEsc = ConvertTo-SfosXmlEscaped -Text $Description
        $xmlDescription = "<Description>$descEsc</Description>"
    }
    
    # Setup HostGroup XML
    $xmlHostGroupList = ''
    if ($HostGroupList) 
    {
        $hostGroupXml = ''
        foreach ($hostGroupItem in $HostGroupList) 
        {
            if (-not $hostGroupItem) 
            {
                continue
            }
            if ($hostGroupItem.Length -gt 50) 
            {
                throw "HostGroup entry '$hostGroupItem' must be at most 50 characters."
            }
            if ($hostGroupItem -match '^[#,]') 
            {
                throw "HostGroup entry '$hostGroupItem' must not start with '#' or ','."
            }
            if ($hostGroupItem -match ',') 
            {
                throw "HostGroup entry '$hostGroupItem' must not contain a comma."
            }
            $hgEsc = ConvertTo-SfosXmlEscaped -Text $hostGroupItem
            $hostGroupXml += "<HostGroup>$hgEsc</HostGroup>"
        }
        
        $xmlHostGroupList = @"
<HostGroupList>
    $hostGroupXml
</HostGroupList>
"@
    }


    # Build Data IP/Network/IPRange/IPList Data XML
    $xmlIpHost = ''
    switch ($PSCmdlet.ParameterSetName) {
        'IP' 
        {
            $xmlIpHost += "<IPAddress>$($IPAddress.IPAddressToString)</IPAddress>"
        }
        'Network' 
        {
            $xmlIpHost += "<IPAddress>$($IPAddress.IPAddressToString)</IPAddress>"
            $xmlIpHost += "<Subnet>$Subnet</Subnet>"
        }
        'IPRange' 
        {
            $xmlIpHost += "<StartIPAddress>$($StartIPAddress.IPAddressToString)</StartIPAddress>"
            $xmlIpHost += "<EndIPAddress>$($EndIPAddress.IPAddressToString)</EndIPAddress>"
        }
        'IPList' 
        {
            $joinedIPs = ($ListOfIPAddresses | ForEach-Object -Process {
                    $_.IPAddressToString
            }) -join ','
            $xmlIpHost = "<ListOfIPAddresses>$joinedIPs</ListOfIPAddresses>"
        }
    }

    # Build final XML
    $inner = @"
<Set operation="edit">
    <IPHost>
        <Name>$nameEsc</Name>
        <IPFamily>$IPFamily</IPFamily>
        $xmlDescription
        <HostType>$HostType</HostType>
        $xmlIpHost
        $xmlHostGroupList
    </IPHost>
</Set>
"@

    # Send API command
    try 
    {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch 
    {
        throw "Failed to create IPHost object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Validate responses
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'IPHost' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Removes a IpHost object from the Sophos Firewall.

        .DESCRIPTION
        Removes a IpHost object using the Sophos Firewall XML API. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Preview removal
        Remove-SfosIpHost -Name "Example" -WhatIf

        .EXAMPLE
        # Pipeline removal preview
        Remove-SfosIpHost -Name "Example" -WhatIf

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/21.5/api/
#>
function Remove-SfosIpHost 
{
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        if (-not $PSCmdlet.ShouldProcess("IPHost '$Name' on $($params.Firewall)", 'Remove')) 
        {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <IPHost>
    <Name>$nameEsc</Name>
  </IPHost>
</Remove>
"@

        try 
        {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch 
        {
            throw "Error removing IPHost object '': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'IPHost' -Action 'remove' -Target $Name
    }
    end {
    }
}

<#
        .SYNOPSIS
        Exports all IpHost objects to a CSV file.

        .DESCRIPTION
        Retrieves all IpHost objects from the Sophos Firewall and exports them to a CSV file at the specified path. If the file already exists, an error is thrown unless the -Overwrite switch is used.

        .PARAMETER FilePath
        Full path to the output CSV file.

        .PARAMETER Overwrite
        Optional switch to overwrite the file if it already exists.

        .OUTPUTS
        None. The function writes the output to a CSV file.

        .EXAMPLE
        # Export IP hosts to a CSV file
        Export-SfosIpHosts -FilePath "C:\Exports\SophosIpHosts.csv"

        .EXAMPLE
        # Export and overwrite existing file
        Export-SfosIpHosts -FilePath "C:\Exports\SophosIpHosts.csv" -Overwrite

        .NOTES
        Minimum supported PowerShell version: 5.1
        This function depends on Get-SfosIpHost to retrieve the data.

        .LINK
        Get-SfosIpHost
#>
function Export-SfosIpHosts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [ValidateSet('AsCSV', 'AsJSON')]
        [ValidateNotNullOrEmpty()]
        [string]$Format = 'AsCSV',

        # Optional overwrite switch
        [switch]$Overwrite,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    # Check if file exists
    if (Test-Path -Path $FilePath) {
        if ($Overwrite) {
            Remove-Item -Path $FilePath -Force
        }
        else {
            throw "The file '$FilePath' already exists. Please specify a different file name."
        }
    }
    
    # Resolve connection parameters
    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Retrieve IP hosts
    $ipHosts = Get-SfosIpHost -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    # Export to CSV or JSON
    try {
        if ($Format -eq 'AsCSV') {
            $ipHosts | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
        }
        else {
            $ipHosts | ConvertTo-Json | Out-File -FilePath $FilePath -Encoding UTF8
        }

        Write-Information "Exported IP hosts to '$FilePath' successfully." -InformationAction Continue
    }
    catch {
        throw "Failed to export IP hosts to '$FilePath': $($_.Exception.Message)"
    }
}

<#
        .SYNOPSIS
        Imports IpHost objects from a CSV file.

        .DESCRIPTION
        Reads IpHost objects from a specified CSV file and creates them on the Sophos Firewall using the New-SfosIpHost cmdlet. The CSV file must have the appropriate headers matching the IpHost properties.

        .PARAMETER FilePath
        Full path to the input CSV file.

        .OUTPUTS
        None. The function creates IpHost objects on the Sophos Firewall.

        .EXAMPLE
        # Import IP hosts from a CSV file
        Import-SfosIpHosts -FilePath "C:\Imports\SophosIpHosts.csv"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This function depends on New-SfosIpHost to create the objects.

        .LINK
        New-SfosIpHost
#>
function Import-SfosIpHosts {
    [CmdletBinding()]
    param(
        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [ValidateSet('AsCSV', 'AsJSON')]
        [string]$Format = 'AsCSV',

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )
    
    if (-not (Test-Path -Path $FilePath)) {
        throw "The file '$FilePath' was not found."
    }

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    
    try {
        $ipHosts = Import-Csv -Path $FilePath -Encoding UTF8
    }
    catch {
        throw "Failed to import IP hosts from '$FilePath': $($_.Exception.Message)"
    }

    foreach ($ipHost in $ipHosts) {

        if (-not $ipHost.Name) {
            Write-Information "Skipping entry without Name." -InformationAction Continue
            continue
        }

        if ($ipHost.Name.StartsWith('#')) {
            Write-Information "Skipping commented entry: $($ipHost.Name)" -InformationAction Continue
            continue
        }

        if($ipHost.HostType -notin @('IP','Network','IPRange','IPList')) {
            Write-Information "Skipping entry with invalid HostType '$($ipHost.HostType)': $($ipHost.Name)" -InformationAction Continue
            continue
        }

        switch($ipHost.HostType) {
            'IP' {
                if (-not $ipHost.IPAddress) {
                    Write-Information "Skipping IP host without IPAddress: $($ipHost.Name)" -InformationAction Continue
                    continue
                }
            }
            'Network' {
                if (-not $ipHost.IPAddress -or -not $ipHost.Subnet) {
                    Write-Information "Skipping Network host without IPAddress or Subnet: $($ipHost.Name)" -InformationAction Continue
                    continue
                }
            }
            'IPRange' {
                if (-not $ipHost.StartIPAddress -or -not $ipHost.EndIPAddress) {
                    Write-Information "Skipping IPRange host without StartIPAddress or EndIPAddress: $($ipHost.Name)" -InformationAction Continue
                    continue
                }
            }
            'IPList' {
                if (-not $ipHost.ListOfIPAddresses) {
                    Write-Information "Skipping IPList host without ListOfIPAddresses: $($ipHost.Name)" -InformationAction Continue
                    continue
                }
            }
            default {
                Write-Information "Skipping entry with invalid HostType '$($ipHost.HostType)': $($ipHost.Name)" -InformationAction Continue
                continue
            }
        }

        try {

            if ($ipHost.HostType -eq 'IP') {
                New-SfosIpHost -Name $ipHost.Name -IPFamily $ipHost.IPFamily -Description $ipHost.Description -HostType $ipHost.HostType -IPAddress $ipHost.IPAddress `
                    -HostGroupList ($ipHost.HostGroupList -split ',') -Firewall $params.Firewall -Port $params.Port -Username $params.Username -Password $params.Password `
                    -SkipCertificateCheck:$params.SkipCertificateCheck
            }
            elseif ($ipHost.HostType -eq 'Network') {
                New-SfosIpHost -Name $ipHost.Name -IPFamily $ipHost.IPFamily -Description $ipHost.Description -HostType $ipHost.HostType -IPAddress $ipHost.IPAddress `
                    -Subnet $ipHost.Subnet -HostGroupList ($ipHost.HostGroupList -split ',') -Firewall $params.Firewall -Port $params.Port -Username $params.Username `
                    -Password $params.Password -SkipCertificateCheck:$params.SkipCertificateCheck
            }
            elseif ($ipHost.HostType -eq 'IPRange') {
                New-SfosIpHost -Name $ipHost.Name -IPFamily $ipHost.IPFamily -Description $ipHost.Description -HostType $ipHost.HostType -StartIPAddress $ipHost.StartIPAddress `
                    -EndIPAddress $ipHost.EndIPAddress -HostGroupList ($ipHost.HostGroupList -split ',') -Firewall $params.Firewall -Port $params.Port -Username $params.Username `
                    -Password $params.Password -SkipCertificateCheck:$params.SkipCertificateCheck
            }
            elseif ($ipHost.HostType -eq 'IPList') {
                New-SfosIpHost -Name $ipHost.Name -IPFamily $ipHost.IPFamily -Description $ipHost.Description -HostType $ipHost.HostType -ListOfIPAddresses ($ipHost.ListOfIPAddresses -split ',') `
                    -HostGroupList ($ipHost.HostGroupList -split ',') -Firewall $params.Firewall -Port $params.Port -Username $params.Username -Password $params.Password `
                    -SkipCertificateCheck:$params.SkipCertificateCheck
            }
            else {
                throw "Invalid HostType '$($ipHost.HostType)' for IP host: $($ipHost.Name)"
            }

            Write-Information "Imported: $($ipHost.Name)" -InformationAction Continue
        }
        catch {
            Write-Information "Failed to import '$($ipHost.Name)': $($_.Exception.Message)" -InformationAction Continue
        }
    }
}


#endregion IPHost

#region IPHostGroup

<#
        .SYNOPSIS
        Retrieves IpHostGroup objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for IpHostGroup objects. By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.
    
        Note: Sophos GET responses can be inconsistent regarding status elements. This cmdlet is designed to return an empty result when no records are found.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER NameLike
        Optional name filter. In Sophos SFOS, 'like' behaves as a substring match (the supplied value may match anywhere in the object name).

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .PARAMETER AsXml
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve all objects
        Get-SfosIpHostGroup

        .EXAMPLE
        # Filter by name (substring match)
        Get-SfosIpHostGroup -NameLike "Example"

        .EXAMPLE
        # Return raw XML for troubleshooting
        Get-SfosIpHostGroup -NameLike "Example" -AsXml

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/21.5/api/
#>
function Get-SfosIpHostGroup 
{
    [CmdletBinding()]
    param(
        # Functional parameters
        [string]$NameLike,
        [string]$DescriptionLike,
        
        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        
        # Output parameters
        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $filterXml = ''
    if ($NameLike) 
    {
        $nameLikeEsc = ConvertTo-SfosXmlEscaped -Text $NameLike
        $filterXml = ('<Filter><key name="Name" criteria="like">{0}</key></Filter>' -f $nameLikeEsc)
    }

    if ($DescriptionLike) 
    {
        $descLikeEsc = ConvertTo-SfosXmlEscaped -Text $DescriptionLike
        $filterXml += ('<Filter><key name="Description" criteria="like">{0}</key></Filter>' -f $descLikeEsc)
    }

    $inner = @"
<Get>
  <IPHostGroup>
    $filterXml
  </IPHostGroup>
</Get>
"@

    try 
    {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch 
    {
        throw "Error retrieving IPHostGroup objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Check login status
    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/IPHostGroup[Name]' | ForEach-Object -Process {
        $_.Node
    }

    if ($AsXml) 
    {
        return @($nodes)
    }

    # Erstelle PSCustomObjects
    $ipHostGroupObjects = @()
    foreach ($node in $nodes) 
    {
        $ipHostGroupObjects += [PSCustomObject]@{
            Name        = $node.Name
            Description = $node.Description
            HostList    = [string[]]($node.HostList | Select-Object -ExpandProperty Host)
        }
    }

    return $ipHostGroupObjects
}

<#
        .SYNOPSIS
        Creates a new IP host group on the Sophos Firewall.

        .DESCRIPTION
        Creates an IP host group that can contain multiple IP host objects.
        Use this to logically group related hosts for easier firewall rule management.
        After creation, use Add-SfosIpHostGroupMember to add additional members.

        .PARAMETER Name
        Name of the IP host group (1-50 characters, no commas).

        .PARAMETER IPFamily
        IP address family: 'IPv4' or 'IPv6'. Default: 'IPv4'.

        .PARAMETER Members
        Array of IP host names to include in the group.

        .PARAMETER Description
        Optional description (max 255 characters).

        # Connection parameters (optional - use stored context if not provided)
        
        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses stored connection context.

        .PARAMETER Port
        Management/API port number. If omitted, uses stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation.

        .OUTPUTS
        None. Throws an exception if creation fails.

        .EXAMPLE
        # Create an empty host group
        New-SfosIpHostGroup -Name "WebServers" -Description "Production web server farm"

        .EXAMPLE
        # Create group with initial members
        New-SfosIpHostGroup -Name "DatabaseServers" -Members @("DB-Primary", "DB-Secondary") -Description "Database cluster"

        .EXAMPLE
        # Create group and add members separately
        New-SfosIpHostGroup -Name "OfficeHosts" -Description "Office network devices"
        Add-SfosIpHostGroupMember -Name "OfficeHosts" -Members @("Printer01", "Scanner01")

        .NOTES
        Minimum supported PowerShell version: 5.1

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
        
        .LINK
        Get-SfosIpHostGroup
        
        .LINK
        Add-SfosIpHostGroupMember
#>
function New-SfosIpHostGroup 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [ValidateSet('IPv4','IPv6')]
        [string]$IPFamily = 'IPv4',

        [string[]]$members,

        [ValidateLength(0, 255)]
        [string]$Description,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

    if ($Description) 
    {
        $descEsc = ConvertTo-SfosXmlEscaped -Text $Description
    }

    $xmlMember = ''
    foreach ($member in $members) 
    {
        if (-not $member) 
        {
            continue
        }
        if ($member.Length -gt 50) 
        {
            throw "Member '' must be 50 characters or fewer."
        }
        if ($member -match ',') 
        {
            throw "Member '' cannot contain a comma."
        }
        $mEsc = ConvertTo-SfosXmlEscaped -Text $member
        $xmlMember += "<Member>$mEsc</Member>"
    }

    $inner = @"
<Set operation="add">
  <IPHostGroup>
    <Name>$nameEsc</Name>
    <IPFamily>$IPFamily</IPFamily>
    <Description>$descEsc</Description>
    <HostList>
        $xmlMember
    </HostList> 
  </IPHostGroup>
</Set>
"@

    try 
    {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch 
    {
        throw "Error creating IPHostGroup object '': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Check login status
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'IPHostGroup' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Updates an existing IpHostGroup object on the Sophos Firewall.

        .DESCRIPTION
        Updates a IpHostGroup object using the Sophos Firewall XML API. You can supply the target object name directly or via the pipeline (when supported by the function's parameters).

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER Members
        One or more member object names to include.

        .PARAMETER Description
        Optional description text.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Update an object by name
        Set-SfosIpHostGroup -Name "Example"

        .EXAMPLE
        # Update using pipeline input
        Get-SfosIpHostGroup -NameLike "Example" | Set-SfosIpHostGroup  # when pipeline is supported

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/21.5/api/
#>
function Set-SfosIpHostGroup 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,
        
        [ValidateSet('IPv4','IPv6')]
        [string]$IPFamily = 'IPv4',
        
        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]$members,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(0, 255)]
        [string]$Description,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        if ($Description) 
        {
            $descEsc = ConvertTo-SfosXmlEscaped -Text $Description
        }

        $xmlMember = ''
        foreach ($member in $members) 
        {
            if (-not $member) 
            {
                continue
            }
            if ($member.Length -gt 50) 
            {
                throw "Member '' must be 50 characters or fewer."
            }
            if ($member -match ',') 
            {
                throw "Member '' cannot contain a comma."
            }
            $mEsc = ConvertTo-SfosXmlEscaped -Text $member
            $xmlMember += "<Member>$mEsc</Member>"
        }

        $inner = @"
<Set operation="edit">
  <IPHostGroup>
    <Name>$nameEsc</Name>
    <IPFamily>$IPFamily</IPFamily>
    <Description>$descEsc</Description>
    <HostList>
        $xmlMember
    </HostList> 
  </IPHostGroup>
</Set>
"@

        try 
        {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch 
        {
            throw "Error updating IPHostGroup object '': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'IPHostGroup' -Action 'edit' -Target $Name
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes a IpHostGroup object from the Sophos Firewall.

        .DESCRIPTION
        Removes a IpHostGroup object using the Sophos Firewall XML API. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Preview removal
        Remove-SfosIpHostGroup -Name "Example" -WhatIf

        .EXAMPLE
        # Pipeline removal preview
        Remove-SfosIpHostGroup -Name "Example" -WhatIf

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/21.5/api/
#>
function Remove-SfosIpHostGroup 
{
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        if (-not $PSCmdlet.ShouldProcess("IPHostGroup '$Name' on $($params.Firewall)", 'Remove')) 
        {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <IPHostGroup>
    <Name>$nameEsc</Name>
  </IPHostGroup>
</Remove>
"@

        try 
        {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch 
        {
            throw "Error removing IPHostGroup object '': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'IPHostGroup' -Action 'remove' -Target $Name
    }
    end {
    }
}

<#
        .SYNOPSIS
        Adds members to an existing IpHostGroup object on the Sophos Firewall.

        .DESCRIPTION
        Adds members to a IpHostGroup object using the Sophos Firewall XML API. The cmdlet validates input where possible and escapes user input for XML safety.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER Members
        One or more member object names to add.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Add members to an existing object
        Add-SfosIpHostGroupMember -Name "Example" -Members "Host1","Host2"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/21.5/api/
#>
function Add-SfosIpHostGroupMember 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$members,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        
        # Check Name
        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        # Retrieve existing object
        $ipHostGroup = Get-SfosIpHostGroup -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -NameLike $Name `
        -SkipCertificateCheck:$params.SkipCertificateCheck

        if ($null -eq $ipHostGroup) 
        {
            throw "The IPHostGroup object '$Name' was not found."
        }
        
        # Prefill existing members
        $ipHostGroupMembers = @()
        $ipHostGroupMembers += $ipHostGroup.Members
        $ipHostGroupMembers += $members
        $ipHostGroupMembers = $ipHostGroupMembers | Select-Object -Unique

        # Build XML member list
        $xmlMember = ''
        foreach ($member in $ipHostGroupMembers) 
        {
            if (-not $member) 
            {
                continue
            }
            if ($member.Length -gt 50) 
            {
                throw "Member '' must be 50 characters or fewer."
            }
            if ($member -match ',') 
            {
                throw "Member '' cannot contain a comma."
            }
            $memberEsc = ConvertTo-SfosXmlEscaped -Text $member
            $xmlMember += "<Host>$memberEsc</Host>"
        }

        $inner = @"
<Set operation="update">
    <IPHostGroup>
        <Name>$nameEsc</Name>
        <HostList>
            $xmlMember
        </HostList> 
    </IPHostGroup>
</Set>
"@

        try 
        {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch 
        {
            throw "Error adding members to IPHostGroup '': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'IPHostGroup' -Action 'add members' -Target $Name
    }
}

<#
        .SYNOPSIS
        Removes members from an existing IpHostGroup object on the Sophos Firewall.

        .DESCRIPTION
        Removes members from a IpHostGroup object using the Sophos Firewall XML API. The cmdlet validates input where possible and escapes user input for XML safety.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER Members
        One or more member object names to remove.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Remove members from an existing object
        Remove-SfosIpHostGroupMember -Name "Example" -Members "Host1","Host2"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/21.5/api/
#>
function Remove-SfosIpHostGroupMember 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$members,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }
    process {

        # Check Name
        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        # Retrieve existing object
        $ipHostGroup = Get-SfosIpHostGroup -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -NameLike $Name `
        -SkipCertificateCheck:$params.SkipCertificateCheck

        if ($null -eq $ipHostGroup) 
        {
            throw "The IPHostGroup object '$Name' was not found."
        }
        
        if($ipHostGroup.Members.Count -eq 0)
        {
            # Es kann nichts entfernt werden...
            return $null
        }


        # Prefill existing members
        $ipHostGroupMembers = [Collections.ArrayList]@()
        $ipHostGroupMembers.AddRange($ipHostGroup.Members)
        
        foreach($member in $members) 
        {
            [int]$indexMember = $ipHostGroupMembers.IndexOf($member)
            
            if($indexMember -ne -1)
            {
                $ipHostGroupMembers.RemoveAt($indexMember)
            }
        }

        $xmlMember = ''
        foreach ($member in $ipHostGroupMembers) 
        {
            if (-not $member) 
            {
                continue
            }
            if ($member.Length -gt 50) 
            {
                throw "Member '' must be 50 characters or fewer."
            }
            if ($member -match ',') 
            {
                throw "Member '' cannot contain a comma."
            }
            $memberEsc = ConvertTo-SfosXmlEscaped -Text $member
            $xmlMember += "<Host>$memberEsc</Host>"
        }

        $inner = @"
<Set operation="remove">
    <IPHostGroup>
        <Name>$nameEsc</Name>
        <HostList>
            $xmlMember
        </HostList> 
    </IPHostGroup>
</Set>
"@
        # Send Request to the API
        try 
        {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch 
        {
            throw "Error removing members from IPHostGroup '': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'IPHostGroup' -Action 'remove members' -Target $Name
    }   
}

<#
        .SYNOPSIS
        Exports IPHostGroup objects to a CSV or JSON file.

        .DESCRIPTION
        Retrieves all IPHostGroup objects from the Sophos Firewall and exports them to a file in CSV or JSON format.
        Group members are stored as JSON arrays within the file for proper handling of multiple members.
        Useful for backup, documentation, or migration purposes.

        .PARAMETER FilePath
        Full path where the export file will be saved. The file extension should match the format (.csv for CSV, .json for JSON).

        .PARAMETER Format
        Export format: 'AsCSV' (default) or 'AsJSON'. CSV format stores member arrays as JSON strings. JSON format preserves nested structure.

        .PARAMETER Overwrite
        If specified, overwrite the file if it already exists. Without this switch, the function throws an error if the file exists.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, uses the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skip SSL/TLS certificate validation for self-signed certificates.

        .OUTPUTS
        PSCustomObject with properties:
        - Operation: 'Export'
        - ObjectType: 'IPHostGroup'
        - Total: Number of objects exported
        - Success: Number of successful exports
        - Failed: Always 0 for export operations
        - SuccessItems: Array of exported IPHostGroup names
        - FailedItems: Empty array for export operations

        .EXAMPLE
        # Export all IP host groups to CSV
        Export-SfosIpHostGroups -FilePath "C:\Exports\IpHostGroups.csv"

        .EXAMPLE
        # Export to JSON with overwrite
        Export-SfosIpHostGroups -FilePath "C:\Exports\IpHostGroups.json" -Format AsJSON -Overwrite

        .NOTES
        Minimum supported PowerShell version: 5.1
        This function depends on Get-SfosIpHostGroup to retrieve the objects.
        Group members are stored as JSON arrays within CSV fields for proper serialization.

        .LINK
        Import-SfosIpHostGroups

        .LINK
        Get-SfosIpHostGroup
#>
function Export-SfosIpHostGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [ValidateSet('AsCSV', 'AsJSON')]
        [ValidateNotNullOrEmpty()]
        [string]$Format = 'AsCSV',

        [switch]$Overwrite,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    # Check if file exists
    if (Test-Path -Path $FilePath) {
        if ($Overwrite) {
            Remove-Item -Path $FilePath -Force
        }
        else {
            throw "File '' already exists. Provide a different file name or use -Overwrite."
        }
    }

    # Resolve connection parameters
    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Retrieve IP host groups
    try {
        $ipHostGroups = Get-SfosIpHostGroup -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -SkipCertificateCheck:$params.SkipCertificateCheck
    }
    catch {
        throw "Error retrieving IP host groups: $($_.Exception.Message)"
    }

    # Convert member arrays to JSON strings for proper serialization
    try {
        $groupsToExport = @()
        foreach ($group in $ipHostGroups) {
            $groupObj = $group | Select-Object * -ExcludeProperty IPHostList
            if ($group.IPHostList) {
                $groupObj | Add-Member -NotePropertyName IPHostList -NotePropertyValue ($group.IPHostList | ConvertTo-Json -Compress)
            }
            else {
                $groupObj | Add-Member -NotePropertyName IPHostList -NotePropertyValue ''
            }
            $groupsToExport += $groupObj
        }

        if ($Format -eq 'AsCSV') {
            $groupsToExport | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
        }
        else {
            $ipHostGroups | ConvertTo-Json | Out-File -FilePath $FilePath -Encoding UTF8
        }

        Write-Information "Export of IP host groups to '$FilePath' successful." -InformationAction Continue

        # Return summary object
        return [PSCustomObject]@{
            Operation     = 'Export'
            ObjectType    = 'IPHostGroup'
            Total         = $ipHostGroups.Count
            Success       = $ipHostGroups.Count
            Failed        = 0
            SuccessItems  = @($ipHostGroups.Name)
            FailedItems   = @()
        }
    }
    catch {
        throw "Error exporting IP host groups to '': $($_.Exception.Message)"
    }
}

<#
        .SYNOPSIS
        Imports IPHostGroup objects from a CSV or JSON file.

        .DESCRIPTION
        Reads IPHostGroup objects from a specified CSV or JSON file and creates them on the Sophos Firewall using the New-SfosIpHostGroup cmdlet.
        The file must have the appropriate headers/structure. Members are expected as JSON arrays in CSV fields.

        .PARAMETER FilePath
        Full path to the input CSV or JSON file.

        .PARAMETER Format
        Import format: 'AsCSV' (default) or 'AsJSON'. Must match the file format.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, uses the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skip SSL/TLS certificate validation for self-signed certificates.

        .OUTPUTS
        PSCustomObject with properties:
        - Operation: 'Import'
        - ObjectType: 'IPHostGroup'
        - Total: Number of objects in import file
        - Success: Number of successfully created objects
        - Failed: Number of failed creations
        - SuccessItems: Array of successfully imported IPHostGroup names
        - FailedItems: Array of PSCustomObjects with Name and Error details for failed items

        .EXAMPLE
        # Import IP host groups from CSV
        Import-SfosIpHostGroups -FilePath "C:\Imports\IpHostGroups.csv"

        .EXAMPLE
        # Import from JSON with explicit connection
        $result = Import-SfosIpHostGroups -FilePath "C:\Imports\IpHostGroups.json" -Format AsJSON -Firewall "192.168.1.1"
        $result | Format-Table

        .NOTES
        Minimum supported PowerShell version: 5.1
        This function depends on New-SfosIpHostGroup to create the objects.
        Members in CSV files should be JSON arrays: ["Host1","Host2"]

        .LINK
        Export-SfosIpHostGroups

        .LINK
        New-SfosIpHostGroup
#>
function Import-SfosIpHostGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [ValidateSet('AsCSV', 'AsJSON')]
        [ValidateNotNullOrEmpty()]
        [string]$Format = 'AsCSV',

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    # Check if file exists
    if (-not (Test-Path -Path $FilePath)) {
        throw "File '' was not found."
    }

    # Resolve connection parameters
    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Import data from CSV or JSON
    try {
        if ($Format -eq 'AsCSV') {
            $ipHostGroups = Import-Csv -Path $FilePath -Encoding UTF8
        }
        else {
            $ipHostGroups = Get-Content -Path $FilePath -Raw | ConvertFrom-Json
        }
    }
    catch {
        throw "Error importing IP host groups from '': $($_.Exception.Message)"
    }

    # Ensure ipHostGroups is an array
    if ($ipHostGroups -isnot [array]) {
        $ipHostGroups = @($ipHostGroups)
    }

    # Track success and failures
    $successItems = @()
    $failedItems = @()

    # Create IP host groups on the Sophos Firewall
    foreach ($group in $ipHostGroups) {
        try {
            # Parse member list from JSON string if present
            $members = @()
            if ($group.IPHostList) {
                try {
                    $members = $group.IPHostList | ConvertFrom-Json
                }
                catch {
                    # If JSON parsing fails, treat as empty
                    $members = @()
                }
            }

            New-SfosIpHostGroup -Name $group.Name `
                -Description $group.Description `
                -Members $members `
                -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -SkipCertificateCheck:$params.SkipCertificateCheck
            
            $successItems += $group.Name
            Write-Information "Imported: $($group.Name)" -InformationAction Continue
        }
        catch {
            $failedItems += [PSCustomObject]@{
                Name  = $group.Name
                Error = $_.Exception.Message
            }
            Write-Information "Error importing '$($group.Name)': $($_.Exception.Message)" -InformationAction Continue
        }
    }

    # Return summary object
    return [PSCustomObject]@{
        Operation     = 'Import'
        ObjectType    = 'IPHostGroup'
        Total         = $ipHostGroups.Count
        Success       = $successItems.Count
        Failed        = $failedItems.Count
        SuccessItems  = $successItems
        FailedItems   = $failedItems
    }
}

#endregion IPHostGroup

#region FQDNHost

<#
        .SYNOPSIS
        Retrieves FqdnHost objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for FqdnHost objects. By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.
    
        Note: Sophos GET responses can be inconsistent regarding status elements. This cmdlet is designed to return an empty result when no records are found.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER NameLike
        Optional name filter. In Sophos SFOS, 'like' behaves as a substring match (the supplied value may match anywhere in the object name).

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .PARAMETER AsXml
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve all objects
        Get-SfosFqdnHost

        .EXAMPLE
        # Filter by name (substring match)
        Get-SfosFqdnHost -NameLike "Example"

        .EXAMPLE
        # Return raw XML for troubleshooting
        Get-SfosFqdnHost -NameLike "Example" -AsXml

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/21.5/api/
#>
function Get-SfosFqdnHost 
{
    [CmdletBinding()]
    param(
        # Functional parameters
        [string]$NameLike,
        [string]$FqdnLike,
        [string]$DescriptionLike,
        
        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        
        # Output parameters
        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Filter in deinem funktionierenden Format
    $filterXml = ''
    if ($NameLike) 
    {
        $nameLikeEsc = ConvertTo-SfosXmlEscaped -Text $NameLike
        $filterXml += ('<Filter><key name="Name" criteria="like">{0}</key></Filter>' -f $nameLikeEsc)
    }

    if ($FqdnLike) 
    {
        $fqdnLikeEsc = ConvertTo-SfosXmlEscaped -Text $FqdnLike
        $filterXml += ('<Filter><key name="FQDN" criteria="like">{0}</key></Filter>' -f $fqdnLikeEsc)
    }

    if ($DescriptionLike) 
    {
        $descriptionLikeEsc = ConvertTo-SfosXmlEscaped -Text $DescriptionLike
        $filterXml += ('<Filter><key name="Description" criteria="like">{0}</key></Filter>' -f $descriptionLikeEsc)
    }

    $inner = @"
<Get>
  <FQDNHost>
    $filterXml
  </FQDNHost>
</Get>
"@

    try 
    {
        $response = Invoke-SfosApi `
        -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -InnerXml $inner `
        -SkipCertificateCheck:$params.SkipCertificateCheck
    }
    catch 
    {
        throw "Error retrieving FQDN host objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    # Important: Only return actual objects, not containers with status
    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/FQDNHost[Name]' -ErrorAction SilentlyContinue |
    ForEach-Object -Process {
        $_.Node
    }

    if ($AsXml) 
    {
        return @($nodes)
    }

    # Erstelle PSCustomObjects
    $fqdnHostObjects = @()
    foreach ($node in $nodes) 
    {
        $fqdnHostObjects += [PSCustomObject]@{
            Name              = $node.Name
            Description       = $node.Description
            FQDN              = $node.FQDN
            FQDNHostGroupList = $node.FQDNHostGroupList | Select-Object -ExpandProperty FQDNHostGroup
        }
    }

    return $fqdnHostObjects
}

<#
        .SYNOPSIS
        Creates a new FQDN (Fully Qualified Domain Name) host on the Sophos Firewall.

        .DESCRIPTION
        Creates an FQDN host object for DNS-based host definitions. Useful for cloud services,
        dynamic IPs, or SaaS applications where IP addresses change frequently.
        The firewall resolves the FQDN to current IP addresses automatically.

        .PARAMETER Name
        Name of the FQDN host object (1-50 characters, no commas).

        .PARAMETER FQDN
        Fully qualified domain name (max 255 characters).
        Examples: 'mail.example.com', '*.cloudapp.azure.com', 'api.service.com'

        .PARAMETER Description
        Optional description (max 255 characters).

        .PARAMETER HostGroup
        Optional array of FQDN host group names to add this host to.

        # Connection parameters (optional - use stored context if not provided)
        
        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses stored connection context.

        .PARAMETER Port
        Management/API port number. If omitted, uses stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation.

        .OUTPUTS
        None. Throws an exception if creation fails.

        .EXAMPLE
        # Create FQDN host for Office 365
        New-SfosFqdnHost -Name "Office365-Outlook" -FQDN "outlook.office365.com" -Description "Microsoft Office 365 Outlook"

        .EXAMPLE
        # Create FQDN host with wildcard for Azure services
        New-SfosFqdnHost -Name "Azure-WestEU" -FQDN "*.westeurope.cloudapp.azure.com"

        .EXAMPLE
        # Create FQDN and add to group
        New-SfosFqdnHost -Name "SalesforceAPI" -FQDN "api.salesforce.com" -HostGroup @("SaaSServices", "CriticalServices")

        .EXAMPLE
        # Create FQDN for internal service
        New-SfosFqdnHost -Name "InternalDB" -FQDN "db.internal.corp" -Description "Internal database cluster"

        .NOTES
        Minimum supported PowerShell version: 5.1
        FQDN resolution happens on the firewall, not at definition time.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
        
        .LINK
        Get-SfosFqdnHost
        
        .LINK
        Set-SfosFqdnHost
        
        .LINK
        Remove-SfosFqdnHost
#>
function New-SfosFqdnHost 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateLength(1, 255)]
        [string]$FQDN,

        [ValidateLength(0, 255)]
        [string]$Description,

        [string[]]$HostGroup,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
    $fqdnEsc = ConvertTo-SfosXmlEscaped -Text $FQDN

    # Setup Description XML
    $xmlDescription = ''
    if ($Description) 
    {
        $descEsc = ConvertTo-SfosXmlEscaped -Text $Description
        $xmlDescription = "<Description>$descEsc</Description>"
    }

    $xmlHostGroupList = ''
    if ($HostGroup) 
    {
        $hostGroupXml = ''
        foreach ($hostGroupItem in $HostGroup) 
        {
            if (-not $hostGroupItem) 
            {
                continue
            }
            if ($hostGroupItem.Length -gt 50) 
            {
                throw "HostGroup '$hostGroupItem' darf max. 50 Zeichen lang sein."
            }
            if ($hostGroupItem -match ',') 
            {
                throw "HostGroup '$hostGroupItem' darf kein Komma enthalten."
            }
            $hgEsc = ConvertTo-SfosXmlEscaped -Text $hostGroupItem
            $hostGroupXml += "<FQDNHostGroup>$hgEsc</FQDNHostGroup>"
        }
        
        $xmlHostGroupList = @"
<FQDNHostGroupList>
    $hostGroupXml
</FQDNHostGroupList>
"@    
    }

    $inner = @"
<Set operation="add">
  <FQDNHost>
    <Name>$nameEsc</Name>
    $xmlDescription
    <FQDN>$fqdnEsc</FQDN>
    $xmlHostGroupList
  </FQDNHost>
</Set>
"@

    try 
    {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch 
    {
        throw "Error creating FQDNHost object '': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Check login status
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FQDNHost' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Updates an existing FqdnHost object on the Sophos Firewall.

        .DESCRIPTION
        Updates a FqdnHost object using the Sophos Firewall XML API. You can supply the target object name directly or via the pipeline (when supported by the function's parameters).

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER FQDN
        Parameter used by this cmdlet.

        .PARAMETER Description
        Optional description text.

        .PARAMETER HostGroup
        Parameter used by this cmdlet.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Update an object by name
        Set-SfosFqdnHost -Name "Example"

        .EXAMPLE
        # Update using pipeline input
        Get-SfosFqdnHost -NameLike "Example" | Set-SfosFqdnHost  # when pipeline is supported

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/21.5/api/
#>
function Set-SfosFqdnHost 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 255)]
        [string]$FQDN,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(0, 255)]
        [string]$Description,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]$HostGroup,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $fqdnEsc = ConvertTo-SfosXmlEscaped -Text $FQDN

        # Setup Description XML
        $xmlDescription = ''
        if ($Description) 
        {
            $descEsc = ConvertTo-SfosXmlEscaped -Text $Description
            $xmlDescription = "<Description>$descEsc</Description>"
        }

        # Setup HostGroup XML
        $xmlHostGroupList = ''
        if ($HostGroup) 
        {
            $hostGroupXml = ''
            foreach ($hostGroupItem in $HostGroup) 
            {
                if (-not $hostGroupItem) 
                {
                    continue
                }
                if ($hostGroupItem.Length -gt 50) 
                {
                    throw "HostGroup '$hostGroupItem' darf max. 50 Zeichen lang sein."
                }
                if ($hostGroupItem -match ',') 
                {
                    throw "HostGroup '$hostGroupItem' darf kein Komma enthalten."
                }
                $hgEsc = ConvertTo-SfosXmlEscaped -Text $hostGroupItem
                $hostGroupXml += "<FQDNHostGroup>$hgEsc</FQDNHostGroup>"
            }
            
            $xmlHostGroupList = @"
<FQDNHostGroupList>
    $hostGroupXml
</FQDNHostGroupList>
"@
        }

        # Build final XML
        $inner = @"
<Set operation="edit">
  <FQDNHost>
    <Name>$nameEsc</Name>
    $xmlDescription
    <FQDN>$fqdnEsc</FQDN>
    $xmlHostGroupList
  </FQDNHost>
</Set>
"@
        
        # Send API Request
        try 
        {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch 
        {
            throw "Error updating FQDNHost object '': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FQDNHost' -Action 'edit' -Target $Name
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes a FqdnHost object from the Sophos Firewall.

        .DESCRIPTION
        Removes a FqdnHost object using the Sophos Firewall XML API. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Preview removal
        Remove-SfosFqdnHost -Name "Example" -WhatIf

        .EXAMPLE
        # Pipeline removal preview
        Remove-SfosFqdnHost -Name "Example" -WhatIf

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/21.5/api/
#>
function Remove-SfosFqdnHost 
{
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        if (-not $PSCmdlet.ShouldProcess("FQDNHost '$Name' on $($params.Firewall)", 'Remove')) 
        {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <FQDNHost>
    <Name>$nameEsc</Name>
  </FQDNHost>
</Remove>
"@

        try 
        {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch 
        {
            throw "Error removing FQDNHost object '': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FQDNHost' -Action 'remove' -Target $Name -ErrorAction SilentlyContinue
    }
    end {
    }
}

# -- BETA -- Works but needs further testing
function Remove-SfosFqdnHostMass
{
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$Names,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        # Respect -WhatIf / -Confirm
        if (-not $PSCmdlet.ShouldProcess(("FQDNHost(s) '{0}' auf {1}" -f ($Names -join ', '), $params.Firewall), 'Remove')) 
        {
            return
        }

        # Build Name XML
        $xmlNames = foreach($nameItem in $Names) 
        {
            $nameEsc = ConvertTo-SfosXmlEscaped -Text $nameItem
            "<Name>$nameEsc</Name>"
        }

        # Build XML
        $inner = @"
<Remove>
  <FQDNHost>
    $xmlNames
  </FQDNHost>
</Remove>
"@

        try 
        {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch 
        {
            throw "Error removing multiple FQDNHost objects: $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FQDNHost' -Action 'remove' -Target ($Names -join ', ')
    }
    end {
    }
}

<#
        .SYNOPSIS
        Exports FqdnHost objects to a CSV or JSON file.

        .DESCRIPTION
        Retrieves all FqdnHost objects from the Sophos Firewall and exports them to a file in CSV or JSON format.
        Useful for backup, documentation, or migration purposes.

        .PARAMETER FilePath
        Full path where the export file will be saved. The file extension should match the format (.csv for CSV, .json for JSON).

        .PARAMETER Format
        Export format: 'AsCSV' (default) or 'AsJSON'. CSV format is human-readable and Excel-compatible. JSON format preserves data structure.

        .PARAMETER Overwrite
        If specified, overwrite the file if it already exists. Without this switch, the function throws an error if the file exists.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, uses the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skip SSL/TLS certificate validation for self-signed certificates.

        .OUTPUTS
        PSCustomObject with properties:
        - Operation: 'Export'
        - ObjectType: 'FqdnHost'
        - Total: Number of objects exported
        - Success: Number of successful exports
        - Failed: Always 0 for export operations
        - SuccessItems: Array of exported FqdnHost names
        - FailedItems: Empty array for export operations

        .EXAMPLE
        # Export all FQDN hosts to CSV
        Export-SfosFqdnHosts -FilePath "C:\Exports\FqdnHosts.csv"

        .EXAMPLE
        # Export to JSON with overwrite
        Export-SfosFqdnHosts -FilePath "C:\Exports\FqdnHosts.json" -Format AsJSON -Overwrite

        .NOTES
        Minimum supported PowerShell version: 5.1
        This function depends on Get-SfosFqdnHost to retrieve the objects.

        .LINK
        Import-SfosFqdnHosts

        .LINK
        Get-SfosFqdnHost
#>
function Export-SfosFqdnHosts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [ValidateSet('AsCSV', 'AsJSON')]
        [ValidateNotNullOrEmpty()]
        [string]$Format = 'AsCSV',

        [switch]$Overwrite,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    # Check if file exists
    if (Test-Path -Path $FilePath) {
        if ($Overwrite) {
            Remove-Item -Path $FilePath -Force
        }
        else {
            throw "File '' already exists. Provide a different file name or use -Overwrite."
        }
    }

    # Resolve connection parameters
    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Retrieve FQDN hosts
    try {
        $fqdnHosts = Get-SfosFqdnHost -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -SkipCertificateCheck:$params.SkipCertificateCheck
    }
    catch {
        throw "Error retrieving FQDN hosts: $($_.Exception.Message)"
    }

    # Export to CSV or JSON
    try {
        if ($Format -eq 'AsCSV') {
            $fqdnHosts | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
        }
        else {
            $fqdnHosts | ConvertTo-Json | Out-File -FilePath $FilePath -Encoding UTF8
        }

        Write-Information "Export of FQDN hosts to '$FilePath' successful." -InformationAction Continue

        # Return summary object
        return [PSCustomObject]@{
            Operation     = 'Export'
            ObjectType    = 'FqdnHost'
            Total         = $fqdnHosts.Count
            Success       = $fqdnHosts.Count
            Failed        = 0
            SuccessItems  = @($fqdnHosts.Name)
            FailedItems   = @()
        }
    }
    catch {
        throw "Error exporting FQDN hosts to '': $($_.Exception.Message)"
    }
}

<#
        .SYNOPSIS
        Imports FqdnHost objects from a CSV or JSON file.

        .DESCRIPTION
        Reads FqdnHost objects from a specified CSV or JSON file and creates them on the Sophos Firewall using the New-SfosFqdnHost cmdlet.
        The file must have the appropriate headers/structure matching the FqdnHost properties (Name, FQDN, Description).

        .PARAMETER FilePath
        Full path to the input CSV or JSON file.

        .PARAMETER Format
        Import format: 'AsCSV' (default) or 'AsJSON'. Must match the file format.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, uses the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skip SSL/TLS certificate validation for self-signed certificates.

        .OUTPUTS
        PSCustomObject with properties:
        - Operation: 'Import'
        - ObjectType: 'FqdnHost'
        - Total: Number of objects in import file
        - Success: Number of successfully created objects
        - Failed: Number of failed creations
        - SuccessItems: Array of successfully imported FqdnHost names
        - FailedItems: Array of PSCustomObjects with Name and Error details for failed items

        .EXAMPLE
        # Import FQDN hosts from CSV
        Import-SfosFqdnHosts -FilePath "C:\Imports\FqdnHosts.csv"

        .EXAMPLE
        # Import from JSON with explicit connection
        $result = Import-SfosFqdnHosts -FilePath "C:\Imports\FqdnHosts.json" -Format AsJSON -Firewall "192.168.1.1"
        $result | Format-Table

        .NOTES
        Minimum supported PowerShell version: 5.1
        This function depends on New-SfosFqdnHost to create the objects.

        .LINK
        Export-SfosFqdnHosts

        .LINK
        New-SfosFqdnHost
#>
function Import-SfosFqdnHosts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [ValidateSet('AsCSV', 'AsJSON')]
        [ValidateNotNullOrEmpty()]
        [string]$Format = 'AsCSV',

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    # Check if file exists
    if (-not (Test-Path -Path $FilePath)) {
        throw "File '' was not found."
    }

    # Resolve connection parameters
    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Import data from CSV or JSON
    try {
        if ($Format -eq 'AsCSV') {
            $fqdnHosts = Import-Csv -Path $FilePath -Encoding UTF8
        }
        else {
            $fqdnHosts = Get-Content -Path $FilePath -Raw | ConvertFrom-Json
        }
    }
    catch {
        throw "Error importing FQDN hosts from '': $($_.Exception.Message)"
    }

    # Ensure fqdnHosts is an array
    if ($fqdnHosts -isnot [array]) {
        $fqdnHosts = @($fqdnHosts)
    }

    # Track success and failures
    $successItems = @()
    $failedItems = @()

    # Create FQDN hosts on the Sophos Firewall
    foreach ($fqdnHost in $fqdnHosts) {
        try {
            New-SfosFqdnHost -Name $fqdnHost.Name `
                -FQDN $fqdnHost.FQDN `
                -Description $fqdnHost.Description `
                -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -SkipCertificateCheck:$params.SkipCertificateCheck
            
            $successItems += $fqdnHost.Name
            Write-Information "Imported: $($fqdnHost.Name)" -InformationAction Continue
        }
        catch {
            $failedItems += [PSCustomObject]@{
                Name  = $fqdnHost.Name
                Error = $_.Exception.Message
            }
            Write-Information "Error importing '$($fqdnHost.Name)': $($_.Exception.Message)" -InformationAction Continue
        }
    }

    # Return summary object
    return [PSCustomObject]@{
        Operation     = 'Import'
        ObjectType    = 'FqdnHost'
        Total         = $fqdnHosts.Count
        Success       = $successItems.Count
        Failed        = $failedItems.Count
        SuccessItems  = $successItems
        FailedItems   = $failedItems
    }
}

#endregion FQDNHost

#region FQDNHostGroup

# --- FQDNHostGroup ---

<#
        .SYNOPSIS
        Retrieves FqdnHostGroup objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for FqdnHostGroup objects. By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.
    
        Note: Sophos GET responses can be inconsistent regarding status elements. This cmdlet is designed to return an empty result when no records are found.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER NameLike
        Optional name filter. In Sophos SFOS, 'like' behaves as a substring match (the supplied value may match anywhere in the object name).

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .PARAMETER AsXml
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve all objects
        Get-SfosFqdnHostGroup

        .EXAMPLE
        # Filter by name (substring match)
        Get-SfosFqdnHostGroup -NameLike "Example"

        .EXAMPLE
        # Return raw XML for troubleshooting
        Get-SfosFqdnHostGroup -NameLike "Example" -AsXml

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/21.5/api/
#>
function Get-SfosFqdnHostGroup 
{
    [CmdletBinding()]
    param(
        # Functional parameters
        [string]$NameLike,
        [string]$DescriptionLike,
        
        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        
        # Output parameters
        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $filterXml = ''
    if ($NameLike) 
    {
        $nameLikeEsc = ConvertTo-SfosXmlEscaped -Text $NameLike
        $filterXml = ('<Filter><key name="Name" criteria="like">{0}</key></Filter>' -f $nameLikeEsc)
    }

    if ($DescriptionLike) 
    {
        $descLikeEsc = ConvertTo-SfosXmlEscaped -Text $DescriptionLike
        $filterXml += ('<Filter><key name="Description" criteria="like">{0}</key></Filter>' -f $descLikeEsc)
    }

    $inner = @"
<Get>
  <FQDNHostGroup>
    $filterXml
  </FQDNHostGroup>
</Get>
"@

    try 
    {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch 
    {
        throw "Error retrieving FQDNHostGroup objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Check login status
    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/FQDNHostGroup[Name]' | ForEach-Object -Process {
        $_.Node
    }

    if ($AsXml) 
    {
        return @($nodes)
    }

    # Erstelle PSCustomObjects
    $fqdnHostGroupObjects = @()
    foreach ($node in $nodes) 
    {
        $fqdnHostGroupObjects += [PSCustomObject]@{
            Name         = $node.Name
            Description  = $node.Description
            FQDNHostList = $node.FQDNHostList | Select-Object -ExpandProperty FQDNHost
        }
    }

    return $fqdnHostGroupObjects
}

<#
        .SYNOPSIS
        Creates a new FqdnHostGroup object on the Sophos Firewall.

        .DESCRIPTION
        Creates a FqdnHostGroup object using the Sophos Firewall XML API. The cmdlet validates input where possible and escapes user input for XML safety.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER Members
        One or more member object names to include.

        .PARAMETER Description
        Optional description text.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Create a new object
        New-SfosFqdnHostGroup -Name "Example"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/21.5/api/
#>
function New-SfosFqdnHostGroup 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [string[]]$members = @(),

        [ValidateLength(0, 255)]
        [string]$Description,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

    if ($Description) 
    {
        $descEsc = ConvertTo-SfosXmlEscaped -Text $Description
    }

    $xmlMember = ''
    foreach ($member in $members) 
    {
        if (-not $member) 
        {
            continue
        }
        if ($member.Length -gt 50) 
        {
            throw "Member '' must be 50 characters or fewer."
        }
        if ($member -match ',') 
        {
            throw "Member '' cannot contain a comma."
        }
        $memberEsc = ConvertTo-SfosXmlEscaped -Text $member
        $xmlMember += "<FQDNHost>$memberEsc</FQDNHost>"
    }

    $xmlMemberList = @"
<FQDNHostList>
    $xmlMember
</FQDNHostList>
"@

    $inner = @"
<Set operation="add">
  <FQDNHostGroup>
    <Name>$nameEsc</Name>
    <Description>$descEsc</Description>
    $xmlMemberList
  </FQDNHostGroup>
</Set>
"@

    try 
    {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch 
    {
        throw "Error creating FQDNHostGroup object '': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Check login status
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FQDNHostGroup' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Updates an existing FqdnHostGroup object on the Sophos Firewall.

        .DESCRIPTION
        Updates a FqdnHostGroup object using the Sophos Firewall XML API. You can supply the target object name directly or via the pipeline (when supported by the function's parameters).

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER Members
        One or more member object names to include.

        .PARAMETER Description
        Optional description text.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Update an object by name
        Set-SfosFqdnHostGroup -Name "Example"

        .EXAMPLE
        # Update using pipeline input
        Get-SfosFqdnHostGroup -NameLike "Example" | Set-SfosFqdnHostGroup  # when pipeline is supported

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/21.5/api/
#>
function Set-SfosFqdnHostGroup 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string[]]$members,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(0, 255)]
        [string]$Description,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        if ($Description) 
        {
            $descEsc = ConvertTo-SfosXmlEscaped -Text $Description
        }

        $xmlMember = ''
        foreach ($member in $members) 
        {
            if (-not $member) 
            {
                continue
            }
            if ($member.Length -gt 50) 
            {
                throw "Member '' must be 50 characters or fewer."
            }
            if ($member -match ',') 
            {
                throw "Member '' cannot contain a comma."
            }
            $mEsc = ConvertTo-SfosXmlEscaped -Text $member
            $xmlMember += "<FQDNHost>$mEsc</FQDNHost>"
        }

        $xmlMemberList = @"
<FQDNHostList>
    $xmlMember
</FQDNHostList>
"@

        $inner = @"
<Set operation="edit">
  <FQDNHostGroup>
    <Name>$nameEsc</Name>
    <Description>$descEsc</Description>
    $xmlMemberList
  </FQDNHostGroup>
</Set>
"@

        try 
        {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch 
        {
            throw "Error updating FQDNHostGroup object '': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FQDNHostGroup' -Action 'edit' -Target $Name
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes a FqdnHostGroup object from the Sophos Firewall.

        .DESCRIPTION
        Removes a FqdnHostGroup object using the Sophos Firewall XML API. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Preview removal
        Remove-SfosFqdnHostGroup -Name "Example" -WhatIf

        .EXAMPLE
        # Pipeline removal preview
        Remove-SfosFqdnHostGroup -Name "Example" -WhatIf

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/21.5/api/
#>
function Remove-SfosFqdnHostGroup 
{
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        if (-not $PSCmdlet.ShouldProcess("FQDNHostGroup '$Name' on $($params.Firewall)", 'Remove')) 
        {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <FQDNHostGroup>
    <Name>$nameEsc</Name>
  </FQDNHostGroup>
</Remove>
"@

        try 
        {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch 
        {
            throw "Error removing FQDNHostGroup object '': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FQDNHostGroup' -Action 'remove' -Target $Name
    }
    end {
    }
}

function Add-SfosFqdnHostGroupMember 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$members,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )
    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

    $xmlMember = ''
    foreach ($member in $members) 
    {
        if (-not $member) 
        {
            continue
        }
        if ($member.Length -gt 50) 
        {
            throw "Member '' must be 50 characters or fewer."
        }
        if ($member -match ',') 
        {
            throw "Member '' cannot contain a comma."
        }
        $memberEsc = ConvertTo-SfosXmlEscaped -Text $member
        $xmlMember += "<FQDNHost>$memberEsc</FQDNHost>"
    }

    $xmlMemberList = @"
<FQDNHostList>
    $xmlMember
</FQDNHostList>
"@

    $inner = @"
<Set operation="add">
  <FQDNHostGroup>
    <Name>$nameEsc</Name>
    $xmlMemberList
  </FQDNHostGroup>
</Set>
"@

    try 
    {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch 
    {
        throw "Error adding members to FQDNHostGroup '': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Check login status
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FQDNHostGroup' -Action 'add members' -Target $Name
}

function Remove-SfosFqdnHostGroupMember 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$members,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )
    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

    $xmlMember = ''
    foreach ($member in $members) 
    {
        if (-not $member) 
        {
            continue
        }
        if ($member.Length -gt 50) 
        {
            throw "Member '' must be 50 characters or fewer."
        }
        if ($member -match ',') 
        {
            throw "Member '' cannot contain a comma."
        }
        $memberEsc = ConvertTo-SfosXmlEscaped -Text $member
        $xmlMember += "<FQDNHost>$memberEsc</FQDNHost>"
    }

    $xmlMemberList = @"
<FQDNHostList>
    $xmlMember
</FQDNHostList>
"@

    $inner = @"
<Set operation="remove">
  <FQDNHostGroup>
    <Name>$nameEsc</Name>
    $xmlMemberList
  </FQDNHostGroup>
</Set>
"@

    try 
    {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch 
    {
        throw "Error removing members from FQDNHostGroup '': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Check login status
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FQDNHostGroup' -Action 'remove members' -Target $Name
}

<#
        .SYNOPSIS
        Exports FqdnHostGroup objects to a CSV or JSON file.

        .DESCRIPTION
        Retrieves all FqdnHostGroup objects from the Sophos Firewall and exports them to a file in CSV or JSON format.
        Group members are stored as JSON arrays within the file for proper handling of multiple members.
        Useful for backup, documentation, or migration purposes.

        .PARAMETER FilePath
        Full path where the export file will be saved. The file extension should match the format (.csv for CSV, .json for JSON).

        .PARAMETER Format
        Export format: 'AsCSV' (default) or 'AsJSON'. CSV format stores member arrays as JSON strings. JSON format preserves nested structure.

        .PARAMETER Overwrite
        If specified, overwrite the file if it already exists. Without this switch, the function throws an error if the file exists.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, uses the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skip SSL/TLS certificate validation for self-signed certificates.

        .OUTPUTS
        PSCustomObject with properties:
        - Operation: 'Export'
        - ObjectType: 'FqdnHostGroup'
        - Total: Number of objects exported
        - Success: Number of successful exports
        - Failed: Always 0 for export operations
        - SuccessItems: Array of exported FqdnHostGroup names
        - FailedItems: Empty array for export operations

        .EXAMPLE
        # Export all FQDN host groups to CSV
        Export-SfosFqdnHostGroups -FilePath "C:\Exports\FqdnHostGroups.csv"

        .EXAMPLE
        # Export to JSON with overwrite
        Export-SfosFqdnHostGroups -FilePath "C:\Exports\FqdnHostGroups.json" -Format AsJSON -Overwrite

        .NOTES
        Minimum supported PowerShell version: 5.1
        This function depends on Get-SfosFqdnHostGroup to retrieve the objects.
        Group members are stored as JSON arrays within CSV fields for proper serialization.

        .LINK
        Import-SfosFqdnHostGroups

        .LINK
        Get-SfosFqdnHostGroup
#>
function Export-SfosFqdnHostGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [ValidateSet('AsCSV', 'AsJSON')]
        [ValidateNotNullOrEmpty()]
        [string]$Format = 'AsCSV',

        [switch]$Overwrite,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    # Check if file exists
    if (Test-Path -Path $FilePath) {
        if ($Overwrite) {
            Remove-Item -Path $FilePath -Force
        }
        else {
            throw "File '' already exists. Provide a different file name or use -Overwrite."
        }
    }

    # Resolve connection parameters
    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Retrieve FQDN host groups
    try {
        $fqdnHostGroups = Get-SfosFqdnHostGroup -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -SkipCertificateCheck:$params.SkipCertificateCheck
    }
    catch {
        throw "Error retrieving FQDN host groups: $($_.Exception.Message)"
    }

    # Convert member arrays to JSON strings for proper serialization
    try {
        $groupsToExport = @()
        foreach ($group in $fqdnHostGroups) {
            $groupObj = $group | Select-Object * -ExcludeProperty FqdnHostList
            if ($group.FqdnHostList) {
                $groupObj | Add-Member -NotePropertyName FqdnHostList -NotePropertyValue ($group.FqdnHostList | ConvertTo-Json -Compress)
            }
            else {
                $groupObj | Add-Member -NotePropertyName FqdnHostList -NotePropertyValue ''
            }
            $groupsToExport += $groupObj
        }

        if ($Format -eq 'AsCSV') {
            $groupsToExport | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
        }
        else {
            $fqdnHostGroups | ConvertTo-Json | Out-File -FilePath $FilePath -Encoding UTF8
        }

        Write-Information "Export of FQDN host groups to '$FilePath' successful." -InformationAction Continue

        # Return summary object
        return [PSCustomObject]@{
            Operation     = 'Export'
            ObjectType    = 'FqdnHostGroup'
            Total         = $fqdnHostGroups.Count
            Success       = $fqdnHostGroups.Count
            Failed        = 0
            SuccessItems  = @($fqdnHostGroups.Name)
            FailedItems   = @()
        }
    }
    catch {
        throw "Error exporting FQDN host groups to '': $($_.Exception.Message)"
    }
}

<#
        .SYNOPSIS
        Imports FqdnHostGroup objects from a CSV or JSON file.

        .DESCRIPTION
        Reads FqdnHostGroup objects from a specified CSV or JSON file and creates them on the Sophos Firewall using the New-SfosFqdnHostGroup cmdlet.
        The file must have the appropriate headers/structure. Members are expected as JSON arrays in CSV fields.

        .PARAMETER FilePath
        Full path to the input CSV or JSON file.

        .PARAMETER Format
        Import format: 'AsCSV' (default) or 'AsJSON'. Must match the file format.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, uses the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skip SSL/TLS certificate validation for self-signed certificates.

        .OUTPUTS
        PSCustomObject with properties:
        - Operation: 'Import'
        - ObjectType: 'FqdnHostGroup'
        - Total: Number of objects in import file
        - Success: Number of successfully created objects
        - Failed: Number of failed creations
        - SuccessItems: Array of successfully imported FqdnHostGroup names
        - FailedItems: Array of PSCustomObjects with Name and Error details for failed items

        .EXAMPLE
        # Import FQDN host groups from CSV
        Import-SfosFqdnHostGroups -FilePath "C:\Imports\FqdnHostGroups.csv"

        .EXAMPLE
        # Import from JSON with explicit connection
        $result = Import-SfosFqdnHostGroups -FilePath "C:\Imports\FqdnHostGroups.json" -Format AsJSON -Firewall "192.168.1.1"
        $result | Format-Table

        .NOTES
        Minimum supported PowerShell version: 5.1
        This function depends on New-SfosFqdnHostGroup to create the objects.
        Members in CSV files should be JSON arrays: ["Host1","Host2"]

        .LINK
        Export-SfosFqdnHostGroups

        .LINK
        New-SfosFqdnHostGroup
#>
function Import-SfosFqdnHostGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [ValidateSet('AsCSV', 'AsJSON')]
        [ValidateNotNullOrEmpty()]
        [string]$Format = 'AsCSV',

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    # Check if file exists
    if (-not (Test-Path -Path $FilePath)) {
        throw "File '' was not found."
    }

    # Resolve connection parameters
    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Import data from CSV or JSON
    try {
        if ($Format -eq 'AsCSV') {
            $fqdnHostGroups = Import-Csv -Path $FilePath -Encoding UTF8
        }
        else {
            $fqdnHostGroups = Get-Content -Path $FilePath -Raw | ConvertFrom-Json
        }
    }
    catch {
        throw "Error importing FQDN host groups from '': $($_.Exception.Message)"
    }

    # Ensure fqdnHostGroups is an array
    if ($fqdnHostGroups -isnot [array]) {
        $fqdnHostGroups = @($fqdnHostGroups)
    }

    # Track success and failures
    $successItems = @()
    $failedItems = @()

    # Create FQDN host groups on the Sophos Firewall
    foreach ($group in $fqdnHostGroups) {
        try {
            # Parse member list from JSON string if present
            $members = @()
            if ($group.FqdnHostList) {
                try {
                    $members = $group.FqdnHostList | ConvertFrom-Json
                }
                catch {
                    # If JSON parsing fails, treat as empty
                    $members = @()
                }
            }

            New-SfosFqdnHostGroup -Name $group.Name `
                -Description $group.Description `
                -Members $members `
                -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -SkipCertificateCheck:$params.SkipCertificateCheck
            
            $successItems += $group.Name
            Write-Information "Imported: $($group.Name)" -InformationAction Continue
        }
        catch {
            $failedItems += [PSCustomObject]@{
                Name  = $group.Name
                Error = $_.Exception.Message
            }
            Write-Information "Error importing '$($group.Name)': $($_.Exception.Message)" -InformationAction Continue
        }
    }

    # Return summary object
    return [PSCustomObject]@{
        Operation     = 'Import'
        ObjectType    = 'FqdnHostGroup'
        Total         = $fqdnHostGroups.Count
        Success       = $successItems.Count
        Failed        = $failedItems.Count
        SuccessItems  = $successItems
        FailedItems   = $failedItems
    }
}

#endregion FQDNHostGroup

#region MACHost

<#
        .SYNOPSIS
        Retrieves MacHost objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for MacHost objects. By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.
    
        Note: Sophos GET responses can be inconsistent regarding status elements. This cmdlet is designed to return an empty result when no records are found.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER NameLike
        Optional name filter. In Sophos SFOS, 'like' behaves as a substring match (the supplied value may match anywhere in the object name).

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .PARAMETER AsXml
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve all objects
        Get-SfosMacHost

        .EXAMPLE
        # Filter by name (substring match)
        Get-SfosMacHost -NameLike "Example"

        .EXAMPLE
        # Return raw XML for troubleshooting
        Get-SfosMacHost -NameLike "Example" -AsXml

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/21.5/api/
#>
function Get-SfosMacHost 
{
    [CmdletBinding()]
    param(
        # Functional parameters
        [string]$NameLike,
        [string]$MACAddressLike,
        [string]$DescriptionLike,
        
        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        
        # Output parameters
        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $filterXml = ''
    if ($NameLike) 
    {
        $nameLikeEsc = ConvertTo-SfosXmlEscaped -Text $NameLike
        $filterXml = ('<Filter><key name="Name" criteria="like">{0}</key></Filter>' -f $nameLikeEsc)
    }

    if ($MACAddressLike) 
    {
        $macLikeEsc = ConvertTo-SfosXmlEscaped -Text $MACAddressLike
        $filterXml += ('<Filter><key name="MACAddress" criteria="like">{0}</key></Filter>' -f $macLikeEsc)
    }

    if ($DescriptionLike) 
    {
        $descLikeEsc = ConvertTo-SfosXmlEscaped -Text $DescriptionLike
        $filterXml += ('<Filter><key name="Description" criteria="like">{0}</key></Filter>' -f $descLikeEsc)
    }

    $inner = @"
<Get>
  <MACHost>
    $filterXml
  </MACHost>
</Get>
"@

    try 
    {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch 
    {
        throw "Error retrieving MAC host objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Check login status
    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/MACHost[Name]' | ForEach-Object -Process {
        $_.Node
    }

    if ($AsXml) 
    {
        return @($nodes)
    }

    # Erstelle PSCustomObjects
    $macHostObjects = @()
    foreach ($node in $nodes) 
    {
        $macHostObjects += [PSCustomObject]@{
            Name        = $node.Name
            Type        = $node.Type
            MACAddress  = $node.MACAddress
            MACList     = @($node.MACList.MACAddress)
            Description = $node.Description
        }
    }

    return $macHostObjects
}

<#
        .SYNOPSIS
        Creates a new MAC address host on the Sophos Firewall.

        .DESCRIPTION
        Creates a MAC host object for Layer 2 device identification. Useful for:
        - Device-based firewall rules (regardless of IP)
        - Guest network management
        - IoT device control
        - BYOD policies
        
        Supports single MAC addresses or comma-separated lists for multiple MACs.

        .PARAMETER Name
        Name of the MAC host object (1-60 characters, no commas).

        .PARAMETER MACAddress
        MAC address in standard format. Examples:
        - Single: '00:11:22:33:44:55'
        - Multiple: '00:11:22:33:44:55,AA:BB:CC:DD:EE:FF'
        Formats supported: colon-separated, hyphen-separated, or no separators.

        .PARAMETER Description
        Optional description (max 255 characters).

        # Connection parameters (optional - use stored context if not provided)
        
        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses stored connection context.

        .PARAMETER Port
        Management/API port number. If omitted, uses stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation.

        .OUTPUTS
        None. Throws an exception if creation fails.

        .EXAMPLE
        # Create MAC host for a specific device
        New-SfosMacHost -Name "CEO-Laptop" -MACAddress "00:11:22:33:44:55" -Description "Executive laptop"

        .EXAMPLE
        # Create MAC host for IoT device
        New-SfosMacHost -Name "SecurityCamera-01" -MACAddress "AA:BB:CC:DD:EE:FF"

        .EXAMPLE
        # Create MAC host with multiple addresses (device with multiple NICs)
        New-SfosMacHost -Name "Server-Dual-NIC" -MACAddress "00:11:22:33:44:55,00:11:22:33:44:66" -Description "Server with 2 network cards"

        .EXAMPLE
        # Create MAC host for guest device
        New-SfosMacHost -Name "Guest-iPhone" -MACAddress "12:34:56:78:9A:BC" -Description "Visitor device"

        .NOTES
        Minimum supported PowerShell version: 5.1
        MAC addresses are case-insensitive.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
        
        .LINK
        Get-SfosMacHost
        
        .LINK
        Set-SfosMacHost
        
        .LINK
        Remove-SfosMacHost
#>
function New-SfosMacHost 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$MACAddress,

        [ValidateLength(0, 255)]
        [string]$Description,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
    $macEsc = ConvertTo-SfosXmlEscaped -Text $MACAddress

    # Setup Description XML
    $xmlDescription = ''
    if ($Description) 
    {
        $descEsc = ConvertTo-SfosXmlEscaped -Text $Description
        $xmlDescription = "<Description>$descEsc</Description>"
    }

    # Setup MACAddress or MACList XML
    $xmlMAC = ''
    $xmlMACType = ''
    $MACList = $MACAddress.Split(',')

    if($MACList.Count -gt 1) 
    {
        $xmlMACType = '<Type>MACList</Type>'
        $xmlMAC = '<MACList>'
        foreach ($mac in $MACList) 
        {
            $macEsc = ConvertTo-SfosXmlEscaped -Text $mac
            $xmlMAC += "<MACAddress>$macEsc</MACAddress>"
        }
        $xmlMAC += '</MACList>'
    }
    else 
    {
        $xmlMACType = '<Type>MACAddress</Type>'
        $xmlMAC = "<MACAddress>$macEsc</MACAddress>"
    }

    # Build Inner XML
    $inner = @"
<Set operation="add">
  <MACHost>
    <Name>$nameEsc</Name>
    $xmlDescription
    $xmlMACType
    $xmlMAC
  </MACHost>
</Set>
"@

    # Send API Request
    try 
    {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch 
    {
        throw "Error creating MACHost object '': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Check login status
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'MACHost' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Updates an existing MacHost object on the Sophos Firewall.

        .DESCRIPTION
        Updates a MacHost object using the Sophos Firewall XML API. You can supply the target object name directly or via the pipeline (when supported by the function's parameters).

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER MAC
        MAC address value.

        .PARAMETER Description
        Optional description text.

        .PARAMETER HostGroup
        Parameter used by this cmdlet.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Update an object by name
        Set-SfosMacHost -Name "Example"

        .EXAMPLE
        # Update using pipeline input
        Get-SfosMacHost -NameLike "Example" | Set-SfosMacHost  # when pipeline is supported

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/21.5/api/
#>
function Set-SfosMacHost 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$MACAddress,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(0, 255)]
        [string]$Description,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $macEsc = ConvertTo-SfosXmlEscaped -Text $MACAddress

        $xmlDescription = ''
        if ($Description) 
        {
            $descEsc = ConvertTo-SfosXmlEscaped -Text $Description
            $xmlDescription = "<Description>$descEsc</Description>"
        }

        # Setup MACAddress or MACList XML
        $xmlMAC = ''
        $MACList = $MACAddress.Split(',')

        if ($MACList.Count -gt 1) 
        {
            $xmlMAC = '<MACList>'
            foreach ($mac in $MACList) 
            {
                $macEsc = ConvertTo-SfosXmlEscaped -Text $mac
                $xmlMAC += "<MACAddress>$macEsc</MACAddress>"
            }
            $xmlMAC += '</MACList>'
        }
        else 
        {
            $xmlMAC = "<MACAddress>$macEsc</MACAddress>"
        }

        # Build Inner XML
        $inner = @"
<Set operation="edit">
  <MACHost>
    <Name>$nameEsc</Name>
    $xmlDescription
    $xmlMAC
  </MACHost>
</Set>
"@

        # Send API Request
        try 
        {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch 
        {
            throw "Error updating MACHost object '': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'MACHost' -Action 'edit' -Target $Name
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes a MacHost object from the Sophos Firewall.

        .DESCRIPTION
        Removes a MacHost object using the Sophos Firewall XML API. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Preview removal
        Remove-SfosMacHost -Name "Example" -WhatIf

        .EXAMPLE
        # Pipeline removal preview
        Remove-SfosMacHost -Name "Example" -WhatIf

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/21.5/api/
#>
function Remove-SfosMacHost 
{
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        if (-not $PSCmdlet.ShouldProcess("MACHost '$Name' on $($params.Firewall)", 'Remove')) 
        {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <MACHost>
    <Name>$nameEsc</Name>
  </MACHost>
</Remove>
"@

        try 
        {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch 
        {
            throw "Error removing MACHost object '': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'MACHost' -Action 'remove' -Target $Name
    }
    end {
    }
}

<#
        .SYNOPSIS
        Exports MacHost objects to a CSV or JSON file.

        .DESCRIPTION
        Retrieves all MacHost objects from the Sophos Firewall and exports them to a file in CSV or JSON format.
        Useful for backup, documentation, or migration purposes.

        .PARAMETER FilePath
        Full path where the export file will be saved. The file extension should match the format (.csv for CSV, .json for JSON).

        .PARAMETER Format
        Export format: 'AsCSV' (default) or 'AsJSON'. CSV format is human-readable and Excel-compatible. JSON format preserves data structure.

        .PARAMETER Overwrite
        If specified, overwrite the file if it already exists. Without this switch, the function throws an error if the file exists.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, uses the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skip SSL/TLS certificate validation for self-signed certificates.

        .OUTPUTS
        PSCustomObject with properties:
        - Operation: 'Export'
        - ObjectType: 'MacHost'
        - Total: Number of objects exported
        - Success: Number of successful exports
        - Failed: Always 0 for export operations
        - SuccessItems: Array of exported MacHost names
        - FailedItems: Empty array for export operations

        .EXAMPLE
        # Export all MAC hosts to CSV
        Export-SfosMacHosts -FilePath "C:\Exports\MacHosts.csv"

        .EXAMPLE
        # Export to JSON with overwrite
        Export-SfosMacHosts -FilePath "C:\Exports\MacHosts.json" -Format AsJSON -Overwrite

        .NOTES
        Minimum supported PowerShell version: 5.1
        This function depends on Get-SfosMacHost to retrieve the objects.

        .LINK
        Import-SfosMacHosts

        .LINK
        Get-SfosMacHost
#>
function Export-SfosMacHosts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [ValidateSet('AsCSV', 'AsJSON')]
        [ValidateNotNullOrEmpty()]
        [string]$Format = 'AsCSV',

        [switch]$Overwrite,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    # Check if file exists
    if (Test-Path -Path $FilePath) {
        if ($Overwrite) {
            Remove-Item -Path $FilePath -Force
        }
        else {
            throw "File '' already exists. Provide a different file name or use -Overwrite."
        }
    }

    # Resolve connection parameters
    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Retrieve MAC hosts
    try {
        $macHosts = Get-SfosMacHost -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -SkipCertificateCheck:$params.SkipCertificateCheck
    }
    catch {
        throw "Error retrieving MAC hosts: $($_.Exception.Message)"
    }

    # Export to CSV or JSON
    try {
        if ($Format -eq 'AsCSV') {
            $macHosts | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
        }
        else {
            $macHosts | ConvertTo-Json | Out-File -FilePath $FilePath -Encoding UTF8
        }

        Write-Information "Export of MAC hosts to '$FilePath' successful." -InformationAction Continue

        # Return summary object
        return [PSCustomObject]@{
            Operation     = 'Export'
            ObjectType    = 'MacHost'
            Total         = $macHosts.Count
            Success       = $macHosts.Count
            Failed        = 0
            SuccessItems  = @($macHosts.Name)
            FailedItems   = @()
        }
    }
    catch {
        throw "Error exporting MAC hosts to '': $($_.Exception.Message)"
    }
}

<#
        .SYNOPSIS
        Imports MacHost objects from a CSV or JSON file.

        .DESCRIPTION
        Reads MacHost objects from a specified CSV or JSON file and creates them on the Sophos Firewall using the New-SfosMacHost cmdlet.
        The file must have the appropriate headers/structure matching the MacHost properties (Name, MACAddress, Description).

        .PARAMETER FilePath
        Full path to the input CSV or JSON file.

        .PARAMETER Format
        Import format: 'AsCSV' (default) or 'AsJSON'. Must match the file format.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, uses the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skip SSL/TLS certificate validation for self-signed certificates.

        .OUTPUTS
        PSCustomObject with properties:
        - Operation: 'Import'
        - ObjectType: 'MacHost'
        - Total: Number of objects in import file
        - Success: Number of successfully created objects
        - Failed: Number of failed creations
        - SuccessItems: Array of successfully imported MacHost names
        - FailedItems: Array of PSCustomObjects with Name and Error details for failed items

        .EXAMPLE
        # Import MAC hosts from CSV
        Import-SfosMacHosts -FilePath "C:\Imports\MacHosts.csv"

        .EXAMPLE
        # Import from JSON with explicit connection
        $result = Import-SfosMacHosts -FilePath "C:\Imports\MacHosts.json" -Format AsJSON -Firewall "192.168.1.1"
        $result | Format-Table

        .NOTES
        Minimum supported PowerShell version: 5.1
        This function depends on New-SfosMacHost to create the objects.

        .LINK
        Export-SfosMacHosts

        .LINK
        New-SfosMacHost
#>
function Import-SfosMacHosts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [ValidateSet('AsCSV', 'AsJSON')]
        [ValidateNotNullOrEmpty()]
        [string]$Format = 'AsCSV',

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    # Check if file exists
    if (-not (Test-Path -Path $FilePath)) {
        throw "File '' was not found."
    }

    # Resolve connection parameters
    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Import data from CSV or JSON
    try {
        if ($Format -eq 'AsCSV') {
            $macHosts = Import-Csv -Path $FilePath -Encoding UTF8
        }
        else {
            $macHosts = Get-Content -Path $FilePath -Raw | ConvertFrom-Json
        }
    }
    catch {
        throw "Error importing MAC hosts from '': $($_.Exception.Message)"
    }

    # Ensure macHosts is an array
    if ($macHosts -isnot [array]) {
        $macHosts = @($macHosts)
    }

    # Track success and failures
    $successItems = @()
    $failedItems = @()

    # Create MAC hosts on the Sophos Firewall
    foreach ($macHost in $macHosts) {
        try {
            New-SfosMacHost -Name $macHost.Name `
                -MACAddress $macHost.MACAddress `
                -Description $macHost.Description `
                -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -SkipCertificateCheck:$params.SkipCertificateCheck
            
            $successItems += $macHost.Name
            Write-Information "Imported: $($macHost.Name)" -InformationAction Continue
        }
        catch {
            $failedItems += [PSCustomObject]@{
                Name  = $macHost.Name
                Error = $_.Exception.Message
            }
            Write-Information "Error importing '$($macHost.Name)': $($_.Exception.Message)" -InformationAction Continue
        }
    }

    # Return summary object
    return [PSCustomObject]@{
        Operation     = 'Import'
        ObjectType    = 'MacHost'
        Total         = $macHosts.Count
        Success       = $successItems.Count
        Failed        = $failedItems.Count
        SuccessItems  = $successItems
        FailedItems   = $failedItems
    }
}

#endregion MACHost

#region CountryHostGroup 

# --- CountryHostGroup ---

<#
        .SYNOPSIS
        Retrieves CountryHostGroup objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for CountryHostGroup objects. By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.
    
        Note: Sophos GET responses can be inconsistent regarding status elements. This cmdlet is designed to return an empty result when no records are found.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER NameLike
        Optional name filter. In Sophos SFOS, 'like' behaves as a substring match (the supplied value may match anywhere in the object name).

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .PARAMETER AsXml
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve all objects
        Get-SfosCountryHostGroup

        .EXAMPLE
        # Filter by name (substring match)
        Get-SfosCountryHostGroup -NameLike "Example"

        .EXAMPLE
        # Return raw XML for troubleshooting
        Get-SfosCountryHostGroup -NameLike "Example" -AsXml

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/21.5/api/
#>
function Get-SfosCountryHostGroup 
{
    [CmdletBinding()]
    param(
        # Functional parameters
        [string]$NameLike,
        [string]$DescriptionLike,
        
        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        
        # Output parameters
        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $filterXml = ''
    if ($NameLike) 
    {
        $nameLikeEsc = ConvertTo-SfosXmlEscaped -Text $NameLike
        $filterXml = ('<Filter><key name="Name" criteria="like">{0}</key></Filter>' -f $nameLikeEsc)
    }

    if ($DescriptionLike) 
    {
        $descLikeEsc = ConvertTo-SfosXmlEscaped -Text $DescriptionLike
        $filterXml += ('<Filter><key name="Description" criteria="like">{0}</key></Filter>' -f $descLikeEsc)
    }

    $inner = @"
<Get>
  <CountryGroup>
    $filterXml
  </CountryGroup>
</Get>
"@

    try 
    {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch 
    {
        throw "Error retrieving CountryHostGroup objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Check login status
    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/CountryGroup[Name]' | ForEach-Object -Process {
        $_.Node
    }

    if ($AsXml) 
    {
        return @($nodes)
    }

    # Erstelle PSCustomObjects
    $countryHostGroupObjects = @()
    foreach ($node in $nodes) 
    {
        $countryHostGroupObjects += [PSCustomObject]@{
            Name        = $node.Name
            Description = $node.Description
            Countries   = [string[]]($node.CountryList | Select-Object -ExpandProperty Country)
        }
    }

    return $countryHostGroupObjects
}

<#
        .SYNOPSIS
        Creates a new country-based host group on the Sophos Firewall.

        .DESCRIPTION
        Creates a country host group using Geo-IP databases. Useful for:
        - Geographic access restrictions (block/allow by country)
        - Compliance requirements (GDPR, data sovereignty)
        - Threat mitigation (block high-risk regions)
        - License enforcement (region-specific services)
        
        The firewall uses its Geo-IP database to match IP addresses to countries.

        .PARAMETER Name
        Name of the country host group (1-50 characters, no commas).

        .PARAMETER Countries
        Array of country codes (ISO 3166-1 alpha-2 format).
        Examples: 'US', 'DE', 'GB', 'CN', 'RU'
        Use Get-SfosCountryHostGroup to see available country codes.

        .PARAMETER Description
        Optional description (max 255 characters).

        # Connection parameters (optional - use stored context if not provided)
        
        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses stored connection context.

        .PARAMETER Port
        Management/API port number. If omitted, uses stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation.

        .OUTPUTS
        None. Throws an exception if creation fails.

        .EXAMPLE
        # Create group for European countries
        New-SfosCountryHostGroup -Name "EU-Countries" -Countries @('DE', 'FR', 'IT', 'ES', 'NL') -Description "European Union member states"

        .EXAMPLE
        # Create group to block high-risk countries
        New-SfosCountryHostGroup -Name "BlockList-Countries" -Countries @('CN', 'RU', 'KP') -Description "Countries to block for security"

        .EXAMPLE
        # Create group for US regions
        New-SfosCountryHostGroup -Name "North-America" -Countries @('US', 'CA', 'MX') -Description "North American countries"

        .EXAMPLE
        # Create single-country group
        New-SfosCountryHostGroup -Name "Germany-Only" -Countries @('DE') -Description "German IP addresses only"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Requires up-to-date Geo-IP database on firewall.
        Country codes are case-sensitive (use uppercase).

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
        
        .LINK
        Get-SfosCountryHostGroup
        
        .LINK
        Set-SfosCountryHostGroup
        
        .LINK
        Remove-SfosCountryHostGroup
#>
function New-SfosCountryHostGroup 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [string[]]$countries,

        [ValidateLength(0, 255)]
        [string]$Description,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

    # Setup Description XML
    $xmlDescription = ''
    if ($Description) 
    {
        $descEsc = ConvertTo-SfosXmlEscaped -Text $Description
        $xmlDescription = "<Description>$descEsc</Description>"
    }

    # Setup Countries XML
    $countriesXml = ''
    foreach ($country in $countries) 
    {
        if (-not $country) 
        {
            continue
        }
        $cEsc = ConvertTo-SfosXmlEscaped -Text $country
        $countriesXml += "<Country>$cEsc</Country>"
    }

    # Build Countries List XML
    $xmlCountriesList = ''
    if( $countriesXml ) 
    {
        $xmlCountriesList = @"
<CountryList>
    $countriesXml
</CountryList>
"@
    }

    # Build API Inner XML
    $inner = @"
<Set operation="add">
  <CountryHostGroup>
    <Name>$nameEsc</Name>
    $xmlDescription
    $xmlCountriesList
  </CountryHostGroup>
</Set>
"@

    try 
    {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch 
    {
        throw "Error creating CountryHostGroup object '': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Check login status
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'CountryHostGroup' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Updates an existing CountryHostGroup object on the Sophos Firewall.

        .DESCRIPTION
        Updates a CountryHostGroup object using the Sophos Firewall XML API. You can supply the target object name directly or via the pipeline (when supported by the function's parameters).

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER Countries
        Parameter used by this cmdlet.

        .PARAMETER Description
        Optional description text.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Update an object by name
        Set-SfosCountryHostGroup -Name "Example"

        .EXAMPLE
        # Update using pipeline input
        Get-SfosCountryHostGroup -NameLike "Example" | Set-SfosCountryHostGroup  # when pipeline is supported

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/21.5/api/
#>
function Set-SfosCountryHostGroup 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string[]]$countries,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(0, 255)]
        [string]$Description,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        # Setup Description XML
        $xmlDescription = ''
        if ($Description) 
        {
            $descEsc = ConvertTo-SfosXmlEscaped -Text $Description
            $xmlDescription = "<Description>$descEsc</Description>"
        }

        # Setup Countries XML
        $countriesXml = ''
        foreach ($country in $countries) 
        {
            if (-not $country) 
            {
                continue
            }
            $cEsc = ConvertTo-SfosXmlEscaped -Text $country
            $countriesXml += "<Country>$cEsc</Country>"
        }

        # Build Countries List XML
        $xmlCountriesList = ''
        if ( $countriesXml ) 
        {
            $xmlCountriesList = @"
<CountryList>
    $countriesXml
</CountryList>
"@
        }

        # Build API Inner XML
        $inner = @"
<Set operation="edit">
  <CountryHostGroup>
    <Name>$nameEsc</Name>
    $xmlDescription
    $xmlCountriesList
  </CountryHostGroup>
</Set>
"@

        try 
        {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch 
        {
            throw "Error updating CountryHostGroup object '': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'CountryHostGroup' -Action 'edit' -Target $Name
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes a CountryHostGroup object from the Sophos Firewall.

        .DESCRIPTION
        Removes a CountryHostGroup object using the Sophos Firewall XML API. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Preview removal
        Remove-SfosCountryHostGroup -Name "Example" -WhatIf

        .EXAMPLE
        # Pipeline removal preview
        Remove-SfosCountryHostGroup -Name "Example" -WhatIf

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/21.5/api/
#>
function Remove-SfosCountryHostGroup 
{
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        if (-not $PSCmdlet.ShouldProcess("CountryHostGroup '$Name' on $($params.Firewall)", 'Remove')) 
        {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <CountryHostGroup>
    <Name>$nameEsc</Name>
  </CountryHostGroup>
</Remove>
"@

        try 
        {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch 
        {
            throw "Error removing CountryHostGroup object '': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'CountryHostGroup' -Action 'remove' -Target $Name
    }
    end {
    }
}

#endregion CountryHostGroup

#region Service

# --- Service ---

<#
        .SYNOPSIS
        Retrieves service definitions from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for service objects. Returns PowerShell-friendly 
        objects by default, or raw XML nodes with -AsXml.
        
        Supports multiple filter parameters:
        - Server-side filters: NameLike, DescriptionLike, TypeLike (faster)
        - Client-side filters: ProtocolLike, SourcePortLike, DestinationPortLike (more flexible)
        
        Returns empty result when no services match the criteria.

        .PARAMETER NameLike
        Filter by service name (substring match). Server-side filter.

        .PARAMETER DescriptionLike
        Filter by description (substring match). Server-side filter.

        .PARAMETER TypeLike
        Filter by service type. Valid values: 'TCPorUDP', 'IP', 'ICMP', 'ICMPv6'. Server-side filter.

        .PARAMETER ProtocolLike
        Filter by protocol (e.g., 'TCP', 'UDP'). Client-side filter using wildcards.

        .PARAMETER SourcePortLike
        Filter by source port or range. Client-side filter using wildcards.

        .PARAMETER DestinationPortLike
        Filter by destination port or range. Client-side filter using wildcards.

        # Connection parameters (optional - use stored context if not provided)
        
        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses stored connection context.

        .PARAMETER Port
        Management/API port number. If omitted, uses stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation.

        # Output parameters
        
        .PARAMETER AsXml
        Returns raw XML nodes instead of PowerShell objects.

        .OUTPUTS
        PSCustomObject with properties: Name, Description, Type, ServiceDetails
        System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve all services
        Get-SfosService

        .EXAMPLE
        # Find services by name pattern
        Get-SfosService -NameLike "HTTP*"

        .EXAMPLE
        # Find all TCP services
        Get-SfosService -TypeLike "TCPorUDP" -ProtocolLike "TCP"

        .EXAMPLE
        # Find services using specific port
        Get-SfosService -DestinationPortLike "443"

        .EXAMPLE
        # Find services in port range
        Get-SfosService -DestinationPortLike "8*"

        .EXAMPLE
        # Get service details as XML
        Get-SfosService -NameLike "HTTPS" -AsXml

        .EXAMPLE
        # Find all ICMP services
        Get-SfosService -TypeLike "ICMP"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Client-side filters retrieve all services first, then filter locally.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
        
        .LINK
        New-SfosService
        
        .LINK
        Set-SfosService
        
        .LINK
        Remove-SfosService

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/21.5/api/
#>
function Get-SfosService 
{
    [CmdletBinding()]
    param(
        # Functional parameters
        [string]$NameLike,
        [string]$DescriptionLike,
        [ValidateSet('TCPorUDP','IP','ICMP','ICMPv6')]
        [string]$TypeLike,
        [string]$ProtocolLike,
        [string]$SourcePortLike,
        [string]$DestinationPortLike,
        
        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        
        # Output parameters
        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Classic serverside Filtering
    $result = @()
    $filterXml = ''
    if ($NameLike) 
    {
        $nameLikeEsc = ConvertTo-SfosXmlEscaped -Text $NameLike
        $filterXml = ('<Filter><key name="Name" criteria="like">{0}</key></Filter>' -f $nameLikeEsc)
    }

    if ($DescriptionLike) 
    {
        $descLikeEsc = ConvertTo-SfosXmlEscaped -Text $DescriptionLike
        $filterXml += ('<Filter><key name="Description" criteria="like">{0}</key></Filter>' -f $descLikeEsc)
    }

    if ($TypeLike) 
    {
        $typeLikeEsc = ConvertTo-SfosXmlEscaped -Text $TypeLike
        $filterXml += ('<Filter><key name="Type" criteria="=">{0}</key></Filter>' -f $typeLikeEsc)
    }

    
    # Advanced filtering done, return results if any filter applied
    if ($ProtocolLike -or $SourcePortLike -or $DestinationPortLike) 
    {
        $allServices = Get-SfosService
        
        if ($ProtocolLike) 
        {
            $protocolLikeEsc = ConvertTo-SfosXmlEscaped -Text $ProtocolLike
            $result += $allServices | Where-Object -FilterScript {
                $_.ServiceDetails.Protocol -like $protocolLikeEsc
            }
        }

        if ($SourcePortLike) 
        {
            $sourcePortLikeEsc = ConvertTo-SfosXmlEscaped -Text $SourcePortLike
            $result += $allServices | Where-Object -FilterScript {
                $_.ServiceDetails.SourcePort -like $sourcePortLikeEsc
            }
        }
    
        if ($DestinationPortLike) 
        {
            $destinationPortLikeEsc = ConvertTo-SfosXmlEscaped -Text $DestinationPortLike
            $result += $allServices | Where-Object -FilterScript {
                $_.ServiceDetails.DestinationPort -like $destinationPortLikeEsc
            }
        }

        return $result | Select-Object -Unique
    }

    # Build API Inner XML
    $inner = @"
<Get>
  <Services>
    $filterXml
  </Services>
</Get>
"@

    # Invoke API
    $response = Invoke-SfosApi -Firewall $params.Firewall `
    -Port $params.Port `
    -Username $params.Username `
    -Password $params.Password `
    -InnerXml $inner `
    -SkipCertificateCheck:$params.SkipCertificateCheck
    
    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Services' -Action 'get'

    $nodeList = Select-Xml -Xml $XmlResponse -XPath '/Response/Services[Name]' -ErrorAction SilentlyContinue | `
    ForEach-Object -Process {
        $_.Node
    }

    # Return raw XML if requested
    if ($AsXml) 
    {
        return @($nodeList)
    }

    # Create PSCustomObjectss
    try
    {
        $result = foreach ($nodeItem in @($nodeList)) 
        {
            $serviceNodes = @()
            $serviceNodes += $nodeItem.ServiceDetails | Select-Object -ExpandProperty ServiceDetail
        
            $serviceObjects = foreach ($serviceItem in $serviceNodes) 
            {
                if($nodeItem.Type -like 'TCPorUDP') 
                {
                    [pscustomobject]@{
                        SourcePort      = [string]$serviceItem.SourcePort
                        DestinationPort = [string]$serviceItem.DestinationPort
                        Protocol        = [string]$serviceItem.Protocol
                    }
                }
                elseif($nodeItem.Type -like 'IP') 
                {
                    [pscustomobject]@{
                        ProtocolName = [string]$serviceItem.ProtocolName
                    }
                }
                elseif($nodeItem.Type -like 'ICMP') 
                {
                    [pscustomobject]@{
                        ICMPType = [string]$serviceItem.ICMPType
                        ICMPCode = [string]$serviceItem.ICMPCode
                    }
                }
                elseif($nodeItem.Type -like 'ICMPv6') 
                {
                    [pscustomobject]@{
                        ICMPv6Type = [string]$serviceItem.ICMPv6Type
                        ICMPv6Code = [string]$serviceItem.ICMPv6Code
                    }
                }
                else 
                {
                    Write-Warning -Message ('[W] Could not detect ServiceType:{0}' -f $nodeItem.Type)
                }
            }

            # Build Custom Object
            [pscustomobject]@{
                Name           = [string]$nodeItem.Name
                Description    = [string]$nodeItem.Description
                Type           = [string]$nodeItem.Type
                ServiceDetails = $serviceObjects
            }
        }
    }
    catch [Management.Automation.RuntimeException]
    {
        # get error record
        [Management.Automation.ErrorRecord]$e = $_

        # retrieve information about runtime error
        $info = [PSCustomObject]@{
            Exception = $e.Exception.Message
            Reason    = $e.CategoryInfo.Reason
            Target    = $e.CategoryInfo.TargetName
            Script    = $e.InvocationInfo.ScriptName
            Line      = $e.InvocationInfo.ScriptLineNumber
            Column    = $e.InvocationInfo.OffsetInLine
        }
        
        # output information. Post-process collected info, and log info (optional)
        $info
    }


    return $result
}

<#
        .SYNOPSIS
        Creates a new service definition on the Sophos Firewall.

        .DESCRIPTION
        Creates a service object for TCP/UDP ports, IP protocols, ICMP, or ICMPv6.
        Services are used in firewall rules to define allowed/blocked traffic.
        
        Supports four parameter sets:
        - TCPUDP: TCP or UDP services with port numbers/ranges
        - IP: IP protocol numbers (e.g., GRE, ESP, OSPF)
        - ICMP: ICMP types and codes for IPv4
        - ICMPv6: ICMPv6 types and codes for IPv6

        .PARAMETER Name
        Name of the service (1-50 characters, no commas).

        .PARAMETER Type
        Service type: 'TCPorUDP', 'IP', 'ICMP', or 'ICMPv6'. Default: 'TCPorUDP'.

        .PARAMETER Protocol
        Protocol for TCP/UDP services: 'TCP' or 'UDP'. Required for TCPUDP parameter set.

        .PARAMETER DstPort
        Destination port or port range. Examples: '443', '8080-8090', '1024:65535'.
        Required for TCPUDP parameter set.

        .PARAMETER SrcPort
        Source port or port range. Default: '1:65535' (all ports).

        .PARAMETER ProtocolName
        IP protocol name (e.g., 'GRE', 'ESP', 'OSPFIGP'). Required for IP parameter set.

        .PARAMETER ICMPType
        ICMP type(s) for IPv4. Valid values: -1, 0, 3, 4, 5, 8, 11-18, 30-40.
        Use -1 for 'any'. Required for ICMP parameter set.

        .PARAMETER ICMPCode
        ICMP code(s). Valid values: -1 (any), 0-15. Optional for ICMP parameter set.

        .PARAMETER ICMPv6Type
        ICMPv6 type(s) for IPv6. Valid values: -1, 0-4, 100-101, 128-158, 200-201.
        Required for ICMPv6 parameter set.

        .PARAMETER ICMPv6Code
        ICMPv6 code(s). Valid values: -1 (any), 0-15. Optional for ICMPv6 parameter set.

        .PARAMETER Description
        Optional description (max 255 characters).

        # Connection parameters (optional - use stored context if not provided)
        
        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses stored connection context.

        .PARAMETER Port
        Management/API port number. If omitted, uses stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation.

        .OUTPUTS
        None. Throws an exception if creation fails.

        .EXAMPLE
        # Create a TCP service for custom HTTPS port
        New-SfosService -Name "HTTPS-Custom" -Protocol TCP -DstPort 8443 -Description "Custom HTTPS port"

        .EXAMPLE
        # Create a UDP service for DNS
        New-SfosService -Name "DNS-Custom" -Protocol UDP -DstPort 53 -SrcPort "1024:65535"

        .EXAMPLE
        # Create a service with port range
        New-SfosService -Name "WebPorts" -Protocol TCP -DstPort "8080-8090" -Description "Web application ports"

        .EXAMPLE
        # Create an IP protocol service (GRE for VPN)
        New-SfosService -Name "GRE-Protocol" -Type IP -ProtocolName "GRE" -Description "Generic Routing Encapsulation"

        .EXAMPLE
        # Create ICMP echo service (ping)
        New-SfosService -Name "ICMP-Echo" -Type ICMP -ICMPType "8" -ICMPCode "0" -Description "Ping requests"

        .EXAMPLE
        # Create ICMPv6 service
        New-SfosService -Name "ICMPv6-EchoRequest" -Type ICMPv6 -ICMPv6Type "128" -Description "IPv6 ping"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Uses parameter sets to enforce correct parameter combinations.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
        
        .LINK
        Get-SfosService
        
        .LINK
        Set-SfosService
        
        .LINK
        Remove-SfosService
        
        .LINK
        New-SfosServiceGroup
#>
function New-SfosService 
{
    [CmdletBinding(DefaultParameterSetName = 'TCPUDP')]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,
        
        [ValidateLength(0, 255)]
        [string]$Description,

        [Parameter(ParameterSetName = 'TCPUDP')]
        [ValidateSet('TCPorUDP', 'IP', 'ICMP', 'ICMPv6')]
        [string]$Type = 'TCPorUDP',
        
        # --- Parameter-Set fr TCP/UDP ---
        [Parameter(Mandatory, ParameterSetName = 'TCPUDP')]
        [ValidateSet('TCP', 'UDP')]
        [string]$Protocol,

        [Parameter(Mandatory, ParameterSetName = 'TCPUDP')]
        [string]$DstPort,

        [Parameter(ParameterSetName = 'TCPUDP')]
        [string]$SrcPort = '1:65535',

        # --- Parameter-Set fr IP-Protokolle ---
        [Parameter(Mandatory, ParameterSetName = 'IP')]
        [string]$ProtocolName, # z.B. GRE, ESP, OSPFIGP

        # --- Parameter-Set fr ICMP ---
        [Parameter(Mandatory, ParameterSetName = 'ICMP')]
        [ValidateSet('-1', '0', '3', '4', '5', '8', '11', '12', '13', '14', '15', '16', '17', '18', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40')]
        [string[]]$ICMPType,

        [Parameter(ParameterSetName = 'ICMP')]
        [ValidateSet('-1', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15')]
        [string[]]$ICMPCode,
        
        # --- Parameter-Set fr ICMPv6 ---
        [Parameter(Mandatory, ParameterSetName = 'ICMPv6')]
        [ValidateSet('0', '-1', '1', '2', '3', '4', '100', '101', '128', '129', '130', '131', '132', '133', '134', '135', '136', '137', '138', '139', '140', '141', '142', '143', '144', '145', '146', '147', '148', '149', '150', '151', '152', '153', '154', '155', '156', '157', '158', '200', '201')]
        [string[]]$ICMPv6Type,

        [Parameter(ParameterSetName = 'ICMPv6')]
        [ValidateSet('-1', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15')]
        [string[]]$ICMPv6Code,
        
        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    # Initialisierung des Service-Details basierend auf dem Parameter-Set
    $detailXml = ''
    switch ($PSCmdlet.ParameterSetName) {
        'TCPUDP' 
        {
            $detailXml = "<Protocol>$Protocol</Protocol><SourcePort>$SrcPort</SourcePort><DestinationPort>$DstPort</DestinationPort>" 
        }
        'IP' 
        {
            $Type = 'IP'
            $detailXml = "<ProtocolName>$ProtocolName</ProtocolName>"
        }
        'ICMP' 
        {
            $detailXml = "<ICMPType>$($ICMPType -join ',')</ICMPType><ICMPCode>$($ICMPCode -join ',')</ICMPCode>" 
        }
        'ICMPv6' 
        {
            $detailXml = "<ICMPv6Type>$($ICMPv6Type -join ',')</ICMPv6Type><ICMPv6Code>$($ICMPv6Code -join ',')</ICMPv6Code>" 
        }
    }

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
    $xmlDescription = if ($Description) 
    {
        "<Description>$(ConvertTo-SfosXmlEscaped -Text $Description)</Description>" 
    }
    else 
    {
        '' 
    }
    $inner = "<Set operation='add'><Services><Name>$nameEsc</Name>$xmlDescription<Type>$Type</Type><ServiceDetails><ServiceDetail>$detailXml</ServiceDetail></ServiceDetails></Services></Set>"

    try 
    {
        $response = Invoke-SfosApi -Firewall $params.Firewall -Port $params.Port -Username $params.Username -Password $params.Password -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck
        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Service' -Action 'create' -Target $Name
    }
    catch 
    {
        throw "Failed to create Service '$Name': $($_.Exception.Message)"
    }
}

function Set-SfosService 
{
    [CmdletBinding(DefaultParameterSetName = 'TCPUDP')]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,
        
        [ValidateLength(0, 255)]
        [string]$Description,

        [Parameter(Mandatory, ParameterSetName = 'TCPUDP')]
        [ValidateSet('TCPorUDP', 'IP', 'ICMP', 'ICMPv6')]
        [string]$Type,
        
        [Parameter(Mandatory, ParameterSetName = 'TCPUDP')]
        [ValidateSet('TCP', 'UDP')]
        [string]$Protocol,

        [Parameter(Mandatory, ParameterSetName = 'TCPUDP')]
        [string]$DstPort,

        [Parameter(ParameterSetName = 'TCPUDP')]
        [string]$SrcPort = '1:65535',

        [Parameter(Mandatory, ParameterSetName = 'IP')]
        [string]$ProtocolName,

        [Parameter(Mandatory, ParameterSetName = 'ICMP')]
        [ValidateSet('-1', '0', '3', '4', '5', '8', '11', '12', '13', '14', '15', '16', '17', '18', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40')]
        [string[]]$ICMPType,

        [Parameter(ParameterSetName = 'ICMP')]
        [ValidateSet('-1', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15')]
        [string[]]$ICMPCode,
        
        [Parameter(Mandatory, ParameterSetName = 'ICMPv6')]
        [ValidateSet('0', '-1', '1', '2', '3', '4', '100', '101', '128', '129', '130', '131', '132', '133', '134', '135', '136', '137', '138', '139', '140', '141', '142', '143', '144', '145', '146', '147', '148', '149', '150', '151', '152', '153', '154', '155', '156', '157', '158', '200', '201')]
        [string[]]$ICMPv6Type,

        [Parameter(ParameterSetName = 'ICMPv6')]
        [ValidateSet('-1', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15')]
        [string[]]$ICMPv6Code,
        
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )
    
    $detailXml = ''
    switch ($PSCmdlet.ParameterSetName) {
        'TCPUDP' 
        {
            $detailXml = "<Protocol>$Protocol</Protocol><SourcePort>$SrcPort</SourcePort><DestinationPort>$DstPort</DestinationPort>"
        }
        'IP' 
        {
            $Type = 'IP'
            $detailXml = "<ProtocolName>$ProtocolName</ProtocolName>"
        }
        'ICMP' 
        {
            $detailXml = "<ICMPType>$($ICMPType -join ',')</ICMPType><ICMPCode>$($ICMPCode -join ',')</ICMPCode>"
        }
        'ICMPv6' 
        {
            $detailXml = "<ICMPv6Type>$($ICMPv6Type -join ',')</ICMPv6Type><ICMPv6Code>$($ICMPv6Code -join ',')</ICMPv6Code>"
        }
    }
    
    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
    $xmlDescription = if ($Description) 
    {
        "<Description>$(ConvertTo-SfosXmlEscaped -Text $Description)</Description>" 
    }
    else 
    {
        '' 
    }

    $inner = "<Set operation='edit'><Services><Name>$nameEsc</Name>$xmlDescription<Type>$Type</Type><ServiceDetails><ServiceDetail>$detailXml</ServiceDetail></ServiceDetails></Services></Set>"

    try 
    {
        $response = Invoke-SfosApi -Firewall $params.Firewall -Port $params.Port -Username $params.Username -Password $params.Password -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck
        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Service' -Action 'edit' -Target $Name
    }
    catch 
    {
        throw "Failed to update Service '$Name': $($_.Exception.Message)"
    }
}


<#
        .SYNOPSIS
        Removes a Service object from the Sophos Firewall.

        .DESCRIPTION
        Removes a Service object using the Sophos Firewall XML API. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Preview removal
        Remove-SfosService -Name "Example" -WhatIf

        .EXAMPLE
        # Pipeline removal preview
        Remove-SfosService -Name "Example" -WhatIf

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/21.5/api/
#>
function Remove-SfosService 
{
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        if (-not $PSCmdlet.ShouldProcess("Service '$Name' on $($params.Firewall)", 'Remove')) 
        {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <Services>
    <Name>$nameEsc</Name>
  </Services>
</Remove>
"@

        try 
        {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner `
            -SkipCertificateCheck:$params.SkipCertificateCheck
        }
        catch 
        {
            throw "Failed to remove Service '$Name': $($_.Exception.Message)"
        }
        
        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Service' -Action 'remove' -Target $Name
    }

    end {

    }
}

<#
        .SYNOPSIS
        Exports Service objects to a CSV or JSON file.

        .DESCRIPTION
        Retrieves all Service objects from the Sophos Firewall and exports them to a file in CSV or JSON format.
        Useful for backup, documentation, or migration purposes. Services include TCP/UDP, IP protocols, ICMP, and ICMPv6 definitions.

        .PARAMETER FilePath
        Full path where the export file will be saved. The file extension should match the format (.csv for CSV, .json for JSON).

        .PARAMETER Format
        Export format: 'AsCSV' (default) or 'AsJSON'. CSV format is human-readable and Excel-compatible. JSON format preserves data structure.

        .PARAMETER Overwrite
        If specified, overwrite the file if it already exists. Without this switch, the function throws an error if the file exists.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, uses the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skip SSL/TLS certificate validation for self-signed certificates.

        .OUTPUTS
        PSCustomObject with properties:
        - Operation: 'Export'
        - ObjectType: 'Service'
        - Total: Number of objects exported
        - Success: Number of successful exports
        - Failed: Always 0 for export operations
        - SuccessItems: Array of exported Service names
        - FailedItems: Empty array for export operations

        .EXAMPLE
        # Export all services to CSV
        Export-SfosServices -FilePath "C:\Exports\Services.csv"

        .EXAMPLE
        # Export to JSON with overwrite
        Export-SfosServices -FilePath "C:\Exports\Services.json" -Format AsJSON -Overwrite

        .NOTES
        Minimum supported PowerShell version: 5.1
        This function depends on Get-SfosService to retrieve the objects.

        .LINK
        Import-SfosServices

        .LINK
        Get-SfosService
#>
function Export-SfosServices {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [ValidateSet('AsCSV', 'AsJSON')]
        [ValidateNotNullOrEmpty()]
        [string]$Format = 'AsCSV',

        [switch]$Overwrite,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    # Check if file exists
    if (Test-Path -Path $FilePath) {
        if ($Overwrite) {
            Remove-Item -Path $FilePath -Force
        }
        else {
            throw "File '' already exists. Provide a different file name or use -Overwrite."
        }
    }

    # Resolve connection parameters
    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Retrieve services
    try {
        $services = Get-SfosService -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -SkipCertificateCheck:$params.SkipCertificateCheck
    }
    catch {
        throw "Error retrieving services: $($_.Exception.Message)"
    }

    # Export to CSV or JSON
    try {
        if ($Format -eq 'AsCSV') {
            $services | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
        }
        else {
            $services | ConvertTo-Json | Out-File -FilePath $FilePath -Encoding UTF8
        }

        Write-Information "Export of services to '$FilePath' successful." -InformationAction Continue

        # Return summary object
        return [PSCustomObject]@{
            Operation     = 'Export'
            ObjectType    = 'Service'
            Total         = $services.Count
            Success       = $services.Count
            Failed        = 0
            SuccessItems  = @($services.Name)
            FailedItems   = @()
        }
    }
    catch {
        throw "Error exporting services to '': $($_.Exception.Message)"
    }
}

<#
        .SYNOPSIS
        Imports Service objects from a CSV or JSON file.

        .DESCRIPTION
        Reads Service objects from a specified CSV or JSON file and creates them on the Sophos Firewall using the New-SfosService cmdlet.
        The file must have the appropriate headers/structure matching the Service properties (Name, Protocol, DestinationPort, SourcePort, etc.).

        .PARAMETER FilePath
        Full path to the input CSV or JSON file.

        .PARAMETER Format
        Import format: 'AsCSV' (default) or 'AsJSON'. Must match the file format.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, uses the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skip SSL/TLS certificate validation for self-signed certificates.

        .OUTPUTS
        PSCustomObject with properties:
        - Operation: 'Import'
        - ObjectType: 'Service'
        - Total: Number of objects in import file
        - Success: Number of successfully created objects
        - Failed: Number of failed creations
        - SuccessItems: Array of successfully imported Service names
        - FailedItems: Array of PSCustomObjects with Name and Error details for failed items

        .EXAMPLE
        # Import services from CSV
        Import-SfosServices -FilePath "C:\Imports\Services.csv"

        .EXAMPLE
        # Import from JSON with explicit connection
        $result = Import-SfosServices -FilePath "C:\Imports\Services.json" -Format AsJSON -Firewall "192.168.1.1"
        $result | Format-Table

        .NOTES
        Minimum supported PowerShell version: 5.1
        This function depends on New-SfosService to create the objects.

        .LINK
        Export-SfosServices

        .LINK
        New-SfosService
#>
function Import-SfosServices {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [ValidateSet('AsCSV', 'AsJSON')]
        [ValidateNotNullOrEmpty()]
        [string]$Format = 'AsCSV',

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    # Check if file exists
    if (-not (Test-Path -Path $FilePath)) {
        throw "File '' was not found."
    }

    # Resolve connection parameters
    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Import data from CSV or JSON
    try {
        if ($Format -eq 'AsCSV') {
            $services = Import-Csv -Path $FilePath -Encoding UTF8
        }
        else {
            $services = Get-Content -Path $FilePath -Raw | ConvertFrom-Json
        }
    }
    catch {
        throw "Error importing services from '': $($_.Exception.Message)"
    }

    # Ensure services is an array
    if ($services -isnot [array]) {
        $services = @($services)
    }

    # Track success and failures
    $successItems = @()
    $failedItems = @()

    # Create services on the Sophos Firewall
    foreach ($service in $services) {
        try {
            New-SfosService -Name $service.Name `
                -Protocol $service.Protocol `
                -DstPort $service.DstPort `
                -SrcPort $service.SrcPort `
                -IcmpType $service.IcmpType `
                -IcmpCode $service.IcmpCode `
                -Ipv6IcmpType $service.Ipv6IcmpType `
                -Ipv6IcmpCode $service.Ipv6IcmpCode `
                -Description $service.Description `
                -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -SkipCertificateCheck:$params.SkipCertificateCheck
            
            $successItems += $service.Name
            Write-Information "Imported: $($service.Name)" -InformationAction Continue
        }
        catch {
            $failedItems += [PSCustomObject]@{
                Name  = $service.Name
                Error = $_.Exception.Message
            }
            Write-Information "Error importing '$($service.Name)': $($_.Exception.Message)" -InformationAction Continue
        }
    }

    # Return summary object
    return [PSCustomObject]@{
        Operation     = 'Import'
        ObjectType    = 'Service'
        Total         = $services.Count
        Success       = $successItems.Count
        Failed        = $failedItems.Count
        SuccessItems  = $successItems
        FailedItems   = $failedItems
    }
}

#endregion Service

#region ServiceGroup
# --- ServiceGroup ---

<#
        .SYNOPSIS
        Retrieves ServiceGroup objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for ServiceGroup objects. By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.
    
        Note: Sophos GET responses can be inconsistent regarding status elements. This cmdlet is designed to return an empty result when no records are found.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER NameLike
        Optional name filter. In Sophos SFOS, 'like' behaves as a substring match (the supplied value may match anywhere in the object name).

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .PARAMETER AsXml
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve all objects
        Get-SfosServiceGroup

        .EXAMPLE
        # Filter by name (substring match)
        Get-SfosServiceGroup -NameLike "Example"

        .EXAMPLE
        # Return raw XML for troubleshooting
        Get-SfosServiceGroup -NameLike "Example" -AsXml

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/21.5/api/
#>
function Get-SfosServiceGroup 
{
    [CmdletBinding()]
    param(
        # Functional parameters
        [string]$NameLike,
        [string]$DescriptionLike,
        
        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        
        # Output parameters
        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $filterXml = ''
    if ($NameLike) 
    {
        $nameLikeEsc = ConvertTo-SfosXmlEscaped -Text $NameLike
        $filterXml = ('<Filter><key name="Name" criteria="like">{0}</key></Filter>' -f $nameLikeEsc)
    }

    if ($DescriptionLike) 
    {
        $descLikeEsc = ConvertTo-SfosXmlEscaped -Text $DescriptionLike
        $filterXml += ('<Filter><key name="Description" criteria="like">{0}</key></Filter>' -f $descLikeEsc)
    }

    $inner = @"
<Get>
  <ServiceGroup>
    $filterXml
  </ServiceGroup>
</Get>
"@

    $response = Invoke-SfosApi -Firewall $params.Firewall `
    -Port $params.Port `
    -Username $params.Username `
    -Password $params.Password `
    -InnerXml $inner `
    -SkipCertificateCheck:$params.SkipCertificateCheck
        
    $XmlResponse = [xml]$response.Content
    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/ServiceGroup[Name]' | ForEach-Object -Process {
        $_.Node
    }
    if ($AsXml) 
    {
        return @($nodes)
    }

    # Erstelle PSCustomObjects
    $serviceGroupObjects = @()
    foreach ($node in $nodes) 
    {
        $serviceGroupObjects += [PSCustomObject]@{
            Name        = $node.Name
            Description = $node.Description
            ServiceList = $node.ServiceList | Select-Object -ExpandProperty Service
        }
    }

    return $serviceGroupObjects
}

<#
        .SYNOPSIS
        Creates a new service group on the Sophos Firewall.

        .DESCRIPTION
        Creates a service group to logically organize multiple service definitions.
        Use service groups in firewall rules to:
        - Simplify rule management (one group instead of many services)
        - Standardize application access (e.g., "WebServices" group)
        - Reduce rule count and improve readability
        
        After creation, use Add-SfosServiceGroupMember to add additional services.

        .PARAMETER Name
        Name of the service group (1-50 characters, no commas).

        .PARAMETER Members
        Array of service names to include in the group.
        Services must already exist on the firewall.

        .PARAMETER Description
        Optional description (max 255 characters).

        # Connection parameters (optional - use stored context if not provided)
        
        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses stored connection context.

        .PARAMETER Port
        Management/API port number. If omitted, uses stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation.

        .OUTPUTS
        None. Throws an exception if creation fails.

        .EXAMPLE
        # Create service group for web services
        New-SfosServiceGroup -Name "WebServices" -Members @('HTTP', 'HTTPS') -Description "Standard web traffic"

        .EXAMPLE
        # Create service group for Microsoft services
        New-SfosServiceGroup -Name "Microsoft365" -Members @('HTTPS', 'SMTP', 'IMAPS') -Description "Office 365 services"

        .EXAMPLE
        # Create empty group and add members later
        New-SfosServiceGroup -Name "CustomApps" -Description "Custom application ports"
        Add-SfosServiceGroupMember -ServiceGroupName "CustomApps" -Members @('CustomHTTPS', 'AppPort-8080')

        .EXAMPLE
        # Create service group for database services
        New-SfosServiceGroup -Name "DatabaseServices" -Members @('MSSQL', 'MySQL', 'PostgreSQL') -Description "Database access ports"

        .EXAMPLE
        # Create service group for remote access
        New-SfosServiceGroup -Name "RemoteAccess" -Members @('RDP', 'SSH', 'VNC') -Description "Remote desktop protocols"

        .NOTES
        Minimum supported PowerShell version: 5.1
        All member services must exist before creating the group.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
        
        .LINK
        Get-SfosServiceGroup
        
        .LINK
        Set-SfosServiceGroup
        
        .LINK
        Add-SfosServiceGroupMember
        
        .LINK
        Remove-SfosServiceGroup
#>
function New-SfosServiceGroup 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [string[]]$members,

        [ValidateLength(0, 255)]
        [string]$Description,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

    # Setup Description XML
    $xmlDescription = ''
    if ($Description) 
    {
        $descEsc = ConvertTo-SfosXmlEscaped -Text $Description
        $xmlDescription = "<Description>$descEsc</Description>"
    }

    # Setup Members XML
    $xmlMember = ''
    foreach ($member in $members) 
    {
        if (-not $member) 
        {
            continue
        }
        if ($member.Length -gt 50) 
        {
            throw "Member '' must be 50 characters or fewer."
        }
        if ($member -match ',') 
        {
            throw "Member '' cannot contain a comma."
        }
        $mEsc = ConvertTo-SfosXmlEscaped -Text $member
        $xmlMember += "<Service>$mEsc</Service>"
    }

    # Setup Members XML List
    $xmlServiceList = ''
    if( $xmlMember ) 
    {
        $xmlServiceList = @"
<ServiceList>
    $xmlMember
</ServiceList>
"@
    }

    # Build final XML    
    $inner = @"
<Set operation="add">
  <ServiceGroup>
    <Name>$nameEsc</Name>
    $xmlDescription
    $xmlServiceList
  </ServiceGroup>
</Set>
"@

    try 
    {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -InnerXml $inner `
        -SkipCertificateCheck:$params.SkipCertificateCheck
    }
    catch 
    {
        throw "Failed to create ServiceGroup '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ServiceGroup' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Updates an existing ServiceGroup object on the Sophos Firewall.

        .DESCRIPTION
        Updates a ServiceGroup object using the Sophos Firewall XML API. You can supply the target object name directly or via the pipeline (when supported by the function's parameters).

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER Members
        One or more member object names to include.

        .PARAMETER Description
        Optional description text.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Update an object by name
        Set-SfosServiceGroup -Name "Example"

        .EXAMPLE
        # Update using pipeline input
        Get-SfosServiceGroup -NameLike "Example" | Set-SfosServiceGroup  # when pipeline is supported

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/21.5/api/
#>
function Set-SfosServiceGroup 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string[]]$members,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(0, 255)]
        [string]$Description,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        # Setup Description XML
        $xmlDescription = ''
        if ($Description) 
        {
            $descEsc = ConvertTo-SfosXmlEscaped -Text $Description
            $xmlDescription = "<Description>$descEsc</Description>"
        }

        # Setup Members XML
        $xmlMember = ''
        foreach ($member in $members) 
        {
            if (-not $member) 
            {
                continue
            }
            if ($member.Length -gt 50) 
            {
                throw "Member '' must be 50 characters or fewer."
            }
            if ($member -match ',') 
            {
                throw "Member '' cannot contain a comma."
            }
            $mEsc = ConvertTo-SfosXmlEscaped -Text $member
            $xmlMember += "<Service>$mEsc</Service>"
        }
        
        # Setup Members XML List
        $xmlServiceList = ''
        if( $xmlMember ) 
        {
            $xmlServiceList = @"
<ServiceList>
    $xmlMember
</ServiceList>
"@
        }

        # Build final XML
        $inner = @"
<Set operation="edit">
  <ServiceGroup>
    <Name>$nameEsc</Name>
    $xmlDescription
    $xmlServiceList
  </ServiceGroup>
</Set>
"@

        try 
        {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner `
            -SkipCertificateCheck:$params.SkipCertificateCheck
        }
        catch 
        {
            throw "Failed to update ServiceGroup '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ServiceGroup' -Action 'edit' -Target $Name
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes a ServiceGroup object from the Sophos Firewall.

        .DESCRIPTION
        Removes a ServiceGroup object using the Sophos Firewall XML API. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Preview removal
        Remove-SfosServiceGroup -Name "Example" -WhatIf

        .EXAMPLE
        # Pipeline removal preview
        Remove-SfosServiceGroup -Name "Example" -WhatIf

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/21.5/api/
#>
function Remove-SfosServiceGroup 
{
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        if (-not $PSCmdlet.ShouldProcess("ServiceGroup '$Name' on $($params.Firewall)", 'Remove')) 
        {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <ServiceGroup>
    <Name>$nameEsc</Name>
  </ServiceGroup>
</Remove>
"@

        try 
        {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner `
            -SkipCertificateCheck:$params.SkipCertificateCheck
        }
        catch 
        {
            throw "Failed to remove ServiceGroup '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ServiceGroup' -Action 'remove' -Target $Name
    }
    end {
    }
}

<#
        .SYNOPSIS
        Adds members to a ServiceGroup on the Sophos Firewall.

        .DESCRIPTION
        Adds one or more members to a ServiceGroup using the Sophos Firewall XML API.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER ServiceGroupName
        Name of the target ServiceGroup.

        .PARAMETER Members
        One or more member object names to add.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Add members to a ServiceGroup
        Add-SfosServiceGroupMember -ServiceGroupName "ExampleGroup" -Members "Service1", "Service2"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/21.5/api/
#>
function Add-SfosServiceGroupMember 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$ServiceGroupName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$members,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    $groupNameEsc = ConvertTo-SfosXmlEscaped -Text $ServiceGroupName

    # Setup Members XML
    $xmlMember = ''
    foreach ($member in $members) 
    {
        if (-not $member) 
        {
            continue
        }
        if ($member.Length -gt 50) 
        {
            throw "Member '' must be 50 characters or fewer."
        }
        if ($member -match ',') 
        {
            throw "Member '' cannot contain a comma."
        }
        $mEsc = ConvertTo-SfosXmlEscaped -Text $member
        $xmlMember += "<Service>$mEsc</Service>"
    }

    # Build final XML
    $inner = @"
<Set operation="add">
  <ServiceGroup>
    <Name>$groupNameEsc</Name>
    <ServiceList>
        $xmlMember
    </ServiceList>
  </ServiceGroup>
</Set>
"@

    try 
    {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -InnerXml $inner `
        -SkipCertificateCheck:$params.SkipCertificateCheck
    }
    catch 
    {
        throw "Failed to add members to ServiceGroup '$ServiceGroupName': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ServiceGroup' -Action 'add members' -Target $ServiceGroupName
}

<#      
        .SYNOPSIS
        Removes members from a ServiceGroup on the Sophos Firewall.

        .DESCRIPTION
        Removes one or more members from a ServiceGroup using the Sophos Firewall XML API.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target ServiceGroup.

        .PARAMETER Members
        One or more member object names to remove.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Remove members from a ServiceGroup
        Remove-SfosServiceGroupMember -Name "ExampleGroup" -Members "Service1", "Service2"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/21.5/api/
#>
function Remove-SfosServiceGroupMember 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$members,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    $groupNameEsc = ConvertTo-SfosXmlEscaped -Text $Name

    # Setup Members XML
    $xmlMember = ''
    foreach ($member in $members) 
    {
        if (-not $member) 
        {
            continue
        }
        if ($member.Length -gt 50) 
        {
            throw "Member '' must be 50 characters or fewer."
        }
        if ($member -match ',') 
        {
            throw "Member '' cannot contain a comma."
        }
        $mEsc = ConvertTo-SfosXmlEscaped -Text $member
        $xmlMember += "<Service>$mEsc</Service>"
    }

    # Build final XML
    $inner = @"
<Set operation="remove">
  <ServiceGroup>
    <Name>$groupNameEsc</Name>
    <ServiceList>
        $xmlMember
    </ServiceList>
  </ServiceGroup>
</Set>
"@

    try 
    {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -InnerXml $inner `
        -SkipCertificateCheck:$params.SkipCertificateCheck
    }
    catch 
    {
        throw "Failed to remove members from ServiceGroup '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ServiceGroup' -Action 'remove members' -Target $Name
}

<#
        .SYNOPSIS
        Exports ServiceGroup objects to a CSV or JSON file.

        .DESCRIPTION
        Retrieves all ServiceGroup objects from the Sophos Firewall and exports them to a file in CSV or JSON format.
        Group members are stored as JSON arrays within the file for proper handling of multiple members.
        Useful for backup, documentation, or migration purposes.

        .PARAMETER FilePath
        Full path where the export file will be saved. The file extension should match the format (.csv for CSV, .json for JSON).

        .PARAMETER Format
        Export format: 'AsCSV' (default) or 'AsJSON'. CSV format stores member arrays as JSON strings. JSON format preserves nested structure.

        .PARAMETER Overwrite
        If specified, overwrite the file if it already exists. Without this switch, the function throws an error if the file exists.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, uses the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skip SSL/TLS certificate validation for self-signed certificates.

        .OUTPUTS
        PSCustomObject with properties:
        - Operation: 'Export'
        - ObjectType: 'ServiceGroup'
        - Total: Number of objects exported
        - Success: Number of successful exports
        - Failed: Always 0 for export operations
        - SuccessItems: Array of exported ServiceGroup names
        - FailedItems: Empty array for export operations

        .EXAMPLE
        # Export all service groups to CSV
        Export-SfosServiceGroups -FilePath "C:\Exports\ServiceGroups.csv"

        .EXAMPLE
        # Export to JSON with overwrite
        Export-SfosServiceGroups -FilePath "C:\Exports\ServiceGroups.json" -Format AsJSON -Overwrite

        .NOTES
        Minimum supported PowerShell version: 5.1
        This function depends on Get-SfosServiceGroup to retrieve the objects.
        Group members are stored as JSON arrays within CSV fields for proper serialization.

        .LINK
        Import-SfosServiceGroups

        .LINK
        Get-SfosServiceGroup
#>
function Export-SfosServiceGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [ValidateSet('AsCSV', 'AsJSON')]
        [ValidateNotNullOrEmpty()]
        [string]$Format = 'AsCSV',

        [switch]$Overwrite,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    # Check if file exists
    if (Test-Path -Path $FilePath) {
        if ($Overwrite) {
            Remove-Item -Path $FilePath -Force
        }
        else {
            throw "File '' already exists. Provide a different file name or use -Overwrite."
        }
    }

    # Resolve connection parameters
    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Retrieve service groups
    try {
        $serviceGroups = Get-SfosServiceGroup -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -SkipCertificateCheck:$params.SkipCertificateCheck
    }
    catch {
        throw "Error retrieving service groups: $($_.Exception.Message)"
    }

    # Convert member arrays to JSON strings for proper serialization
    try {
        $groupsToExport = @()
        foreach ($group in $serviceGroups) {
            $groupObj = $group | Select-Object * -ExcludeProperty ServiceList
            if ($group.ServiceList) {
                $groupObj | Add-Member -NotePropertyName ServiceList -NotePropertyValue ($group.ServiceList | ConvertTo-Json -Compress)
            }
            else {
                $groupObj | Add-Member -NotePropertyName ServiceList -NotePropertyValue ''
            }
            $groupsToExport += $groupObj
        }

        if ($Format -eq 'AsCSV') {
            $groupsToExport | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
        }
        else {
            $serviceGroups | ConvertTo-Json | Out-File -FilePath $FilePath -Encoding UTF8
        }

        Write-Information "Export of service groups to '$FilePath' successful." -InformationAction Continue

        # Return summary object
        return [PSCustomObject]@{
            Operation     = 'Export'
            ObjectType    = 'ServiceGroup'
            Total         = $serviceGroups.Count
            Success       = $serviceGroups.Count
            Failed        = 0
            SuccessItems  = @($serviceGroups.Name)
            FailedItems   = @()
        }
    }
    catch {
        throw "Error exporting service groups to '': $($_.Exception.Message)"
    }
}

<#
        .SYNOPSIS
        Imports ServiceGroup objects from a CSV or JSON file.

        .DESCRIPTION
        Reads ServiceGroup objects from a specified CSV or JSON file and creates them on the Sophos Firewall using the New-SfosServiceGroup cmdlet.
        The file must have the appropriate headers/structure. Members are expected as JSON arrays in CSV fields.

        .PARAMETER FilePath
        Full path to the input CSV or JSON file.

        .PARAMETER Format
        Import format: 'AsCSV' (default) or 'AsJSON'. Must match the file format.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, uses the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skip SSL/TLS certificate validation for self-signed certificates.

        .OUTPUTS
        PSCustomObject with properties:
        - Operation: 'Import'
        - ObjectType: 'ServiceGroup'
        - Total: Number of objects in import file
        - Success: Number of successfully created objects
        - Failed: Number of failed creations
        - SuccessItems: Array of successfully imported ServiceGroup names
        - FailedItems: Array of PSCustomObjects with Name and Error details for failed items

        .EXAMPLE
        # Import service groups from CSV
        Import-SfosServiceGroups -FilePath "C:\Imports\ServiceGroups.csv"

        .EXAMPLE
        # Import from JSON with explicit connection
        $result = Import-SfosServiceGroups -FilePath "C:\Imports\ServiceGroups.json" -Format AsJSON -Firewall "192.168.1.1"
        $result | Format-Table

        .NOTES
        Minimum supported PowerShell version: 5.1
        This function depends on New-SfosServiceGroup to create the objects.
        Members in CSV files should be JSON arrays: ["Service1","Service2"]

        .LINK
        Export-SfosServiceGroups

        .LINK
        New-SfosServiceGroup
#>
function Import-SfosServiceGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [ValidateSet('AsCSV', 'AsJSON')]
        [ValidateNotNullOrEmpty()]
        [string]$Format = 'AsCSV',

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port = 4444,
        [SecureString]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    # Check if file exists
    if (-not (Test-Path -Path $FilePath)) {
        throw "File '' was not found."
    }

    # Resolve connection parameters
    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Import data from CSV or JSON
    try {
        if ($Format -eq 'AsCSV') {
            $serviceGroups = Import-Csv -Path $FilePath -Encoding UTF8
        }
        else {
            $serviceGroups = Get-Content -Path $FilePath -Raw | ConvertFrom-Json
        }
    }
    catch {
        throw "Error importing service groups from '': $($_.Exception.Message)"
    }

    # Ensure serviceGroups is an array
    if ($serviceGroups -isnot [array]) {
        $serviceGroups = @($serviceGroups)
    }

    # Track success and failures
    $successItems = @()
    $failedItems = @()

    # Create service groups on the Sophos Firewall
    foreach ($group in $serviceGroups) {
        try {
            # Parse member list from JSON string if present
            $members = @()
            if ($group.ServiceList) {
                try {
                    $members = $group.ServiceList | ConvertFrom-Json
                }
                catch {
                    # If JSON parsing fails, treat as empty
                    $members = @()
                }
            }

            New-SfosServiceGroup -Name $group.Name `
                -Description $group.Description `
                -Services $members `
                -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -SkipCertificateCheck:$params.SkipCertificateCheck
            
            $successItems += $group.Name
            Write-Information "Imported: $($group.Name)" -InformationAction Continue
        }
        catch {
            $failedItems += [PSCustomObject]@{
                Name  = $group.Name
                Error = $_.Exception.Message
            }
            Write-Information "Error importing '$($group.Name)': $($_.Exception.Message)" -InformationAction Continue
        }
    }

    # Return summary object
    return [PSCustomObject]@{
        Operation     = 'Import'
        ObjectType    = 'ServiceGroup'
        Total         = $serviceGroups.Count
        Success       = $successItems.Count
        Failed        = $failedItems.Count
        SuccessItems  = $successItems
        FailedItems   = $failedItems
    }
}

#endregion ServiceGroup

