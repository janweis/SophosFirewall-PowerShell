#requires -Version 5.1
<#
.SYNOPSIS
    Core helper functions for Sophos Firewall API modules.

.DESCRIPTION
    Provides shared functionality for all Sophos Firewall PowerShell modules including:
    - Session management (Connect/Disconnect)
    - API communication (Invoke-SfosApi)
    - Response parsing and validation
    - XML escaping for security
    - Parameter resolution from session context

.NOTES
    Module Name: SophosFirewall.Core
    Author: Jan Weis
    Homepage: https://www.it-explorations.de
    Version: 1.0.0
    PowerShell Version: 5.1+
    
.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>

#region Module Variables

# Default Sophos Firewall API port
[int]$script:DefaultSfosPort = 4444

# Session context for connection reuse across cmdlets
$script:SfosConnection = $null

#endregion

#region XML Helper Functions

<#
.SYNOPSIS
    Escapes XML special characters in text strings.

.DESCRIPTION
    Converts special characters to XML-safe entities to prevent injection attacks
    and ensure proper XML formatting.

.PARAMETER Text
    The text string to escape.

.OUTPUTS
    System.String. The XML-escaped string.

.EXAMPLE
    ConvertTo-SfosXmlEscaped -Text "Company & Co <test>"
    Returns: "Company &amp; Co &lt;test&gt;"
#>
function ConvertTo-SfosXmlEscaped {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowEmptyString()]
        [string]$Text
    )
    
    process {
        return ($Text `
            -replace '&', '&amp;' `
            -replace '<', '&lt;' `
            -replace '>', '&gt;' `
            -replace '"', '&quot;' `
            -replace "'", '&apos;')
    }
}

<#
.SYNOPSIS
    Invokes a Sophos Firewall API request.
.DESCRIPTION
    Sends an XML request to the Sophos Firewall API endpoint and returns the response.
.PARAMETER Firewall
    The Sophos Firewall hostname or IP address.
.PARAMETER Port
    The management/API port number (default: 4444).
.PARAMETER Username
    The username for authentication (protected via XML-escaping).
.PARAMETER Password
    The password for authentication (as SecureString for security).
.PARAMETER InnerXml
    The inner XML content of the API request.
.PARAMETER SkipCertificateCheck
    Skips SSL certificate validation for self-signed certificates.
.OUTPUTS
    The response from the API as a WebResponseObject.
.EXAMPLE
    Invoke-SfosApi -Firewall "firewall.example.com" -Port 4444 -Username (ConvertTo-SecureString "admin" -AsPlainText -Force) -Password (ConvertTo-SecureString "password" -AsPlainText -Force) -InnerXml "<SomeRequest>Data</SomeRequest>" -SkipCertificateCheck
#>
function Invoke-SfosApi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Firewall,
        
        [int]$Port = $script:DefaultSfosPort,
        
        [Parameter(Mandatory)]
        [string]$Username,
        
        [Parameter(Mandatory)]
        [SecureString]$Password,
        
        [Parameter(Mandatory)]
        [string]$InnerXml,
        
        [switch]$SkipCertificateCheck
    )
    
    # Variables for secure handling and cleanup
    $plainPassword = $null
    $passwordBstr = $null
    $savedCertCallback = $null
    
    try {
        # Security: XML-escape credentials to prevent injection attacks
        $usernameEscaped = ConvertTo-SfosXmlEscaped -Text $Username
        
        # Convert Password SecureString to plaintext with BSTR cleanup
        $passwordBstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto($passwordBstr)
        $passwordEscaped = ConvertTo-SfosXmlEscaped -Text $plainPassword
        
        $uri = ("https://{0}:{1}/webconsole/APIController" -f $Firewall, $Port)
        $body = "reqxml=<Request><Login><Username>$usernameEscaped</Username><Password>$passwordEscaped</Password></Login>$InnerXml</Request>"
        
        $invokeParams = @{
            Uri         = $uri
            Method      = 'Post'
            Body        = $body
            ErrorAction = 'Stop'
        }
        
        # Handle certificate validation for PS 5.1 vs PS 7+
        if ($SkipCertificateCheck) {
            if ($PSVersionTable.PSVersion.Major -le 5) {
                # Save current callback before modifying global state
                $savedCertCallback = [Net.ServicePointManager]::ServerCertificateValidationCallback
                [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            } else {
                # PS 7+: Use parameter instead of global callback
                return Invoke-WebRequest @invokeParams -SkipCertificateCheck
            }
        }
        
        return Invoke-WebRequest @invokeParams
    } finally {
        # Restore previous certificate validation callback
        if ($null -ne $savedCertCallback) {
            [Net.ServicePointManager]::ServerCertificateValidationCallback = $savedCertCallback
        }
        
        # Free BSTR memory to prevent leaks
        if ($passwordBstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::FreeBSTR($passwordBstr)
        }
        
        # Clear plaintext variables from memory
        $plainPassword = $null
    }
}

#endregion

#region Response Parsing

<#
.SYNOPSIS
    Extracts status information from API XML response.

.DESCRIPTION
    Parses the XML response to find status codes and messages.
    Looks in /Response/ObjectName/Status or /Response/Status.

.PARAMETER Xml
    The XML response from the API.

.PARAMETER ObjectName
    Optional object name to search for specific status node.

.OUTPUTS
    PSCustomObject with Code, Message, and XPathHint properties.

.EXAMPLE
    Get-SfosApiStatus -Xml $response -ObjectName "Zone"
#>
function Get-SfosApiStatus {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [xml]$Xml,
        
        [string]$ObjectName
    )
    
    $statusNode = $null
    $hint = $null
    
    if ($ObjectName -and $Xml.Response.$ObjectName -and ($Xml.Response.$ObjectName.Status -notlike '')) {
        $statusNode = $Xml.Response.$ObjectName.Status
        $hint = "/Response/$ObjectName/Status"
    } elseif ($Xml.Response -and $Xml.Response.Status) {
        $statusNode = $Xml.Response.Status
        $hint = '/Response/Status'
    }
    
    if (-not $statusNode) {
        return $null
    }
    
    return [PSCustomObject]@{
        Code      = [string]$statusNode.code
        Message   = [string]$statusNode.'#text'
        XPathHint = $hint
    }
}

<#
.SYNOPSIS
    Validates that an API response indicates success.

.DESCRIPTION
    Checks the status code in the XML response and throws an error if not successful.
    Success codes are 200 (OK) and 202 (Accepted).

.PARAMETER Xml
    The XML response from the API.

.PARAMETER ObjectName
    Optional object name for status lookup.

.PARAMETER Action
    Description of the action being performed (for error messages).

.PARAMETER Target
    Target object name (for error messages).

.EXAMPLE
    Assert-SfosApiReturnSuccess -Xml $response -ObjectName "Zone" -Action "Create" -Target "DMZ"
#>
function Assert-SfosApiReturnSuccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [xml]$Xml,
        
        [string]$ObjectName,
        
        [string]$Action,
        
        [string]$Target
    )
    
    $status = Get-SfosApiStatus -Xml $Xml -ObjectName $ObjectName
    if (-not $status) {
        return
    }
    
    $actionPart = if ($Action) { $Action } else { 'execute request' }
    $targetPart = if ($Target) { " for '$Target'" } else { '' }
    
    if ($status.Code -ne '200' -and $status.Code -ne '202') {
        throw "Sophos API error while trying to $actionPart$targetPart. Code $($status.Code) - $($status.Message) (StatusPath=$($status.XPathHint))"
    }
}

#endregion

#region Session Management

<#
.SYNOPSIS
    Resolves connection parameters from session context or explicit values.

.DESCRIPTION
    Looks up connection parameters from the module session variable if not explicitly provided.
    Ensures all required parameters are available for API calls.

.PARAMETER BoundParameters
    Hashtable of bound parameters from calling cmdlet.

.OUTPUTS
    Hashtable with resolved Firewall, Port, Username, Password, and SkipCertificateCheck.

.EXAMPLE
    $resolved = Resolve-SfosParameters -BoundParameters $PSBoundParameters
#>
function Resolve-SfosParameters {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$BoundParameters
    )
    
    $resolved = @{
        Firewall             = $BoundParameters.Firewall
        Port                 = $BoundParameters.Port
        Username             = $BoundParameters.Username
        Password             = $BoundParameters.Password
        SkipCertificateCheck = $BoundParameters.SkipCertificateCheck
    }
    
    if ($script:SfosConnection) {
        if (-not $resolved.Firewall) {
            $resolved.Firewall = $script:SfosConnection.Firewall
        }
        if (-not $resolved.Port) {
            $resolved.Port = $script:SfosConnection.Port
        }
        if (-not $resolved.Username) {
            $resolved.Username = $script:SfosConnection.Username
        }
        if (-not $resolved.Password) {
            $resolved.Password = $script:SfosConnection.Password
        }
        if (-not $resolved.SkipCertificateCheck) {
            $resolved.SkipCertificateCheck = $script:SfosConnection.SkipCertificateCheck
        }
    }
    
    if (-not $resolved.Firewall -or -not $resolved.Username -or -not $resolved.Password) {
        throw 'No active Sophos Firewall connection found. Use Connect-SfosFirewall to establish a connection or provide Firewall, Username, and Password explicitly.'
    }
    
    if (-not $resolved.Port) {
        $resolved.Port = $script:DefaultSfosPort
    }
    
    return $resolved
}

<#
.SYNOPSIS
    Establishes a connection to a Sophos Firewall.

.DESCRIPTION
    Stores connection details in the module session variable for reuse by other cmdlets.
    Credentials are stored as SecureString for security.

.PARAMETER Firewall
    Sophos Firewall hostname or IP address.

.PARAMETER Port
    Management/API port number (default: 4444).

.PARAMETER Credential
    PSCredential object containing username and password.

.PARAMETER SkipCertificateCheck
    Skips SSL certificate validation for self-signed certificates.

.OUTPUTS
    PSCustomObject with connection details.

.EXAMPLE
    $cred = Get-Credential -Message "Sophos Firewall Admin"
    Connect-SfosFirewall -Firewall "192.168.1.1" -Port 4444 -Credential $cred -SkipCertificateCheck
#>
function Connect-SfosFirewall {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Firewall,
        
        [ValidateRange(1, 65535)]
        [int]$Port = $script:DefaultSfosPort,
        
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [pscredential]$Credential,
        
        [switch]$SkipCertificateCheck
    )
    
    $script:SfosConnection = [PSCustomObject]@{
        Firewall             = $Firewall
        Port                 = $Port
        Username             = $Credential.UserName
        Password             = $Credential.Password
        SkipCertificateCheck = [bool]$SkipCertificateCheck
    }
    
    Write-Verbose "Connected to Sophos Firewall at $Firewall`:$Port as $($Credential.UserName)"
    return $script:SfosConnection
}

<#
.SYNOPSIS
    Disconnects from the Sophos Firewall.

.DESCRIPTION
    Clears the module session variable, removing stored credentials.

.EXAMPLE
    Disconnect-SfosFirewall
#>
function Disconnect-SfosFirewall {
    [CmdletBinding()]
    param()
    
    if ($script:SfosConnection) {
        Write-Verbose "Disconnected from Sophos Firewall at $($script:SfosConnection.Firewall)"
        $script:SfosConnection = $null
    }
}

#endregion

#region Module Exports

Export-ModuleMember -Function @(
    'Connect-SfosFirewall',
    'Disconnect-SfosFirewall',
    'Invoke-SfosApi',
    'Get-SfosApiStatus',
    'Assert-SfosApiReturnSuccess',
    'Resolve-SfosParameters',
    'ConvertTo-SfosXmlEscaped'
)

#endregion
