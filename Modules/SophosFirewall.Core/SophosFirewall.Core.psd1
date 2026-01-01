@{
    RootModule        = 'SophosFirewall.Core.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'e480ca2a-0d74-4153-b3f1-a0aaf11dc2e8'
    Author            = 'Jan Weis'
    CompanyName       = 'RAWE-IT GbR'
    Copyright         = '(c) 2025 RAWE-IT GbR. All rights reserved.'
    Description       = 'Core helper functions for Sophos Firewall API modules. Provides session management, API communication, XML escaping, and response validation.'
    PowerShellVersion = '5.1'
    
    FunctionsToExport = @(
        'Connect-SfosFirewall',
        'Disconnect-SfosFirewall',
        'Invoke-SfosApi',
        'Get-SfosApiStatus',
        'Assert-SfosApiReturnSuccess',
        'Resolve-SfosParameters',
        'ConvertTo-SfosXmlEscaped'
    )
    
    CmdletsToExport   = @()
    VariablesToExport = @('SfosConnection')
    AliasesToExport   = @()
    
    PrivateData       = @{
        PSData = @{
            Tags         = @('Sophos', 'Firewall', 'XGS', 'SFOS', 'API', 'Core', 'Helper')
            LicenseUri   = ''
            ProjectUri   = ''
            ReleaseNotes = @'
Version 1.0.0 (2025-12-31)
- Initial release
- Centralized helper functions for all Sophos Firewall modules
- Session management with Connect/Disconnect-SfosFirewall
- API communication via Invoke-SfosApi
- XML escaping for security
- Response parsing and validation
- Parameter resolution from session context
- PowerShell 5.1 and 7+ compatibility
'@
        }
    }
}
