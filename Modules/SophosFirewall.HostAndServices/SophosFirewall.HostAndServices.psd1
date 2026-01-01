@{
    RootModule           = 'SophosFirewall.HostAndServices.psm1'
    ModuleVersion        = '1.0.0'
    GUID                 = '1c2a45f5-8215-4035-a691-2be3ef0e8191'
    Author               = 'Jan Weis'
    Description          = 'PowerShell module for managing Sophos XGS / SFOS 21.x firewall hosts and services via API.'

    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    RequiredModules      = @(
        @{
            ModuleName    = 'SophosFirewall.Core'
            ModuleVersion = '1.0.0'
        }
    )

    FunctionsToExport    = @(
        'Get-SfosIpHost',
        'New-SfosIpHost',
        'Set-SfosIpHost',
        'Remove-SfosIpHost',
        'Export-SfosIpHosts',
        'Import-SfosIpHosts',
        'Get-SfosIpHostGroup',
        'New-SfosIpHostGroup',
        'Set-SfosIpHostGroup',
        'Remove-SfosIpHostGroup',
        'Add-SfosIpHostGroupMember',
        'Remove-SfosIpHostGroupMember',
        'Export-SfosIpHostGroups',
        'Import-SfosIpHostGroups',
        'Get-SfosFqdnHost',
        'New-SfosFqdnHost',
        'Set-SfosFqdnHost',
        'Remove-SfosFqdnHost',
        'Remove-SfosFqdnHostMass',
        'Export-SfosFqdnHosts',
        'Import-SfosFqdnHosts',
        'Get-SfosFqdnHostGroup',
        'New-SfosFqdnHostGroup',
        'Set-SfosFqdnHostGroup',
        'Remove-SfosFqdnHostGroup',
        'Add-SfosFqdnHostGroupMember',
        'Remove-SfosFqdnHostGroupMember',
        'Export-SfosFqdnHostGroups',
        'Import-SfosFqdnHostGroups',
        'Get-SfosMacHost',
        'New-SfosMacHost',
        'Set-SfosMacHost',
        'Remove-SfosMacHost',
        'Export-SfosMacHosts',
        'Import-SfosMacHosts',
        'Get-SfosCountryHostGroup',
        'New-SfosCountryHostGroup',
        'Set-SfosCountryHostGroup',
        'Remove-SfosCountryHostGroup',
        'Get-SfosService',
        'New-SfosService',
        'Set-SfosService',
        'Remove-SfosService',
        'Export-SfosServices',
        'Import-SfosServices',
        'Get-SfosServiceGroup',
        'New-SfosServiceGroup',
        'Set-SfosServiceGroup',
        'Remove-SfosServiceGroup',
        'Add-SfosServiceGroupMember',
        'Remove-SfosServiceGroupMember',
        'Export-SfosServiceGroups',
        'Import-SfosServiceGroups'
    )

    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()

    PrivateData          = @{
        PSData = @{
            Tags         = @('Sophos', 'Firewall', 'API', 'XGS', 'SFOS', 'Network', 'Security')
            LicenseUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/blob/main/Modules/SophosFirewall.HostAndServices/LICENSE'
            ProjectUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/tree/main/Modules/SophosFirewall.HostAndServices'
            ReleaseNotes = 'Initial release of HostAndServices module for Sophos Firewall API management.'
        }
    }
}
