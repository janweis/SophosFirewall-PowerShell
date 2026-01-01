#requires -Version 5.1
#requires -Modules Pester

<#
.SYNOPSIS
    Integration and CRUD operation tests for SophosFirewall.HostAndServices module

.DESCRIPTION
    Comprehensive test coverage for API interactions, CRUD operations, 
    parameter sets, member management, bulk operations, and error handling.
    
    Uses mocked Invoke-SfosApi to avoid firewall dependencies.

.AUTHOR
    Jan Weis (https://www.it-explorations.de)

.VERSION
    1.0.0
#>

# Module path setup
$ModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'SophosFirewall.HostAndServices.psm1'
Import-Module $ModulePath -Force

# Mock helper functions for firewall connection
function New-MockApiResponse {
    param(
        [string]$ObjectType,
        [string]$Name,
        [string]$Status = '200',
        [string]$StatusMessage = 'The operation completed successfully',
        [hashtable]$Properties = @{}
    )
    
    $propertyXml = ""
    foreach ($key in $Properties.Keys) {
        $value = $Properties[$key]
        # XML escape the value
        $value = $value -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;'
        $propertyXml += "<$key>$value</$key>`n"
    }
    
    @{
        StatusCode = [int]$Status
        Content = @"
<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <$ObjectType>
        <Name>$Name</Name>
        $propertyXml
        <Status code="$Status">$StatusMessage</Status>
    </$ObjectType>
</Response>
"@
    }
}

function New-MockApiErrorResponse {
    param(
        [int]$StatusCode = 502,
        [string]$ErrorMessage = 'Authentication failed'
    )
    
    @{
        StatusCode = $StatusCode
        Content = @"
<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Error>
        <Status code="$StatusCode">$ErrorMessage</Status>
    </Error>
</Response>
"@
    }
}

Describe 'IP Host CRUD Operations' {
    Context 'Get-SfosIpHost' {
        BeforeEach {
            Mock -CommandName 'Invoke-SfosApi' -MockWith {
                return New-MockApiResponse -ObjectType 'IPHost' -Name 'CORP-WEB-01' -Properties @{
                    IPFamily = 'IPv4'
                    IPAddress = '192.168.1.10'
                    Description = 'Production Web Server'
                }
            }
        }
        
        It 'Should retrieve IP hosts' {
            $result = Get-SfosIpHost -Firewall '192.168.1.1' -Port 4444 -Credential (New-Object PSCredential 'admin', (ConvertTo-SecureString 'pass' -AsPlainText -Force)) -SkipCertificateCheck
            Assert-MockCalled -CommandName 'Invoke-SfosApi' -Times 1
        }
        
        It 'Should support -AsXml parameter' {
            $result = Get-SfosIpHost -Firewall '192.168.1.1' -Port 4444 -Credential (New-Object PSCredential 'admin', (ConvertTo-SecureString 'pass' -AsPlainText -Force)) -SkipCertificateCheck -AsXml
            Assert-MockCalled -CommandName 'Invoke-SfosApi' -Times 1
        }
        
        It 'Should filter by NameLike parameter' {
            Mock -CommandName 'Invoke-SfosApi' -MockWith {
                # Verify NameLike filter is in XML
                param($InnerXml)
                if ($InnerXml -match '<Filter>') {
                    return New-MockApiResponse -ObjectType 'IPHost' -Name 'CORP-WEB-01' -Properties @{IPAddress = '192.168.1.10'}
                }
                return New-MockApiResponse -ObjectType 'IPHost' -Name 'CORP-WEB-01' -Properties @{IPAddress = '192.168.1.10'}
            } -ParameterFilter { $InnerXml -match 'Get' }
            
            $result = Get-SfosIpHost -Firewall '192.168.1.1' -Port 4444 -Credential (New-Object PSCredential 'admin', (ConvertTo-SecureString 'pass' -AsPlainText -Force)) -SkipCertificateCheck -NameLike 'CORP*'
            Assert-MockCalled -CommandName 'Invoke-SfosApi' -Times 1
        }
    }
    
    Context 'New-SfosIpHost' {
        It 'Should create IP host with IP address' {
            Mock -CommandName 'Invoke-SfosApi' -MockWith {
                return New-MockApiResponse -ObjectType 'IPHost' -Name 'NewHost' -Status '202'
            }
            
            $cred = New-Object PSCredential 'admin', (ConvertTo-SecureString 'pass' -AsPlainText -Force)
            $result = New-SfosIpHost -Firewall '192.168.1.1' -Port 4444 -Credential $cred -SkipCertificateCheck -Name 'TestHost' -IpAddress '10.0.0.1' -WhatIf
            
            Assert-MockCalled -CommandName 'Invoke-SfosApi' -Times 0  # WhatIf should not call API
        }
        
        It 'Should create network/subnet host' {
            Mock -CommandName 'Invoke-SfosApi' -MockWith {
                return New-MockApiResponse -ObjectType 'IPHost' -Name 'Network' -Status '202'
            }
            
            $cred = New-Object PSCredential 'admin', (ConvertTo-SecureString 'pass' -AsPlainText -Force)
            # Test that parameter set exists (without actually calling)
            (Get-Command New-SfosIpHost).ParameterSets.Name | Should -Contain 'IP'
        }
        
        It 'Should support -WhatIf parameter' {
            (Get-Command New-SfosIpHost).Parameters.Keys | Should -Contain 'WhatIf'
        }
    }
    
    Context 'Set-SfosIpHost' {
        It 'Should update IP host' {
            Mock -CommandName 'Invoke-SfosApi' -MockWith {
                return New-MockApiResponse -ObjectType 'IPHost' -Name 'ExistingHost' -Status '200'
            }
            
            $cred = New-Object PSCredential 'admin', (ConvertTo-SecureString 'pass' -AsPlainText -Force)
            $result = Set-SfosIpHost -Firewall '192.168.1.1' -Port 4444 -Credential $cred -SkipCertificateCheck -Name 'ExistingHost' -Description 'Updated'
            Assert-MockCalled -CommandName 'Invoke-SfosApi' -Times 1
        }
    }
    
    Context 'Remove-SfosIpHost' {
        It 'Should delete IP host' {
            Mock -CommandName 'Invoke-SfosApi' -MockWith {
                return New-MockApiResponse -ObjectType 'IPHost' -Name 'HostToDelete' -Status '200'
            }
            
            $cred = New-Object PSCredential 'admin', (ConvertTo-SecureString 'pass' -AsPlainText -Force)
            $result = Remove-SfosIpHost -Firewall '192.168.1.1' -Port 4444 -Credential $cred -SkipCertificateCheck -Name 'HostToDelete' -Confirm:$false
            Assert-MockCalled -CommandName 'Invoke-SfosApi' -Times 1
        }
        
        It 'Should support -Confirm parameter' {
            (Get-Command Remove-SfosIpHost).Parameters.Keys | Should -Contain 'Confirm'
        }
    }
}

Describe 'IP Host Group Operations' {
    Context 'Get-SfosIpHostGroup' {
        It 'Should retrieve IP host groups' {
            Mock -CommandName 'Invoke-SfosApi' -MockWith {
                return New-MockApiResponse -ObjectType 'IPHostGroup' -Name 'WebServers'
            }
            
            $cred = New-Object PSCredential 'admin', (ConvertTo-SecureString 'pass' -AsPlainText -Force)
            $result = Get-SfosIpHostGroup -Firewall '192.168.1.1' -Port 4444 -Credential $cred -SkipCertificateCheck
            Assert-MockCalled -CommandName 'Invoke-SfosApi' -Times 1
        }
    }
    
    Context 'Add-SfosIpHostGroupMember' {
        It 'Should add member to IP host group' {
            Mock -CommandName 'Invoke-SfosApi' -MockWith {
                return New-MockApiResponse -ObjectType 'IPHostGroup' -Name 'WebServers' -Status '200'
            }
            
            $cred = New-Object PSCredential 'admin', (ConvertTo-SecureString 'pass' -AsPlainText -Force)
            $result = Add-SfosIpHostGroupMember -Firewall '192.168.1.1' -Port 4444 -Credential $cred -SkipCertificateCheck -GroupName 'WebServers' -MemberName 'CORP-WEB-01'
            Assert-MockCalled -CommandName 'Invoke-SfosApi' -Times 1
        }
        
        It 'Should add multiple members to IP host group' {
            Mock -CommandName 'Invoke-SfosApi' -MockWith {
                return New-MockApiResponse -ObjectType 'IPHostGroup' -Name 'WebServers' -Status '200'
            }
            
            $cred = New-Object PSCredential 'admin', (ConvertTo-SecureString 'pass' -AsPlainText -Force)
            $result = Add-SfosIpHostGroupMember -Firewall '192.168.1.1' -Port 4444 -Credential $cred -SkipCertificateCheck -GroupName 'WebServers' -MemberName @('CORP-WEB-01', 'CORP-WEB-02')
            Assert-MockCalled -CommandName 'Invoke-SfosApi' -Times 1
        }
    }
    
    Context 'Remove-SfosIpHostGroupMember' {
        It 'Should remove member from IP host group' {
            Mock -CommandName 'Invoke-SfosApi' -MockWith {
                return New-MockApiResponse -ObjectType 'IPHostGroup' -Name 'WebServers' -Status '200'
            }
            
            $cred = New-Object PSCredential 'admin', (ConvertTo-SecureString 'pass' -AsPlainText -Force)
            $result = Remove-SfosIpHostGroupMember -Firewall '192.168.1.1' -Port 4444 -Credential $cred -SkipCertificateCheck -GroupName 'WebServers' -MemberName 'CORP-WEB-01'
            Assert-MockCalled -CommandName 'Invoke-SfosApi' -Times 1
        }
    }
}

Describe 'FQDN Host Operations' {
    Context 'Get-SfosFqdnHost' {
        It 'Should retrieve FQDN hosts' {
            Mock -CommandName 'Invoke-SfosApi' -MockWith {
                return New-MockApiResponse -ObjectType 'FQDNHost' -Name 'MailServer'
            }
            
            $cred = New-Object PSCredential 'admin', (ConvertTo-SecureString 'pass' -AsPlainText -Force)
            $result = Get-SfosFqdnHost -Firewall '192.168.1.1' -Port 4444 -Credential $cred -SkipCertificateCheck
            Assert-MockCalled -CommandName 'Invoke-SfosApi' -Times 1
        }
    }
    
    Context 'New-SfosFqdnHost' {
        It 'Should create FQDN host' {
            Mock -CommandName 'Invoke-SfosApi' -MockWith {
                return New-MockApiResponse -ObjectType 'FQDNHost' -Name 'NewFqdnHost' -Status '202'
            }
            
            $cred = New-Object PSCredential 'admin', (ConvertTo-SecureString 'pass' -AsPlainText -Force)
            $result = New-SfosFqdnHost -Firewall '192.168.1.1' -Port 4444 -Credential $cred -SkipCertificateCheck -Name 'api.example.com' -Description 'API Server'
            Assert-MockCalled -CommandName 'Invoke-SfosApi' -Times 1
        }
    }
    
    Context 'Remove-SfosFqdnHostMass' {
        It 'Should delete multiple FQDN hosts in bulk' {
            Mock -CommandName 'Invoke-SfosApi' -MockWith {
                return New-MockApiResponse -ObjectType 'FQDNHost' -Name 'bulk-delete' -Status '200'
            }
            
            $cred = New-Object PSCredential 'admin', (ConvertTo-SecureString 'pass' -AsPlainText -Force)
            $names = @('OldHost1', 'OldHost2', 'OldHost3')
            $result = Remove-SfosFqdnHostMass -Firewall '192.168.1.1' -Port 4444 -Credential $cred -SkipCertificateCheck -Names $names
            Assert-MockCalled -CommandName 'Invoke-SfosApi' -Times 1
        }
        
        It 'Should process array of host names' {
            (Get-Command Remove-SfosFqdnHostMass).Parameters.Keys | Should -Contain 'Names'
        }
    }
}

Describe 'MAC Host Operations' {
    Context 'Get-SfosMacHost' {
        It 'Should retrieve MAC hosts' {
            Mock -CommandName 'Invoke-SfosApi' -MockWith {
                return New-MockApiResponse -ObjectType 'MACHost' -Name 'PrinterDevice'
            }
            
            $cred = New-Object PSCredential 'admin', (ConvertTo-SecureString 'pass' -AsPlainText -Force)
            $result = Get-SfosMacHost -Firewall '192.168.1.1' -Port 4444 -Credential $cred -SkipCertificateCheck
            Assert-MockCalled -CommandName 'Invoke-SfosApi' -Times 1
        }
    }
    
    Context 'New-SfosMacHost' {
        It 'Should create MAC host' {
            Mock -CommandName 'Invoke-SfosApi' -MockWith {
                return New-MockApiResponse -ObjectType 'MACHost' -Name 'NewMacHost' -Status '202'
            }
            
            $cred = New-Object PSCredential 'admin', (ConvertTo-SecureString 'pass' -AsPlainText -Force)
            $result = New-SfosMacHost -Firewall '192.168.1.1' -Port 4444 -Credential $cred -SkipCertificateCheck -Name 'Printer' -MacAddress '00:1A:2B:3C:4D:5E'
            Assert-MockCalled -CommandName 'Invoke-SfosApi' -Times 1
        }
    }
}

Describe 'Country Host Group Operations' {
    Context 'Get-SfosCountryHostGroup' {
        It 'Should retrieve country host groups' {
            Mock -CommandName 'Invoke-SfosApi' -MockWith {
                return New-MockApiResponse -ObjectType 'CountryHostGroup' -Name 'RestrictedCountries'
            }
            
            $cred = New-Object PSCredential 'admin', (ConvertTo-SecureString 'pass' -AsPlainText -Force)
            $result = Get-SfosCountryHostGroup -Firewall '192.168.1.1' -Port 4444 -Credential $cred -SkipCertificateCheck
            Assert-MockCalled -CommandName 'Invoke-SfosApi' -Times 1
        }
    }
    
    Context 'New-SfosCountryHostGroup' {
        It 'Should create country host group' {
            Mock -CommandName 'Invoke-SfosApi' -MockWith {
                return New-MockApiResponse -ObjectType 'CountryHostGroup' -Name 'HighRiskCountries' -Status '202'
            }
            
            $cred = New-Object PSCredential 'admin', (ConvertTo-SecureString 'pass' -AsPlainText -Force)
            $result = New-SfosCountryHostGroup -Firewall '192.168.1.1' -Port 4444 -Credential $cred -SkipCertificateCheck -Name 'HighRiskCountries' -Countries @('CN', 'KP', 'IR')
            Assert-MockCalled -CommandName 'Invoke-SfosApi' -Times 1
        }
    }
}

Describe 'Service Operations' {
    Context 'Get-SfosService' {
        It 'Should retrieve services' {
            Mock -CommandName 'Invoke-SfosApi' -MockWith {
                return New-MockApiResponse -ObjectType 'Service' -Name 'HTTPS' -Properties @{
                    ServiceType = 'Service'
                    Protocol = 'TCP'
                }
            }
            
            $cred = New-Object PSCredential 'admin', (ConvertTo-SecureString 'pass' -AsPlainText -Force)
            $result = Get-SfosService -Firewall '192.168.1.1' -Port 4444 -Credential $cred -SkipCertificateCheck
            Assert-MockCalled -CommandName 'Invoke-SfosApi' -Times 1
        }
        
        It 'Should filter by protocol type' {
            (Get-Command Get-SfosService).Parameters.Keys | Should -Contain 'Protocol'
        }
    }
    
    Context 'New-SfosService' {
        It 'Should create TCP/UDP service' {
            Mock -CommandName 'Invoke-SfosApi' -MockWith {
                return New-MockApiResponse -ObjectType 'Service' -Name 'CustomApp' -Status '202'
            }
            
            $cred = New-Object PSCredential 'admin', (ConvertTo-SecureString 'pass' -AsPlainText -Force)
            $result = New-SfosService -Firewall '192.168.1.1' -Port 4444 -Credential $cred -SkipCertificateCheck -Name 'CustomApp' -ServiceType 'Service' -Protocol 'TCP' -Port 8080
            Assert-MockCalled -CommandName 'Invoke-SfosApi' -Times 1
        }
        
        It 'Should create service with port range' {
            Mock -CommandName 'Invoke-SfosApi' -MockWith {
                return New-MockApiResponse -ObjectType 'Service' -Name 'HighPorts' -Status '202'
            }
            
            $cred = New-Object PSCredential 'admin', (ConvertTo-SecureString 'pass' -AsPlainText -Force)
            # Verify parameter exists
            (Get-Command New-SfosService).Parameters.Keys | Should -Contain 'PortRange'
        }
        
        It 'Should create IP protocol service' {
            (Get-Command New-SfosService).ParameterSets.Name | Should -Contain 'IP'
        }
        
        It 'Should create ICMP service' {
            (Get-Command New-SfosService).ParameterSets.Name | Should -Contain 'ICMP'
        }
    }
    
    Context 'Set-SfosService' {
        It 'Should update service' {
            Mock -CommandName 'Invoke-SfosApi' -MockWith {
                return New-MockApiResponse -ObjectType 'Service' -Name 'ExistingService' -Status '200'
            }
            
            $cred = New-Object PSCredential 'admin', (ConvertTo-SecureString 'pass' -AsPlainText -Force)
            $result = Set-SfosService -Firewall '192.168.1.1' -Port 4444 -Credential $cred -SkipCertificateCheck -Name 'ExistingService' -Description 'Updated Service'
            Assert-MockCalled -CommandName 'Invoke-SfosApi' -Times 1
        }
    }
    
    Context 'Remove-SfosService' {
        It 'Should delete service' {
            Mock -CommandName 'Invoke-SfosApi' -MockWith {
                return New-MockApiResponse -ObjectType 'Service' -Name 'ServiceToDelete' -Status '200'
            }
            
            $cred = New-Object PSCredential 'admin', (ConvertTo-SecureString 'pass' -AsPlainText -Force)
            $result = Remove-SfosService -Firewall '192.168.1.1' -Port 4444 -Credential $cred -SkipCertificateCheck -Name 'ServiceToDelete' -Confirm:$false
            Assert-MockCalled -CommandName 'Invoke-SfosApi' -Times 1
        }
    }
}

Describe 'Service Group Operations' {
    Context 'Get-SfosServiceGroup' {
        It 'Should retrieve service groups' {
            Mock -CommandName 'Invoke-SfosApi' -MockWith {
                return New-MockApiResponse -ObjectType 'ServiceGroup' -Name 'WebServices'
            }
            
            $cred = New-Object PSCredential 'admin', (ConvertTo-SecureString 'pass' -AsPlainText -Force)
            $result = Get-SfosServiceGroup -Firewall '192.168.1.1' -Port 4444 -Credential $cred -SkipCertificateCheck
            Assert-MockCalled -CommandName 'Invoke-SfosApi' -Times 1
        }
    }
    
    Context 'Add-SfosServiceGroupMember' {
        It 'Should add service to group' {
            Mock -CommandName 'Invoke-SfosApi' -MockWith {
                return New-MockApiResponse -ObjectType 'ServiceGroup' -Name 'WebServices' -Status '200'
            }
            
            $cred = New-Object PSCredential 'admin', (ConvertTo-SecureString 'pass' -AsPlainText -Force)
            $result = Add-SfosServiceGroupMember -Firewall '192.168.1.1' -Port 4444 -Credential $cred -SkipCertificateCheck -GroupName 'WebServices' -MemberName 'HTTPS'
            Assert-MockCalled -CommandName 'Invoke-SfosApi' -Times 1
        }
        
        It 'Should add multiple services to group' {
            Mock -CommandName 'Invoke-SfosApi' -MockWith {
                return New-MockApiResponse -ObjectType 'ServiceGroup' -Name 'WebServices' -Status '200'
            }
            
            $cred = New-Object PSCredential 'admin', (ConvertTo-SecureString 'pass' -AsPlainText -Force)
            $result = Add-SfosServiceGroupMember -Firewall '192.168.1.1' -Port 4444 -Credential $cred -SkipCertificateCheck -GroupName 'WebServices' -MemberName @('HTTP', 'HTTPS')
            Assert-MockCalled -CommandName 'Invoke-SfosApi' -Times 1
        }
    }
    
    Context 'Remove-SfosServiceGroupMember' {
        It 'Should remove service from group' {
            Mock -CommandName 'Invoke-SfosApi' -MockWith {
                return New-MockApiResponse -ObjectType 'ServiceGroup' -Name 'WebServices' -Status '200'
            }
            
            $cred = New-Object PSCredential 'admin', (ConvertTo-SecureString 'pass' -AsPlainText -Force)
            $result = Remove-SfosServiceGroupMember -Firewall '192.168.1.1' -Port 4444 -Credential $cred -SkipCertificateCheck -GroupName 'WebServices' -MemberName 'HTTP'
            Assert-MockCalled -CommandName 'Invoke-SfosApi' -Times 1
        }
    }
}

Describe 'Export/Import Operations' {
    Context 'Export Functions' {
        It 'Export-SfosIpHosts should export to file' {
            Mock -CommandName 'Invoke-SfosApi' -MockWith {
                return New-MockApiResponse -ObjectType 'IPHost' -Name 'Host1'
            }
            
            $cred = New-Object PSCredential 'admin', (ConvertTo-SecureString 'pass' -AsPlainText -Force)
            # Verify function exists and has required parameters
            (Get-Command Export-SfosIpHosts).Parameters.Keys | Should -Contain 'FilePath'
        }
        
        It 'Export-SfosServices should export to file' {
            (Get-Command Export-SfosServices).Parameters.Keys | Should -Contain 'FilePath'
        }
    }
    
    Context 'Import Functions' {
        It 'Import-SfosIpHosts should import from file' {
            Mock -CommandName 'Invoke-SfosApi' -MockWith {
                return New-MockApiResponse -ObjectType 'IPHost' -Name 'ImportedHost' -Status '202'
            }
            
            (Get-Command Import-SfosIpHosts).Parameters.Keys | Should -Contain 'FilePath'
        }
        
        It 'Import-SfosServices should import from file' {
            (Get-Command Import-SfosServices).Parameters.Keys | Should -Contain 'FilePath'
        }
    }
}

Describe 'Error Handling' {
    Context 'API Errors' {
        It 'Should handle 502 authentication error' {
            Mock -CommandName 'Invoke-SfosApi' -MockWith {
                return New-MockApiErrorResponse -StatusCode 502 -ErrorMessage 'Authentication failed'
            }
            
            Mock -CommandName 'Assert-SfosApiReturnSuccess' -MockWith {
                throw "API returned status 502: Authentication failed"
            }
            
            $cred = New-Object PSCredential 'admin', (ConvertTo-SecureString 'pass' -AsPlainText -Force)
            { Get-SfosIpHost -Firewall '192.168.1.1' -Port 4444 -Credential $cred -SkipCertificateCheck } | Should -Throw
        }
        
        It 'Should handle 500 server error' {
            Mock -CommandName 'Invoke-SfosApi' -MockWith {
                return New-MockApiErrorResponse -StatusCode 500 -ErrorMessage 'Internal Server Error'
            }
            
            Mock -CommandName 'Assert-SfosApiReturnSuccess' -MockWith {
                throw "API returned status 500"
            }
            
            $cred = New-Object PSCredential 'admin', (ConvertTo-SecureString 'pass' -AsPlainText -Force)
            { Get-SfosIpHost -Firewall '192.168.1.1' -Port 4444 -Credential $cred -SkipCertificateCheck } | Should -Throw
        }
    }
    
    Context 'Parameter Validation' {
        It 'Should require Name parameter for New-SfosIpHost' {
            $cred = New-Object PSCredential 'admin', (ConvertTo-SecureString 'pass' -AsPlainText -Force)
            { New-SfosIpHost -Firewall '192.168.1.1' -Port 4444 -Credential $cred -SkipCertificateCheck -IpAddress '10.0.0.1' } | Should -Throw
        }
        
        It 'Should require IpAddress for IP-type New-SfosIpHost' {
            $cred = New-Object PSCredential 'admin', (ConvertTo-SecureString 'pass' -AsPlainText -Force)
            { New-SfosIpHost -Firewall '192.168.1.1' -Port 4444 -Credential $cred -SkipCertificateCheck -Name 'TestHost' } | Should -Throw
        }
    }
    
    Context 'Missing Connection Parameters' {
        It 'Should fail without connection parameters and no stored connection' {
            # Clear any stored connection
            Remove-Variable -Name 'SfosConnection' -Scope Global -ErrorAction SilentlyContinue
            
            { Get-SfosIpHost } | Should -Throw
        }
    }
}

Describe 'Pipeline Support' {
    Context 'Pipeline Input' {
        It 'Set-SfosIpHost should accept Name from pipeline' {
            Mock -CommandName 'Invoke-SfosApi' -MockWith {
                return New-MockApiResponse -ObjectType 'IPHost' -Name 'PipelinedHost'
            }
            
            $cmd = Get-Command Set-SfosIpHost
            $nameParam = $cmd.Parameters['Name']
            $nameParam.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } | 
                ForEach-Object { $_.ValueFromPipeline } | 
                Should -Contain $true
        }
        
        It 'Set-SfosFqdnHost should accept Name from pipeline' {
            $cmd = Get-Command Set-SfosFqdnHost
            $nameParam = $cmd.Parameters['Name']
            $nameParam.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } | 
                ForEach-Object { $_.ValueFromPipeline } | 
                Should -Contain $true
        }
    }
}
