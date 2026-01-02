#requires -Version 5.1
#requires -Modules Pester

<#
.SYNOPSIS
    Unit tests for SophosFirewall.HostAndServices module

.DESCRIPTION
    Tests for cmdlet functionality, parameter validation, and structure.
    Integration tests (actual API calls) are skipped.
#>

param(
    [switch]$SkipIntegration
)

$ErrorActionPreference = 'Stop'

# Get module path - use relative paths that work in any environment
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$ModulePath = Join-Path $ProjectRoot "Modules\SophosFirewall.HostAndServices\SophosFirewall.HostAndServices.psd1"
$CoreModulePath = Join-Path $ProjectRoot "Modules\SophosFirewall.Core\SophosFirewall.Core.psd1"

if (-not (Test-Path $ModulePath)) {
    Write-Error "Module manifest not found: $ModulePath"
    exit 1
}

# Import modules
Import-Module $CoreModulePath -Force
Import-Module $ModulePath -Force

Describe 'Module Loading' {
    It 'SophosFirewall.HostAndServices module should load' {
        Get-Module SophosFirewall.HostAndServices | Should -Not -BeNullOrEmpty
    }
    
    It 'SophosFirewall.Core dependency should load' {
        Get-Module SophosFirewall.Core | Should -Not -BeNullOrEmpty
    }
}

Describe 'IP Host Functions' {
    It 'Get-SfosIpHost function should exist' {
        Get-Command Get-SfosIpHost | Should -Not -BeNullOrEmpty
    }
    
    It 'New-SfosIpHost function should exist' {
        Get-Command New-SfosIpHost | Should -Not -BeNullOrEmpty
    }
    
    It 'Set-SfosIpHost function should exist' {
        Get-Command Set-SfosIpHost | Should -Not -BeNullOrEmpty
    }
    
    It 'Remove-SfosIpHost function should exist' {
        Get-Command Remove-SfosIpHost | Should -Not -BeNullOrEmpty
    }
    
    Context 'Get-SfosIpHost Parameters' {
        It 'Should have NameLike parameter' {
            (Get-Command Get-SfosIpHost).Parameters.Keys | Should -Contain 'NameLike'
        }
        
        It 'Should have Firewall parameter' {
            (Get-Command Get-SfosIpHost).Parameters.Keys | Should -Contain 'Firewall'
        }
        
        It 'Should have Port parameter' {
            (Get-Command Get-SfosIpHost).Parameters.Keys | Should -Contain 'Port'
        }
    }
    
    Context 'New-SfosIpHost Parameters' {
        It 'Should have Name parameter' {
            (Get-Command New-SfosIpHost).Parameters.Keys | Should -Contain 'Name'
        }
        
        It 'Should have HostType parameter' {
            (Get-Command New-SfosIpHost).Parameters.Keys | Should -Contain 'HostType'
        }
        
        It 'Should support IP parameter set' {
            (Get-Command New-SfosIpHost).ParameterSets.Name | Should -Contain 'IP'
        }
        
        It 'HostType should have valid ValidateSet values' {
            $hostTypeParam = (Get-Command New-SfosIpHost).Parameters['HostType']
            $hostTypeParam.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } | 
                ForEach-Object { $_.ValidValues } | Should -Contain 'IP'
        }
    }
    
    Context 'Set-SfosIpHost Parameters' {
        It 'Should have Name parameter' {
            (Get-Command Set-SfosIpHost).Parameters.Keys | Should -Contain 'Name'
        }
        
        It 'Should have Description parameter' {
            (Get-Command Set-SfosIpHost).Parameters.Keys | Should -Contain 'Description'
        }
    }
}

Describe 'IP Host Group Functions' {
    It 'Get-SfosIpHostGroup function should exist' {
        Get-Command Get-SfosIpHostGroup | Should -Not -BeNullOrEmpty
    }
    
    It 'Add-SfosIpHostGroupMember function should exist' {
        Get-Command Add-SfosIpHostGroupMember | Should -Not -BeNullOrEmpty
    }
    
    It 'Remove-SfosIpHostGroupMember function should exist' {
        Get-Command Remove-SfosIpHostGroupMember | Should -Not -BeNullOrEmpty
    }
    
    Context 'Add-SfosIpHostGroupMember Parameters' {
        It 'Should have Name parameter (for group name)' {
            (Get-Command Add-SfosIpHostGroupMember).Parameters.Keys | Should -Contain 'Name'
        }
        
        It 'Should have members parameter' {
            (Get-Command Add-SfosIpHostGroupMember).Parameters.Keys | Should -Contain 'members'
        }
    }
    
    Context 'Remove-SfosIpHostGroupMember Parameters' {
        It 'Should have Name parameter (for group name)' {
            (Get-Command Remove-SfosIpHostGroupMember).Parameters.Keys | Should -Contain 'Name'
        }
        
        It 'Should have members parameter' {
            (Get-Command Remove-SfosIpHostGroupMember).Parameters.Keys | Should -Contain 'members'
        }
    }
}

Describe 'FQDN Host Functions' {
    It 'Get-SfosFqdnHost function should exist' {
        Get-Command Get-SfosFqdnHost | Should -Not -BeNullOrEmpty
    }
    
    It 'New-SfosFqdnHost function should exist' {
        Get-Command New-SfosFqdnHost | Should -Not -BeNullOrEmpty
    }
    
    It 'Set-SfosFqdnHost function should exist' {
        Get-Command Set-SfosFqdnHost | Should -Not -BeNullOrEmpty
    }
}

Describe 'MAC Host Functions' {
    It 'Get-SfosMacHost function should exist' {
        Get-Command Get-SfosMacHost | Should -Not -BeNullOrEmpty
    }
    
    It 'New-SfosMacHost function should exist' {
        Get-Command New-SfosMacHost | Should -Not -BeNullOrEmpty
    }
}

Describe 'Service Functions' {
    It 'Get-SfosService function should exist' {
        Get-Command Get-SfosService | Should -Not -BeNullOrEmpty
    }
    
    It 'New-SfosService function should exist' {
        Get-Command New-SfosService | Should -Not -BeNullOrEmpty
    }
    
    It 'Set-SfosService function should exist' {
        Get-Command Set-SfosService | Should -Not -BeNullOrEmpty
    }
    
    Context 'Get-SfosService Parameters' {
        It 'Should have ProtocolLike parameter for filtering' {
            (Get-Command Get-SfosService).Parameters.Keys | Should -Contain 'ProtocolLike'
        }
    }
    
    Context 'New-SfosService Parameters' {
        It 'Should have DstPort parameter (not Port)' {
            (Get-Command New-SfosService).Parameters.Keys | Should -Contain 'DstPort'
        }
        
        It 'Should have SrcPort parameter' {
            (Get-Command New-SfosService).Parameters.Keys | Should -Contain 'SrcPort'
        }
    }
}

Describe 'Service Group Functions' {
    It 'Get-SfosServiceGroup function should exist' {
        Get-Command Get-SfosServiceGroup | Should -Not -BeNullOrEmpty
    }
    
    It 'Add-SfosServiceGroupMember function should exist' {
        Get-Command Add-SfosServiceGroupMember | Should -Not -BeNullOrEmpty
    }
    
    It 'Remove-SfosServiceGroupMember function should exist' {
        Get-Command Remove-SfosServiceGroupMember | Should -Not -BeNullOrEmpty
    }
    
    Context 'Add-SfosServiceGroupMember Parameters' {
        It 'Should have ServiceGroupName parameter' {
            (Get-Command Add-SfosServiceGroupMember).Parameters.Keys | Should -Contain 'ServiceGroupName'
        }
        
        It 'Should have members parameter' {
            (Get-Command Add-SfosServiceGroupMember).Parameters.Keys | Should -Contain 'members'
        }
    }
}

Describe 'Export/Import Functions' {
    It 'Export-SfosIpHosts function should exist' {
        Get-Command Export-SfosIpHosts | Should -Not -BeNullOrEmpty
    }
    
    It 'Import-SfosIpHosts function should exist' {
        Get-Command Import-SfosIpHosts | Should -Not -BeNullOrEmpty
    }
    
    It 'Export-SfosServices function should exist' {
        Get-Command Export-SfosServices | Should -Not -BeNullOrEmpty
    }
    
    Context 'Export-SfosIpHosts Parameters' {
        It 'Should have FilePath parameter' {
            (Get-Command Export-SfosIpHosts).Parameters.Keys | Should -Contain 'FilePath'
        }
    }
}

Describe 'Pipeline Support' {
    Context 'Name Parameter Pipeline Support' {
        It 'Set-SfosIpHost Name should support ValueFromPipeline' {
            $cmd = Get-Command Set-SfosIpHost
            $nameParam = $cmd.Parameters['Name']
            $pipelineAttribs = $nameParam.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] }
            ($pipelineAttribs | Where-Object { $_.ValueFromPipeline -eq $true }) | Should -Not -BeNullOrEmpty
        }
    }
}


