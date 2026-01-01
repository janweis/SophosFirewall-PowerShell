#requires -Version 5.1
#requires -Modules Pester

<#
.SYNOPSIS
    Pester Tests for SophosFirewall.Core module
    
.DESCRIPTION
    Comprehensive test suite for core helper functions:
    - Connect-SfosFirewall / Disconnect-SfosFirewall
    - Invoke-SfosApi
    - Get-SfosApiStatus
    - Assert-SfosApiReturnSuccess
    - Resolve-SfosParameters
    - ConvertTo-SfosXmlEscaped
    
.NOTES
    Run with: Invoke-Pester -Path "SophosFirewall.Core.Tests.ps1" -Verbose
#>

BeforeAll {
    # Import the module - adjust path for both local and CI environments
    $modulePath = if (Test-Path "$PSScriptRoot\..\Modules\SophosFirewall.Core\SophosFirewall.Core.psd1") {
        "$PSScriptRoot\..\Modules\SophosFirewall.Core\SophosFirewall.Core.psd1"
    } else {
        "$PSScriptRoot\..\..\Modules\SophosFirewall.Core\SophosFirewall.Core.psd1"
    }
    
    Import-Module -Name $modulePath -Force -ErrorAction Stop
}

Describe 'SophosFirewall.Core Module' {
    
    Context 'Module Loading' {
        It 'Module should load without errors' {
            $modulePath = if (Test-Path "$PSScriptRoot\..\Modules\SophosFirewall.Core\SophosFirewall.Core.psd1") {
                "$PSScriptRoot\..\Modules\SophosFirewall.Core\SophosFirewall.Core.psd1"
            } else {
                "$PSScriptRoot\..\..\Modules\SophosFirewall.Core\SophosFirewall.Core.psd1"
            }
            { Import-Module -Name $modulePath -Force -ErrorAction Stop } | Should -Not -Throw
        }
        
        It 'Should export required functions' {
            $module = Get-Module -Name 'SophosFirewall.Core'
            $requiredFunctions = @(
                'Connect-SfosFirewall',
                'Disconnect-SfosFirewall',
                'Invoke-SfosApi',
                'Get-SfosApiStatus',
                'Assert-SfosApiReturnSuccess',
                'Resolve-SfosParameters',
                'ConvertTo-SfosXmlEscaped'
            )
            
            foreach ($func in $requiredFunctions) {
                $module.ExportedFunctions.Keys | Should -Contain $func
            }
        }
    }
    
    Context 'ConvertTo-SfosXmlEscaped - XML Entity Escaping' {
        It 'Should escape ampersand (&)' {
            ConvertTo-SfosXmlEscaped 'Test & Test' | Should -Be 'Test &amp; Test'
        }
        
        It 'Should escape less-than (<)' {
            ConvertTo-SfosXmlEscaped 'A < B' | Should -Be 'A &lt; B'
        }
        
        It 'Should escape greater-than (>)' {
            ConvertTo-SfosXmlEscaped 'A > B' | Should -Be 'A &gt; B'
        }
        
        It 'Should escape double quote (")' {
            ConvertTo-SfosXmlEscaped 'Say "Hello"' | Should -Be 'Say &quot;Hello&quot;'
        }
        
        It "Should escape apostrophe (')" {
            ConvertTo-SfosXmlEscaped "It's" | Should -Be 'It&apos;s'
        }
        
        It 'Should handle multiple special characters' {
            ConvertTo-SfosXmlEscaped 'Test & <value> "quoted"' | `
                Should -Be 'Test &amp; &lt;value&gt; &quot;quoted&quot;'
        }
        
        It 'Should not modify plain text' {
            ConvertTo-SfosXmlEscaped 'PlainText' | Should -Be 'PlainText'
        }
        
        It 'Should handle empty string' {
            ConvertTo-SfosXmlEscaped '' | Should -Be ''
        }
    }
    
    Context 'Get-SfosApiStatus - XML Response Parsing' {
        It 'Should extract status code 200 from valid response' {
            $xmlResponse = @'
<Response><Status code="200"></Status></Response>
'@
            $xml = [xml]$xmlResponse
            $result = Get-SfosApiStatus -Xml $xml
            $result.Code | Should -Be '200'
        }
        
        It 'Should extract status code 202 from valid response' {
            $xmlResponse = @'
<Response><Status code="202"></Status></Response>
'@
            $xml = [xml]$xmlResponse
            $result = Get-SfosApiStatus -Xml $xml
            $result.Code | Should -Be '202'
        }
        
        It 'Should extract status code 502 from error response' {
            $xmlResponse = @'
<Response><Status code="502"><Msg>Authentication failed</Msg></Status></Response>
'@
            $xml = [xml]$xmlResponse
            $result = Get-SfosApiStatus -Xml $xml
            $result.Code | Should -Be '502'
        }
    }
    
    Context 'Assert-SfosApiReturnSuccess - Error Throwing' {
        It 'Should not throw on status 200' {
            $xmlResponse = @'
<Response><Status code="200"><Msg>Success</Msg></Status></Response>
'@
            $xml = [xml]$xmlResponse
            { Assert-SfosApiReturnSuccess -Xml $xml } | Should -Not -Throw
        }
        
        It 'Should not throw on status 202' {
            $xmlResponse = @'
<Response><Status code="202"><Msg>Success</Msg></Status></Response>
'@
            $xml = [xml]$xmlResponse
            { Assert-SfosApiReturnSuccess -Xml $xml } | Should -Not -Throw
        }
        
        It 'Should throw on status 502' {
            $xmlResponse = @'
<Response><Status code="502"><Msg>Authentication failed</Msg></Status></Response>
'@
            $xml = [xml]$xmlResponse
            { Assert-SfosApiReturnSuccess -Xml $xml -ErrorAction Stop } | Should -Throw
        }
        
        It 'Should throw on status 400' {
            $xmlResponse = @'
<Response><Status code="400"><Msg>Bad Request</Msg></Status></Response>
'@
            $xml = [xml]$xmlResponse
            { Assert-SfosApiReturnSuccess -Xml $xml -ErrorAction Stop } | Should -Throw
        }
    }
    
    Context 'Resolve-SfosParameters - Parameter Merging' {
        It 'Should use provided parameters when supplied' {
            $params = @{
                BoundParameters = @{
                    Firewall = '192.168.1.1'
                    Port = 4444
                    Username = 'user'
                    Password = (ConvertTo-SecureString 'pass' -AsPlainText -Force)
                }
            }
            
            $result = Resolve-SfosParameters @params
            $result.Firewall | Should -Be '192.168.1.1'
            $result.Port | Should -Be 4444
        }
        
        It 'Should fall back to stored connection when parameters missing' {
            # This requires stored connection context
            # Mock scenario: if no parameters provided, should attempt to use stored context
            Connect-SfosFirewall -Firewall '192.168.1.1' -Port 4444 -Credential (New-Object System.Management.Automation.PSCredential('test', (ConvertTo-SecureString 'test' -AsPlainText -Force)))
            
            $result = Resolve-SfosParameters -BoundParameters @{}
            $result.Firewall | Should -Be '192.168.1.1'
            $result.Port | Should -Be 4444
        }
    }
    
    Context 'Connect-SfosFirewall / Disconnect-SfosFirewall - Session Management' {
        It 'Connect should store connection parameters' {
            # This would require actual firewall connection or mocking
            # Validate that function accepts parameters without error
            $cred = New-Object System.Management.Automation.PSCredential('test', (ConvertTo-SecureString 'test' -AsPlainText -Force))
            { Connect-SfosFirewall -Firewall '192.168.1.1' -Port 4444 -Credential $cred -SkipCertificateCheck } | Should -Not -Throw
        }
        
        It 'Disconnect should clear connection context' {
            { Disconnect-SfosFirewall } | Should -Not -Throw
        }
    }
    
    Context 'Error Handling' {
        It 'ConvertTo-SfosXmlEscaped should escape special characters' {
            $result = ConvertTo-SfosXmlEscaped 'Test & <special>'
            $result | Should -Be 'Test &amp; &lt;special&gt;'
        }
        
        It 'Get-SfosApiStatus should handle valid XML response' {
            $validXml = @'
<Response>
    <StatusCode>200</StatusCode>
    <Message>Success</Message>
</Response>
'@
            $xml = [xml]$validXml
            { $result = Get-SfosApiStatus -Xml $xml } | Should -Not -Throw
        }
    }
}

Describe 'SophosFirewall.Core Integration Tests' {
    
    Context 'XML API Request Pattern Validation' {
        It 'Should correctly escape parameters in XML' {
            $name = 'Test & Special'
            $escaped = ConvertTo-SfosXmlEscaped $name
            $escaped | Should -Match '&amp;'
        }
    }
    
    Context 'Pipeline Support' {
        It 'ConvertTo-SfosXmlEscaped should support pipeline input' {
            'Test & Value' | ConvertTo-SfosXmlEscaped | Should -Be 'Test &amp; Value'
        }
    }
}
