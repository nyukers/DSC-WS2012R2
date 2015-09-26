Configuration DSCWS2012R2
{
    param 
    (
        [string[]]$Server
    )
    
    Import-DscResource –ModuleName "PSDesiredStateConfiguration"

    Node $Server 
    {
        Script First {
            TestScript = { if ( "Test script content" ) { $true } else { $false } }
            SetScript = { "Set script content" }
            GetScript = { return @{ Result = "Result for GetScript"
                GetScript = $GetScript; SetScript = $SetScript; TestScript = $TestScript
                }
            }
        }
    }
}  

$configData = @{ 
    AllNodes = @( @{ NodeName = "cs1.example.com"; PSDscAllowPlainTextPassword = $true } ) 
}

DSCWS2012R2 -Server ("cs1.example.com") -ConfigurationData $configData

Start-DscConfiguration -ComputerName ("cs1.example.com") `
    -Credential (Get-Credential -Message "Password" -UserName "Administrator") `
    -Path DSCWS2012R2 -Wait -Force -Verbose

<#
$configData = @{ 
    AllNodes = @( 
        @{ NodeName = "cs1.example.com"; PSDscAllowPlainTextPassword = $true },
        @{ NodeName = "cs1.example.com"; PSDscAllowPlainTextPassword = $true } 
    ) 
}

DSCWS2012R2 -Server ("cs1.example.com", "cs2.example.com") -ConfigurationData $configData

Start-DscConfiguration -ComputerName ("cs1.example.com", "cs2.example.com") `
    -Credential (Get-Credential -Message "Password" -UserName "Administrator") `
    -Path DSCWS2012R2 -Wait -Force -Verbose
#>