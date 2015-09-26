Configuration DSCWS2012R2
{
    param 
    (
        [string[]]$Server
    )
    
    Import-DscResource –ModuleName "PSDesiredStateConfiguration"

    Node $Server 
    {

        Script ScriptFirst {
            TestScript = { if ( "Test script content" ) { $true } else { $false } }
            SetScript = { "Set script content" }
            GetScript = { return @{ Result = "Result for GetScript"
                GetScript = $GetScript; SetScript = $SetScript; TestScript = $TestScript
                }
            }
        }

        # Install hotfix installer
        $abcUpdatePath = "C:\UTILS\ABC-Update"
        $abcUpdateZip  = Join-Path $abcUpdatePath "ABC-Update.zip"
        File AbcUpdateDir {
            Ensure          = "present"
            DestinationPath = $abcUpdatePath
            Type            = "Directory"
        }
        Script AbcUpdateDownload {
            DependsOn = "[File]AbcUpdateDir"
            SetScript =  ({
                Invoke-WebRequest -Uri http://abc-deploy.com/Files/ABC-Update.zip -OutFile {0}
                } -f @($abcUpdateZip)) 
            GetScript = { 
                return @{ Result = $TestScript
                    GetScript = $GetScript; SetScript = $SetScript; TestScript = $TestScript
                    }
                }
            TestScript = ({
                Test-Path {0} 
                } -f @($abcUpdateZip)) 
        }
        Archive AbcUpdateUnpack {
            Ensure = "Present"
            DependsOn = "[Script]AbcUpdateDownload"
            Path = $abcUpdateZip
            Destination = $abcUpdatePath
        }

        #
        # Base settings
        #
        $shortName = $Server.Split(".")[0].ToLower()
        Script ComputerName {
            SetScript = ({
                Rename-Computer -NewName "{0}"
            } -f @($shortName))
            GetScript = { return @{ Result = $env:computerName
                GetScript = $GetScript.Trim(); SetScript = $SetScript.Trim(); TestScript = $TestScript.Trim()
                }
            }
            TestScript = ({ 
                $env:computerName.ToLower() -eq "{0}" 
            } -f @($shortName))
        }

        Registry PrimaryDomainSuffix {
            Key = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\"
            ValueName = "NV Domain"
            Ensure = "Present"
            ValueData = "example.com"
            ValueType = "String"
        }

        Script LanguageSettings {
            SetScript = {
                    Set-Culture ru-RU
                    Set-WinSystemLocale ru-RU
                    Set-WinHomeLocation 203
            }
            GetScript = { return @{ Result = ( "Culture: " + (Get-Culture).Name + ". WinSystemLocale: " + (Get-WinSystemLocale).Name -eq "ru-RU")
                GetScript = $GetScript.Trim(); SetScript = $SetScript.Trim(); TestScript = $TestScript.Trim()
                }
            }
            TestScript = { (Get-Culture).Name -eq "ru-RU" -and (Get-WinSystemLocale).Name -eq "ru-RU" -and (Get-WinHomeLocation).GeoID -eq 203 }
        }
        
        Script AbcUpdateNet452Install {
            DependsOn = "[Archive]AbcUpdateUnpack"
            SetScript = { C:\UTILS\ABC-Update\ABC-Update.exe /a:install /k:2934520 }
            GetScript = { return @{ Result = if ( Get-HotFix -Id KB2934520 -ErrorAction SilentlyContinue ) { "KB2934520: Installed" } else { "KB2934520: Not Found" }
                GetScript = $GetScript; SetScript = $SetScript; TestScript = $TestScript
                }
            }
            TestScript = { if ( Get-HotFix -Id KB2934520 -ErrorAction SilentlyContinue ) { $true } else { $false } }
        }

        Script AbcUpdateTimeZoneInstall {
            DependsOn = "[Archive]AbcUpdateUnpack"
            SetScript = { C:\UTILS\ABC-Update\ABC-Update.exe /a:install /k:3013410 }
            GetScript = { return @{ Result = if ( Get-HotFix -Id KB3013410 -ErrorAction SilentlyContinue ) { "KB3013410: Installed" } else { "KB3013410: Not Found" }
                GetScript = $GetScript; SetScript = $SetScript; TestScript = $TestScript
                }
            }
            TestScript = { if ( Get-HotFix -Id KB3013410 -ErrorAction SilentlyContinue ) { $true } else { $false } }
        }

        Script TimeZoneSettings {
            SetScript = { tzutil.exe /s "North Asia East Standard Time" }
            GetScript = { return @{ Result = [System.TimeZone]::CurrentTimeZone.StandardName
                GetScript = $GetScript.Trim(); SetScript = $SetScript.Trim(); TestScript = $TestScript.Trim()
                }
            }
            TestScript = { [System.TimeZone]::CurrentTimeZone.StandardName -eq "Russia TZ 7 Standard Time" }
        }

        Script WindowsUpdateSettings {
            SetScript = {
                $WUSettings = (New-Object -com "Microsoft.Update.AutoUpdate").Settings
                $WUSettings.NotificationLevel=2
                $WUSettings.IncludeRecommendedUpdates=$true
                $WUSettings.Save()
            }
            GetScript = { return @{ Result = ''
                    GetScript = $GetScript; SetScript = $SetScript; TestScript = $TestScript
                }
            }
            TestScript = { 
                $WUSettings = (New-Object -com "Microsoft.Update.AutoUpdate").Settings; $WUSettings.NotificationLevel -eq 2 -and $WUSettings.IncludeRecommendedUpdates -eq $true
            }
        }

        #
        # Required Windows Features 
        #
        WindowsFeature offFSSMB1 {
            Ensure = "Absent"
            Name   = "FS-SMB1"
        }
        WindowsFeature WebAspNet45 {
            Ensure = "Present"
            Name   = "Web-Asp-Net45"
            IncludeAllSubFeature = $True
        }
        WindowsFeature WebHttpErrors {
            Ensure = "Present"
            Name   = "Web-Http-Errors"
            DependsOn = "[WindowsFeature]WebAspNet45"
        }
        WindowsFeature WebStaticContent {
            Ensure = "Present"
            Name   = "Web-Static-Content"
            DependsOn = "[WindowsFeature]WebAspNet45"
        }
        WindowsFeature WebHttpLogging {
            Ensure = "Present"
            Name   = "Web-Http-Logging"
            DependsOn = "[WindowsFeature]WebAspNet45"
        }
        WindowsFeature WebStatCompression {
            Ensure = "Present"
            Name   = "Web-Stat-Compression"
            DependsOn = "[WindowsFeature]WebAspNet45"
        }
        WindowsFeature WebDynCompression {
            Ensure = "Present"
            Name   = "Web-Dyn-Compression"
            DependsOn = "[WindowsFeature]WebAspNet45"
        }
        WindowsFeature WebIPSecurity {
            Ensure = "Present"
            Name   = "Web-IP-Security"
            DependsOn = "[WindowsFeature]WebAspNet45"
        }
        WindowsFeature WebCGI {
            Ensure = "Present"
            Name   = "Web-CGI"
            DependsOn = "[WindowsFeature]WebAspNet45"
        }
        WindowsFeature WebMgmtConsole {
            Ensure = "Present"
            Name   = "Web-Mgmt-Console"
            DependsOn = "[WindowsFeature]WebAspNet45"
        }

        #
        # Utilites 
        #
        Script FarDownLoad {
            SetScript = { Invoke-WebRequest -Uri http://www.farmanager.com/files/Far30b4400.x64.20150709.msi -OutFile C:\Users\Public\Downloads\Far30b4400.x64.20150709.msi }
            GetScript = { return @{ Result = Test-Path C:\Users\Public\Downloads\Far30b4400.x64.20150709.msi
                GetScript = $GetScript; SetScript = $SetScript; TestScript = $TestScript
                }
            }
            TestScript = { Test-Path C:\Users\Public\Downloads\Far30b4400.x64.20150709.msi }
        }
        Package FarInstall {
            Ensure    = "Present"
            DependsOn = "[Script]FarDownLoad"
            Name      = "Far Manager 3 x64"
            ProductId = 'E5512F32-B7C1-48E3-B6AF-E5F962F99ED6'
            Path      = "C:\Users\Public\Downloads\Far30b4400.x64.20150709.msi"
            Arguments = ''
            LogPath   = "C:\Users\Public\Downloads\FarInstall.log"
        }


        #
        # Users and ACLs
        #
        $JenkinsCredential = New-Object System.Management.Automation.PSCredential(`
            "Jenkins", ("Pa`$`$w0rd" | ConvertTo-SecureString -asPlainText -Force)`
        )
        User JenkinsUser {
            UserName = "Jenkins"
            Ensure = "Present"
            Password = $JenkinsCredential
            PasswordChangeNotAllowed = $true
            PasswordNeverExpires = $true
        }

        $AccessStringTmpl = "NT AUTHORITY\SYSTEM Allow  FullControl`nBUILTIN\Administrators Allow  FullControl`nBUILTIN\Users Allow  ReadAndExecute, Synchronize`nCS1\Jenkins Allow  Modify, Synchronize"
        File DirDweb {
            Ensure          = "present"
            DestinationPath = "c:\web"
            Type            = "Directory"
        }
        Script AclsDweb
        {
            DependsOn = "[File]DirDweb"
            SetScript = {
                icacls c:\web /reset /t /q
                takeown.exe /f c:\web /r /a /d y
                icacls.exe c:\web /inheritance:r
                icacls.exe c:\web /grant:r "Administrators:(OI)(CI)(F)" "System:(OI)(CI)(F)" "Users:(OI)(CI)(RX)" "Jenkins:(OI)(CI)(M)" /t /q
            }
            GetScript = { return @{ Result = (get-acl c:\web).AccessToString
                GetScript = $GetScript; SetScript = $SetScript; TestScript = $TestScript
                }
            }
            TestScript = ({ (get-acl c:\web).AccessToString -eq "{0}"  
            } -f @($AccessStringTmpl))
        }

        #
        # MSSQL 
        #
        WindowsFeature NetFrameworkCore {
            Ensure = "Present"
            Name   = "Net-Framework-Core"
            IncludeAllSubFeature = $True
        }
        Script MSSQLConfigDownLoad {
            SetScript = { Invoke-WebRequest -Uri https://raw.githubusercontent.com/nelsh/DSC-WS2012R2/master/SQL2014-Setup.ini -OutFile C:\Users\Public\Downloads\SQL2014-Setup.ini }
            GetScript = { return @{ Result = Test-Path C:\Users\Public\Downloads\SQL2014-Setup.ini
                GetScript = $GetScript; SetScript = $SetScript; TestScript = $TestScript
                }
            }
            TestScript = { Test-Path C:\Users\Public\Downloads\SQL2014-Setup.ini }
        }
        Script MSSQL {
            SetScript = { r:\setup.exe /configurationfile=C:\Users\Public\Downloads\SQL2014-Setup.ini /SAPWD=1q@w3e }
            GetScript = { return @{ Result = if ( Get-Service -Name "MSSQLSERVER" -ErrorAction SilentlyContinue ) { "Servise MSSQLSERVER is exist" } else { "Servise MSSQLSERVER not found" }
                GetScript = $GetScript; SetScript = $SetScript; TestScript = $TestScript
                }
            }
            TestScript = { if ( Get-Service -Name "MSSQLSERVER" -ErrorAction SilentlyContinue ) { $true } else { $false } }
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
