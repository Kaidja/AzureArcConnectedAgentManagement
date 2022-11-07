Function Connect-AzureArcNode
{
<#
.Synopsis
   Connects the local machine to Azure Arc.
.DESCRIPTION
   Connects the local machine to Azure Arc.
.PARAMETER AccessToken
.PARAMETER ServicePrincipalSecret
Azure AD Application ServicePrincipal Secret
.PARAMETER ServicePrincipalID
Azure AD Application ServicePrincipal ID
.PARAMETER DeviceLogin
Specifies the Azure Arc onboarding method
.PARAMETER TenantID
Specifies the Azure Active Directory Tenant ID
.PARAMETER ResourceGroup
Specifies the Azure Resource Group Name
.PARAMETER SubscriptionID
Specifies the Azure Subscription ID
.PARAMETER Tags
Specifies the Azure Resource Tags
.EXAMPLE
Connect-AzureArcNode -DeviceLogin -TenantID XXXX-XXXX-XXXX-XXXX-XXXXXX -ResourceGroup "Resource Group Name" -Location "West Europe" -SubscriptionID XXXX-XXXX-XXXX-XXXX-XXXXXX
.EXAMPLE
Connect-AzureArcNode -ServicePrincipalID XXXX-XXXX-XXXX-XXXX-XXXXXX -ServicePrincipalSecret "XXXX-XXXX-XXXX-XXXX-XXXXXX" -TenantID XXXX-XXXX-XXXX-XXXX-XXXXXX -ResourceGroup "Resource Group Name" -Location "West Europe" -SubscriptionID XXXX-XXXX-XXXX-XXXX-XXXXXX
.EXAMPLE
#Define Azure Resource Tags Hashtable
$Tags = @{
    Datacenter = "Value1"
    City = "Value2"
    StateOrDistrict = "Value3"
    CountryOrRegion = "Value4"
    MinuTag= "Value5"
}

Connect-AzureArcNode -ServicePrincipalID XXXX-XXXX-XXXX-XXXX-XXXXXX -ServicePrincipalSecret "XXXX-XXXX-XXXX-XXXX-XXXXXX" -TenantID XXXX-XXXX-XXXX-XXXX-XXXXXX -ResourceGroup "Resource Group Name" -Location "West Europe" -SubscriptionID XXXX-XXXX-XXXX-XXXX-XXXXXX -Tags $Tags

#>
    [CmdletBinding(DefaultParameterSetName = 'ServicePrincipal')]
    Param(
      [Parameter(Mandatory = $true,ParameterSetName = 'AccessToken',HelpMessage = 'Enter Access Token')]
        $AccessToken,
     [Parameter(Mandatory = $true,ParameterSetName = 'ServicePrincipal',HelpMessage = 'Enter ServicePrincipal')]
        $ServicePrincipalSecret,
     [Parameter(Mandatory = $true,ParameterSetName = 'ServicePrincipal',HelpMessage = 'Enter ServicePrincipal ID')]
        $ServicePrincipalID,
     [Parameter(Mandatory = $true,ParameterSetName = 'DeviceLogin')]
        [Switch]$DeviceLogin,
     [Parameter(Mandatory = $true,ParameterSetName = 'ServicePrincipal',HelpMessage = 'Enter')]
     [Parameter(Mandatory = $true,ParameterSetName = 'DeviceLogin',HelpMessage = 'Enter')]
        [String]$TenantID,
     [Parameter(Mandatory = $true,ParameterSetName = 'AccessToken',HelpMessage = 'Enter')]
     [Parameter(Mandatory = $true,ParameterSetName = 'ServicePrincipal',HelpMessage = 'Enter')]
     [Parameter(Mandatory = $true,ParameterSetName = 'DeviceLogin',HelpMessage = 'Enter')]
        [String]$ResourceGroup,
     [Parameter(Mandatory = $true,ParameterSetName = 'AccessToken',HelpMessage = 'Enter')]
     [Parameter(Mandatory = $true,ParameterSetName = 'ServicePrincipal',HelpMessage = 'Enter')]
     [Parameter(Mandatory = $true,ParameterSetName = 'DeviceLogin',HelpMessage = 'Enter')]
        [String]$Location,
     [Parameter(Mandatory = $true,ParameterSetName = 'AccessToken',HelpMessage = 'Enter')]
     [Parameter(Mandatory = $true,ParameterSetName = 'ServicePrincipal',HelpMessage = 'Enter')]
     [Parameter(Mandatory = $true,ParameterSetName = 'DeviceLogin',HelpMessage = 'Enter')]
        [String]$SubscriptionID,
     [Parameter(Mandatory = $false,ParameterSetName = 'AccessToken',HelpMessage = 'Enter')]
     [Parameter(Mandatory = $false,ParameterSetName = 'ServicePrincipal',HelpMessage = 'Enter')]
     [Parameter(Mandatory = $false,ParameterSetName = 'DeviceLogin',HelpMessage = 'Enter')]
        [HashTable]$Tags
    )

    Begin{
        $AZCMAGENTLocation = "C:\Program Files\AzureConnectedMachineAgent\azcmagent.exe"
        If(!(Test-Path -Path $AZCMAGENTLocation)){
            Throw "Azure Arc Agent not installed"
        }
    }
    Process{
        
        

        If($PSBoundParameters.ContainsKey("ServicePrincipalID")){
            $Parameters = '& $AZCMAGENTLocation connect --service-principal-id $ServicePrincipalID --service-principal-secret $ServicePrincipalSecret --tenant-id $TenantID --subscription-id $SubscriptionID --resource-group $ResourceGroup --location $Location'

        }
        ElseIf($PSBoundParameters.ContainsKey("AccessToken")){
            $Parameters = '& $AZCMAGENTLocation connect --access-token $AccessToken --subscription-id $SubscriptionID --resource-group $ResourceGroup --location $Location'
        }
        ElseIf($PSBoundParameters.ContainsKey("DeviceLogin")){
            $Parameters = '& $AZCMAGENTLocation connect --tenant-id $TenantID --subscription-id $SubscriptionID --resource-group $ResourceGroup --location $Location'
        }

        If($PSBoundParameters.ContainsKey("Tags")){
            $ProcessedTags = ($Tags.GetEnumerator()| ForEach-Object -Process { "$($PSItem.key)" + "=" + "'$($PSItem.value)'" }) -join ","
            $Parameters = "$Parameters --tags $ProcessedTags"
        }
        Try{
            Write-Verbose -Message "& (Executing $AZCMAGENTLocation with the following parameters: $Parameters)"
            Invoke-Expression $Parameters
        }
        Catch{
            $Error[0]
        }
    
    }
    End{}
}
Function Disconnect-AzureArcNode
{
<#
.Synopsis
   Disconnects the local machine from Azure Arc service.
.DESCRIPTION
   Disconnects the local machine from Azure Arc service.
.PARAMETER AccessToken
.PARAMETER ServicePrincipalSecret
.PARAMETER ServicePrincipalID
.PARAMETER DeviceLogin
.EXAMPLE
Disconnect-AzureArcNode -ServicePrincipalSecret XXXX-XXXX-XXXX-XXXX-XXXXXX -ServicePrincipalID XXXX-XXXX-XXXX-XXXX-XXXXXX
.EXAMPLE   
Disconnect-AzureArcNode -AccessToken $MyAccessToken
.EXAMPLE  
Disconnect-AzureArcNode -DeviceLogin
#>
    [CmdletBinding(DefaultParameterSetName = 'ServicePrincipal')]
    Param(
      [Parameter(Mandatory = $true,ParameterSetName = 'AccessToken',HelpMessage = 'Enter Access Token')]
        $AccessToken,
     [Parameter(Mandatory = $true,ParameterSetName = 'ServicePrincipal',HelpMessage = 'Enter ServicePrincipal')]
        $ServicePrincipalSecret,
     [Parameter(Mandatory = $true,ParameterSetName = 'ServicePrincipal',HelpMessage = 'Enter ServicePrincipal ID')]
        $ServicePrincipalID,
     [Parameter(Mandatory = $true,ParameterSetName = 'DeviceLogin')]
        [Switch]$DeviceLogin


    )

    Begin{
        $AZCMAGENTLocation = "C:\Program Files\AzureConnectedMachineAgent\azcmagent.exe"
        If(!(Test-Path -Path $AZCMAGENTLocation)){
            Throw "Azure Arc Agent not installed"
        }
    }
    Process{
        
        If($PSBoundParameters.ContainsKey("ServicePrincipalID")){
            $Parameters = "& $AZCMAGENTLocation disconnect --service-principal-id $ServicePrincipalID --service-principal-secret $ServicePrincipalSecret"
        }
        ElseIf($PSBoundParameters.ContainsKey("AccessToken")){
            $Parameters = "& $AZCMAGENTLocation disconnect --access-token $AccessToken"
        }
        ElseIf($PSBoundParameters.ContainsKey("DeviceLogin")){
            $Parameters = "& $AZCMAGENTLocation disconnect "
        }

        Try{
            Write-Verbose -Message "Executing $AZCMAGENTLocation with the following parameters: $Parameters"

            Invoke-Expression $Parameters
        }
        Catch{
            $Error[0]
        }
    
    }
    End{}
}
Function Get-AzureArcNodeAgentInformation
{
<#
.Synopsis
   Outputs information about the Azure Arc Agent.
.DESCRIPTION
   Outputs information about the Azure Arc Agent.
.PARAMETER OutPutType
Specifies the output type. Type can be JSON or RAW.
.EXAMPLE
Get-AzureArcNodeAgentInformation -OutPutType JSON
.EXAMPLE   
Get-AzureArcNodeAgentInformation -OutPutType RAW
#>
    [CmdletBinding()]
    Param(
      [Parameter(Mandatory = $True,HelpMessage = 'Enter the output type')]
      [ValidateSet("JSON", "RAW")]
        $OutPutType = "JSON"
    
    )

    Begin{
        $AZCMAGENTLocation = "C:\Program Files\AzureConnectedMachineAgent\azcmagent.exe"
        If(!(Test-Path -Path $AZCMAGENTLocation)){
            Throw "Azure Arc Agent not installed"
        }
    }
    Process{
       If($OutPutType -eq "JSON"){
            $Parameters = '& $AZCMAGENTLocation show -j'

            $AgentstatusHash = [ordered]@{}
            $QueryResults = Invoke-Expression $Parameters | ConvertFrom-Json
            $QueryResults.psobject.properties | Sort-Object -Property Name | 
                ForEach-Object { $AgentstatusHash[$((Get-Culture).TextInfo.ToTitleCase($PSItem.Name))] = $PSItem.Value }
            
            Return $AgentstatusHash

       }
       Else{
            $Parameters = '& $AZCMAGENTLocation show'
            $QueryResults = Invoke-Expression $Parameters

            Return $QueryResults
       }
       
        Try{
            Write-Verbose -Message "Executing $AZCMAGENTLocation with the following parameters: $Parameters"


        }
        Catch{
            $Error[0]
        }
    
    }
    End{}
}

Function Test-AzureArcNodeNetworkConnectivity
{
<#
.Synopsis
   Tests the connectivity of Azure Arc Network Service
.DESCRIPTION
   Tests the connectivity of Azure Arc Network Service
.PARAMETER Location
    Specifies the Azure Region.
.PARAMETER OutPutType
    Specifies the output type. Type can be JSON or RAW.
.EXAMPLE
    Test-AzureArcNodeNetworkConnectivity -OutPutType JSON
.EXAMPLE   
    Test-AzureArcNodeNetworkConnectivity -OutPutType RAW
#>
    [CmdletBinding()]
    Param(
     [Parameter(Mandatory = $True,HelpMessage = 'Enter the Azure Region')]
        [String]$Location,
      [Parameter(Mandatory = $True,HelpMessage = 'Enter the output type')]
      [ValidateSet("JSON", "RAW")]
        $OutPutType = "JSON"    
    )

    Begin{
        $AZCMAGENTLocation = "C:\Program Files\AzureConnectedMachineAgent\azcmagent.exe"
        If(!(Test-Path -Path $AZCMAGENTLocation)){
            Throw "Azure Arc Agent not installed"
        }
    }
    Process{
        If($OutPutType -eq "JSON"){
            $Parameters = '& $AZCMAGENTLocation check -l $Location -j'
        }
        Else{
            $Parameters = '& $AZCMAGENTLocation check -l $Location'
        }

        $QueryResults = Invoke-Expression $Parameters
    
        Return $QueryResults
    }
    End{}

}

Function Set-AzureArcNodeConfiguration
{
<#
.Synopsis
   Configures settings for the local Azure Arc Agent
.DESCRIPTION
   Configures settings for the local Azure Arc Agent
.PARAMETER ConfigurationName
    Specifies the setting name. Possible values are incomingconnections.ports,proxy.url,extensions.allowlist,extensions.blocklist,proxy.bypass,guestconfiguration.enabled,extensions.enabled
.PARAMETER ConfigurationValue
    Specifies the setting value.
.PARAMETER OutPutType
.EXAMPLE
    Set-AzureArcNodeConfiguration -ConfigurationName proxy.url -ConfigurationValue "http://proxy.Kaido.ee:8530" -OutPutType JSON
#>
    [CmdletBinding()]
    Param(
      [Parameter(Mandatory = $True,HelpMessage = 'Enter the Configuration Name')]
      [ValidateSet("incomingconnections.ports","proxy.url","extensions.allowlist","extensions.blocklist","proxy.bypass","guestconfiguration.enabled","extensions.enabled")]
        $ConfigurationName,
      [Parameter(Mandatory = $True,HelpMessage = 'Enter the Configuration Value')]
        $ConfigurationValue,
      [Parameter(Mandatory = $True,HelpMessage = 'Enter the output type')]
      [ValidateSet("JSON", "RAW")]
        $OutPutType = "JSON"     
    )

    Begin{
        $AZCMAGENTLocation = "C:\Program Files\AzureConnectedMachineAgent\azcmagent.exe"
        If(!(Test-Path -Path $AZCMAGENTLocation)){
            Throw "Azure Arc Agent not installed"
        }
    }

    Process{
        If($OutPutType -eq "JSON"){
            $Parameters = '& $AZCMAGENTLocation config set $ConfigurationName $ConfigurationValue -j'
        }
        Else{
            $Parameters = '& $AZCMAGENTLocation config set $ConfigurationName $ConfigurationValue'
        }
        
        $SetConfigResults = Invoke-Expression $Parameters
    
        Return $SetConfigResults
    }

    End{}

}

Function Get-AzureArcNodeConfiguration
{
<#
.Synopsis
   Queries the local Azure Arc Agent configuration
.DESCRIPTION
   Queries the local Azure Arc Agent configuration
.PARAMETER ConfigurationName
    Specifies the setting name. Possible values are incomingconnections.ports,proxy.url,extensions.allowlist,extensions.blocklist,proxy.bypass,guestconfiguration.enabled,extensions.enabled
.PARAMETER OutPutType
.EXAMPLE
    Get-AzureArcNodeConfiguration -ConfigurationName proxy.url -OutPutType JSON
#>
    [CmdletBinding()]
    Param(
      [Parameter(Mandatory = $True,HelpMessage = 'Enter the Configuration Name')]
      [ValidateSet("incomingconnections.ports","proxy.url","extensions.allowlist","extensions.blocklist","proxy.bypass","guestconfiguration.enabled","extensions.enabled")]
        $ConfigurationName,
      [Parameter(Mandatory = $True,HelpMessage = 'Enter the output type')]
      [ValidateSet("JSON", "RAW")]
        $OutPutType = "JSON"     
    )

    Begin{
        $AZCMAGENTLocation = "C:\Program Files\AzureConnectedMachineAgent\azcmagent.exe"
        If(!(Test-Path -Path $AZCMAGENTLocation)){
            Throw "Azure Arc Agent not installed"
        }
    }

    Process{
        If($OutPutType -eq "JSON"){
            $Parameters = '& $AZCMAGENTLocation config get $ConfigurationName $ConfigurationValue -j'
        }
        Else{
            $Parameters = '& $AZCMAGENTLocation config get $ConfigurationName $ConfigurationValue'
        }
        
        $SetConfigResults = Invoke-Expression $Parameters
    
        Return $SetConfigResults
    }

    End{}

}

Function Clear-AzureArcNodeConfiguration
{
<#
.Synopsis
   Resets the local Azure Arc Agent configurationf or specific setting
.DESCRIPTION
   Resets the local Azure Arc Agent configurationf or specific setting
.PARAMETER ConfigurationName
    Specifies the setting name. Possible values are incomingconnections.ports,proxy.url,extensions.allowlist,extensions.blocklist,proxy.bypass,guestconfiguration.enabled,extensions.enabled
.PARAMETER OutPutType
.EXAMPLE
    Clear-AzureArcNodeConfiguration -ConfigurationName proxy.url -OutPutType JSON
#>
    [CmdletBinding()]
    Param(
      [Parameter(Mandatory = $True,HelpMessage = 'Enter the Configuration Name')]
      [ValidateSet("incomingconnections.ports","proxy.url","extensions.allowlist","extensions.blocklist","proxy.bypass","guestconfiguration.enabled","extensions.enabled")]
        $ConfigurationName,
      [Parameter(Mandatory = $True,HelpMessage = 'Enter the output type')]
      [ValidateSet("JSON", "RAW")]
        $OutPutType = "JSON"     
    )

    Begin{
        $AZCMAGENTLocation = "C:\Program Files\AzureConnectedMachineAgent\azcmagent.exe"
        If(!(Test-Path -Path $AZCMAGENTLocation)){
            Throw "Azure Arc Agent not installed"
        }
    }

    Process{
        If($OutPutType -eq "JSON"){
            $Parameters = '& $AZCMAGENTLocation config clear $ConfigurationName -j'
        }
        Else{
            $Parameters = '& $AZCMAGENTLocation config clear $ConfigurationName'
        }
        
        $SetConfigResults = Invoke-Expression $Parameters
    
        Return $SetConfigResults
    }

    End{}

}

Function Get-MSIVersion 
{
<#
    Source - https://raw.githubusercontent.com/Azure/ArcEnabledServersGroupPolicy/main/EnableAzureArc.ps1
#>
    Param(
        [IO.FileInfo]$Path
    )
    
    $WindowsInstaller = New-Object -ComObject WindowsInstaller.Installer
    $Database = $windowsInstaller.GetType().InvokeMember("OpenDatabase", "InvokeMethod", $Null,$windowsInstaller, @($path.FullName, 0))
    
    $Query = "SELECT Value FROM Property WHERE Property = 'ProductVersion'"
    $View = $Database.GetType().InvokeMember(
        "OpenView", "InvokeMethod", $Null, $database, ($Query)
    )
    
    $View.GetType().InvokeMember("Execute", "InvokeMethod", $Null, $View, $Null)
    $Record = $View.GetType().InvokeMember( "Fetch", "InvokeMethod", $Null, $View, $Null )
    $Version = ($Record.GetType().InvokeMember( "StringData", "GetProperty", $Null, $record, 1 ))
    
    return $Version
}

Function Download-AzureArcAgent
{
    $ArcAgentURL = "https://aka.ms/AzureConnectedMachineAgent"
    $MSILocation = "C:\Windows\Temp\AzureConnectedMachineAgent.msi"
    Invoke-WebRequest -Uri $ArcAgentURL -OutFile $MSILocation
}

Function Install-AzureArcAgent
{
<#
.Synopsis
   Installs Azure Arc Agent
.DESCRIPTION
   Installs Azure Arc Agent
.EXAMPLE
    Install-AzureArcAgent
#>
    Begin{

        $MSILocation = "C:\Windows\Temp\AzureConnectedMachineAgent.msi"
        Download-AzureArcAgent
        $DownloadedVersion = Get-MSIVersion -Path $MSILocation

        $AZCMAGENTLocation = "C:\Program Files\AzureConnectedMachineAgent\azcmagent.exe"
        If(!(Test-Path -Path $AZCMAGENTLocation)){
            [Version]$InstalledVersion = 0.0.0.0
        }
        Else{
            [Version]$InstalledVersion = (Get-AzureArcNodeAgentInformation -OutPutType JSON).Agentversion
        }
        
    }
    Process{
        If([Version]$InstalledVersion -lt [Version]$DownloadedVersion[1]){
            $ARCAgentInstallation = (Start-Process -FilePath msiexec -ArgumentList "/i $MSILocation /qn" -Wait -PassThru).ExitCode
            If($ARCAgentInstallation -eq 0){
                Write-Output -InputObject "Installation succeeded. Exit Code: $ARCAgentInstallation"
            }
            Else{
                Write-Output -InputObject "Installation failed. Exit Code: $ARCAgentInstallation"
            }
        }
        Else{
            "All good. No need to update the agent. Current agent version: $InstalledVersion"
        }
    }
    End{}

}


Function Save-AzureArcNodeLogs
{
<#
.Synopsis
   Gathers Azure Arc Agent logs from the local machine for troubleshooting. The logs will be saved on the desktop of the current user
.DESCRIPTION
   Gathers Azure Arc Agent logs from the local machine for troubleshooting. The logs will be saved on the desktop of the current user
.EXAMPLE
    Save-AzureArcNodeLogs
#>

    Begin{
        $AZCMAGENTLocation = "C:\Program Files\AzureConnectedMachineAgent\azcmagent.exe"
        If(!(Test-Path -Path $AZCMAGENTLocation)){
            Throw "Azure Arc Agent not installed"
        }
    }

    Process{
        $Parameters = '& $AZCMAGENTLocation logs -o $env:USERPROFILE\Desktop\AzureConnectedMachineAgentLogs.zip'

        $Logs = Invoke-Expression $Parameters
    
        Return $Logs
    }

    End{}
}

Function Get-AzureArcNodeServiceStatus
{
<#
.Synopsis
   Prints out local Azure Arc Agent Service Status.
.DESCRIPTION
   Prints out local Azure Arc Agent Service Status.
.EXAMPLE
    Get-AzureArcNodeServiceStatus
#>    
    Begin{}
    Process{
        
        Try{
            Get-Service -Name himds -ErrorAction Stop
        }
        Catch{
            Write-Output -InputObject "Azure Hybrid Instance Metadata Service is not installed"
        }

    }
    End{}
    
}

Function Restart-AzureArcNodeService
{
<#
.Synopsis
   Restarts local Azure Arc Agent Service.
.DESCRIPTION
   Restarts local Azure Arc Agent Service.
.EXAMPLE
    Restart-AzureArcNodeService
#>    
    Begin{}
    Process{
        
        Try{
            Restart-Service -Name himds -ErrorAction Stop -Force -Verbose
        }
        Catch{
            Write-Output -InputObject "Failed to restart Azure Hybrid Instance Metadata Service"
        }

    }
    End{}
    
}

Function Test-AzureArcNodeConnection
{
<#
.Synopsis
   Gathers local Azure Arc Agent Service status.
.DESCRIPTION
   Gathers local Azure Arc Agent Service status.
.EXAMPLE
    Test-AzureArcNodeConnection
#>
    Begin{

        $AZCMAGENTLocation = "C:\Program Files\AzureConnectedMachineAgent\azcmagent.exe"
        If(!(Test-Path -Path $AZCMAGENTLocation)){
            Throw "Azure Arc Agent not installed"
        }    
    }
    Process{
        Try{
            $URL = "http://localhost:40342/agentstatus"
            $ServiceStatus = (Invoke-WebRequest -Uri $URL -UseBasicParsing -ErrorAction STOP).Content | ConvertFrom-Json
            
            $ServicestatusHash = [ordered]@{}
            $ServiceStatus.psobject.properties | Sort-Object -Property Name | 
                ForEach-Object { $ServicestatusHash[$((Get-Culture).TextInfo.ToTitleCase($PSItem.Name))] = $PSItem.Value }
            
            Return $ServicestatusHash
        }
        Catch{
            $Error[0]
        }
    }
    End{}
    

}

Function Get-AzureArcNodeAgentConfigurationFileContent
{
<#
.Synopsis
   Prints out local Azure Arc Agent Service "C:\ProgramData\AzureConnectedMachineAgent\Config\agentconfig.json" file content.
.DESCRIPTION
   Prints out local Azure Arc Agent Service "C:\ProgramData\AzureConnectedMachineAgent\Config\agentconfig.json" file content.
.EXAMPLE
    Get-AzureArcNodeAgentConfigurationFileContent
#>  
   Begin{

        $AZCMAGENTLocation = "C:\Program Files\AzureConnectedMachineAgent\azcmagent.exe"
        If(!(Test-Path -Path $AZCMAGENTLocation)){
            Throw "Azure Arc Agent not installed"
        }    
    }
    Process{
        Try{
            $ConfigurationFileContent = Get-Content -Raw -Path "C:\ProgramData\AzureConnectedMachineAgent\Config\agentconfig.json" -ErrorAction Stop | ConvertFrom-Json

            $ConfigurationFileHash = [ordered]@{}
            $ConfigurationFileContent.psobject.properties | Sort-Object -Property Name | 
            ForEach-Object { $ConfigurationFileHash[$((Get-Culture).TextInfo.ToTitleCase($PSItem.Name))] = $PSItem.Value }
            
            Return $ConfigurationFileHash
        }
        Catch{
            $Error[0]
        }
    }
    End{}
}

Function Get-AzureArcNodeAgentLocalConfigurationFileContent
{
<#
.Synopsis
   Prints out local Azure Arc Agent Service "C:\ProgramData\AzureConnectedMachineAgent\Config\localconfig.json" file content.
.DESCRIPTION
   Prints out local Azure Arc Agent Service "C:\ProgramData\AzureConnectedMachineAgent\Config\localconfig.json" file content.
.EXAMPLE
    Get-AzureArcNodeAgentLocalConfigurationFileContent
#>   
   Begin{

        $AZCMAGENTLocation = "C:\Program Files\AzureConnectedMachineAgent\azcmagent.exe"
        If(!(Test-Path -Path $AZCMAGENTLocation)){
            Throw "Azure Arc Agent not installed"
        }    
    }
    Process{
        Try{
            $ConfigurationFileContent = Get-Content -Raw -Path "C:\ProgramData\AzureConnectedMachineAgent\Config\localconfig.json" -ErrorAction Stop | ConvertFrom-Json

            $ConfigurationFileHash = [ordered]@{}
            $ConfigurationFileContent.psobject.properties | Sort-Object -Property Name | 
            ForEach-Object { $ConfigurationFileHash[$((Get-Culture).TextInfo.ToTitleCase($PSItem.Name))] = $PSItem.Value }
            
            Return $ConfigurationFileHash
        }
        Catch{
            $Error[0]
        }
    }
    End{}
}

Function Get-AzureArcNodeAgentInstalledExtensions
{
<#
.Synopsis
   Prints out local Azure Arc Agent installed exentsions
.DESCRIPTION
   Prints out local Azure Arc Agent installed exentsions
.EXAMPLE
   Get-AzureArcNodeAgentInstalledExtensions
#>    
   Begin{

        $AZCMAGENTLocation = "C:\Program Files\AzureConnectedMachineAgent\azcmagent.exe"
        If(!(Test-Path -Path $AZCMAGENTLocation)){
            Throw "Azure Arc Agent not installed"
        }    
    }
    Process{
        Try{
            If(Test-Path -Path "C:\ProgramData\GuestConfig\extension_logs"){
                $Extensions = Get-ChildItem -Path "C:\ProgramData\GuestConfig\extension_logs"
                foreach($Extension in $Extensions){
                
                    If(Test-Path "$($Extension.FullName)\state.json"){
                        $ExtensionData = Get-Content -Raw -Path "$($Extension.FullName)\state.json" -ErrorAction Stop | ConvertFrom-Json
                        $ExtensionData
                    }

                }
            }
            Else{
                Write-Output -InputObject "No extensions installed yet."
            }

        }
        Catch{
            $Error[0]
        }
    }
    End{}
}
