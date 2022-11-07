# AzureArcConnectedAgentManagement
PowerShell module for Azure Arc Connected Agent. [This module is built over the Azcmagent.exe utility.](https://www.kaidojarvemets.com/azure-arc-enabled-servers-agent/) It allows you to manage, view and troubleshoot the Azure Arc Connected Agent.


#### Version 1.0 commands
* Clear-AzureArcNodeConfiguration<br>
* Connect-AzureArcNode<br>
* Disconnect-AzureArcNode<br>
* Get-AzureArcNodeAgentConfigurationFileContent<br>
* Get-AzureArcNodeAgentInformation<br>
* Get-AzureArcNodeAgentInstalledExtensions<br>
* Get-AzureArcNodeAgentLocalConfigurationFileContent<br>
* Get-AzureArcNodeConfiguration<br>
* Get-AzureArcNodeServiceStatus<br>
* Install-AzureArcAgent<br>
* Restart-AzureArcNodeService<br>
* Save-AzureArcNodeLogs<br>
* Set-AzureArcNodeConfiguration<br>
* Test-AzureArcNodeConnection<br>
* Test-AzureArcNodeNetworkConnectivity<br>

### How to install AzureArcConnectedAgentManagement Module
* Open PowerShell as an administrator and run the following command:
  * <b>Install-Module -Name AzureArcConnectedAgentManagement</b><br>
* After the installation, print out all the commands using the following command
  * <b>Get-Command -Module AzureArcConnectedAgentManagement</b>

Read more from - https://www.kaidojarvemets.com/getting-started-with-azurearcconnectedagentmanagement-powershell-module/
