_This documentation are synced from Franky repo, if you want to change something just do a pull request._

# Setup host
1. Install PowerShell Universal version 2.7 or later
    - https://ironmansoftware.com/downloads
2. Create a service user that will run PowerShell Universal service and change so that user are running PowerShell Universal service in the windows services.
    - https://docs.powershelluniversal.com/config/running-as-a-service-account#configuring-a-powershell-universal-service-to-run-as-the-account
3. Make sure that that service account has the right permissions for the AD, WinRM, CIM etc.
4. Make sure that you have the ActiveDirectory module installed
    - https://docs.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps
5. Install the ImportExcel module version 7.4.1 or later 
    - Open Powershell and type: Install-Module ImportExcel -Force
    - If you have the module installed just write Update-Module to make sure that you have the latest
6. Now you need to open and change the appsettings.json file that you can find C:\ProgramData\PowerShellUniversal
    - At line 5 "Url" here you need to change too full FQDN for the server and ending with :port for example: franky.se:443
    - You need to do the same as above at line 40 under "API"
    - Here is a example file of how you can activate and use https you can either look at this file in the repo appsettings-example.json or this link https://www.keepcodeopen.com/example-file-appsettings-json/
    - Here is some more information you can read: https://docs.powershelluniversal.com/config/hosting
6. Make sure that you have opend the right ports in Windows firewall for PowerShell Universal
6. Copy all of the folders from this repo to C:\ProgramData\UniversalAutomation\Repository\ can downoad it from
    - https://github.com/KeepCodeOpen/Franky
    - https://www.keepcodeopen.com/download-franky/
7. When that's done restart the PowerShell Universal service.

# Change settings in .ps1 files
Before we begin with this it's some simple steps you need to do.
1. Create an AD group where you can add all role groups (nesting) that should have access to Franky for example "Franky.Access"
2. Create an AD group that are named "Franky" that group will give all members of it access to the Franky role.
3. It's recommended that you create a group for the standard roles for PowerShell Universal also but no need to add any members in them. This is just so not someone can login as that role.
4. Create the follwoing groups: PSU.PowerUser , PSU.Operator , PSU.Administrator , PSU.Execute , PSU.Reader
5. Add all of the groups that you created in 4. and also the Franky group to the group Franky.Access
5. Add the user that you want to use to administrate PowerShell Universal to PSU.Administrator and Franky group.

## authentication.ps1
1. At row 9 Change $CurrentDomain to your own LDAP path for example; "LDAP://DC=FR,DC=SE"
2. At row 23 you should change the 'xxx' to the ID for your own access group that can access PSU. In this example it's the Franky.Access group that you created earlier.

## roles.ps1
1. At row 3 change $RoleDomain add your domain to it for example LDAP://DC=FR,DC=SE
    - If the variabel above don't work you can just change the $Searcher.SearchRoot to your own LDAP path for example LDAP://DC=FR,DC=SE on every role
2. You need to add the search path for the AD group that you want to dedicate for each role in $Searcher.Filter after MemberOf= in every role.

## Dashboards\Franky\Dashboard.ps1
I'll not specifiy this as it's noted in the dashboard.ps1 file what you should do

# Logging
I have included logging that are stored in Eventlog on the host/s.
Before you activate the logging you need to run the InstallEventLog.ps1 that are loacted under the folder "Installation Scripts" in this repo so all the sources are created.
As default the LogName is set to Franky but if you want to change that just change the $EventLogName variable in both InstallEventLog.ps1 and in the dashboard.ps1 file.

When that's done you just need to change [bool]$ActiveEventLog variable from $false to $true in the dashboard.ps1 file.
As default it's set to $false

# Load Balancing
It's possible to run this dashboard with multiple hosts and use git for it if you follow the process below.
It's also working if you have a VIP address and then attach the hosts to the VIP address.

1. In PSU admin on each host create an AppToken. If you set an experation date on the AppToken remember that date as it will stop working after that date and then the loadbalancing will also stop working.
    - https://docs.powershelluniversal.com/config/security/app-tokens
2. In the dashboard.ps1 file you should change [bool]$ActivateLoadBalancing to $true
3. Go in to the Component loadbalancing.psm1 file and change the host1 etc. and also add the AppToken for each host.

## VIP address
If your using a VIP address you also need to change in the appsettings.json on each host.

1. Change the http url to the VIP address
2. Change the https url to the VIP address
3. Change the API url to the VIP address
