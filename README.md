# Franky!
Franky is the ultimate IT-Support dashboard developed for PowerShell Universal and it's an open source project under GNU General Public License version 3.  
Franky is developed by KeepCodeOpen, KeepCodeOpen is a nonprofit organization.  
  
What's Franky? <https://www.keepcodeopen.com/whats-franky/>  
How to install <https://www.keepcodeopen.com/franky-installation-instructions/>  
How to upgrade <https://www.keepcodeopen.com/how-to-upgrade-franky/>  
To see our roadmap visit: <https://www.keepcodeopen.com/franky-public-roadmap/>  
  
For more information how to use some of our functions visit <https://keepcodeopen.com>  
  
For more information visit <https://keepcodeopen.com>  

## Version 1.0 Beta 2 2022-02-04

### New functions
- Generate report over disabled computer objects
- Generate report over locked out users
- Generate report over Users password has expired
- Generate report over disabled users
- Generate report over empty groups
- Generate report over AccountExpired
- Generate report over empty groups
- Bulk add users/groups/computers to group

### Updated functions
- Added CSV as a export option

### Bug fixes
- Fixed typos
- Fixed so generated password will autofyll in the password fields

### Other
I have done it easier to upgrade Franky now.  
What I have done is that I have moved many of the variables that are static to the variables.ps1 file instead of the dashboard.ps1.  
I have also made a upgrade manual, you can find it under Docs/Instructions here in the repo or at this link:  
<https://www.keepcodeopen.com/how-to-upgrade-franky/>

### Important
We have done updates in variables.ps1, environments.ps1, publishedFolders.ps1 and dashboards.ps1 in the .universal folder.  
Also we have done modifications in the dashboard.ps1 under the Dashboards folder.  
Make sure that you take a look at the changes and add it to your own configuration.

# Public roadmap
| Status | Goal | Labels | Repository or release |
| :---: | :--- | --- | --- |
| ✅ | [Public beta 1 release]() |`Done`| <https://github.com/KeepCodeOpen/Franky/releases/tag/v1.0-Beta1> |
| ✅ | [Public beta 2 release]() |`Done`| <https://github.com/KeepCodeOpen/Franky/releases/tag/v1.0-Beta1> |
| 🚀 | [Work with the issues in repo and add more features from it]() |`in progress`| <https://github.com/KeepCodeOpen/Franky/issues> |
| 🚀 | [Integrate AzureAD]() | | |
| 🚀 | [Integrate Hyper-V]() | | |
| 🚀 | [Integrate Exchange Online]() | | |
| 🚀 | [Integrate M/O 365]() | | |
| 🚀 | [Integrate VMWare Horizon]() | | |
| 🚀 | [Integrate VMWare DEM]() |`in progress`| |
| 🚀 | [Integrate VMWare Workspace]() | | |
| 🚀 | [Integrate VMWare vSphere]() |`in progress`| |  
  
Note, This features can run on hosts that are Linux, macOS, Windows and docker. The only thing is that AzureAD module are not working with ARM yet.  