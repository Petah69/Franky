<#
    Copyright (C) 2022  KeepCodeOpen - The ultimate IT-Support dashboard
    <https://keepcodeopen.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
#>

New-UDGrid -Spacing '1' -Container -Content {
    New-UDGrid -Item -Size 1 -Content { }
    New-UDGrid -Item -Size 10 -Content {
        New-UDGrid -Spacing '1' -Container -Content {
            New-UDGrid -Item -Size 3 -Content {
                New-UDTextbox -Id "txtComputerNameStart" -Icon (New-UDIcon -Icon 'desktop') -Label "Computer name (Wildcard *)" -FullWidth
            }
            New-UDGrid -Item -Size 3 -Content {
                New-UDButton -Icon (New-UDIcon -Icon 'search') -Size large -OnClick {
                    $ComputerName = (Get-UDElement -Id "txtComputerNameStart").value

                    if ([string]::IsNullOrEmpty($ComputerName)) {
                        Sync-UDElement -Id 'ComputerSearchStart'
                    }
                    elseif ($ComputerName.EndsWith('*')) {
                        New-MultiSearch -ActiveEventLog $ActiveEventLog -SearchFor $ComputerName -txtBoxMultiSearch "txtComputerNameStart" -MultiSearchObj "Computer" -ElementSync 'ComputerSearchStart'
                    }
                    else {
                        Sync-UDElement -Id 'ComputerSearchStart'
                    }
                }
            }
            New-UDGrid -Item -Size 6 -Content { }
        }
    }
    New-UDGrid -Item -Size 1 -Content { }
}

New-UDGrid -Spacing '1' -Container -Content {
    New-UDGrid -Item -Size 1 -Content { }
    New-UDGrid -Item -Size 10 -Content {
        New-UDCard -Content {
            New-UDDynamic -Id 'ComputerSearchStart' -content {
                New-UDGrid -Spacing '1' -Container -Content {
                    $ComputerName = (Get-UDElement -Id "txtComputerNameStart").value
                    if ($NULL -ne $ComputerName) {
                        $ComputerName = $ComputerName.trim()
                    }

                    if ([string]::IsNullOrEmpty($ComputerName)) {
                        New-UDGrid -Item -Size 12 -Content {
                            New-UDAlert -Severity 'error' -Text "You must enter a computername!"
                        }
                    }
                    else {
                        $SearchComputerSam = $(try { Get-ADComputer -Filter "samaccountname -eq '$($ComputerName)$'" -properties SamAccountName, Name } catch { $Null })
                        $SearchComputerName = $(try { Get-ADComputer -Filter "Name -eq '$($ComputerName)'" -properties SamAccountName, Name } catch { $Null })
                        $SearchComputerDisplayName = $(try { Get-ADComputer -Filter "DisplayName -eq '$($ComputerName)'" -properties SamAccountName, Name, DisplayName } catch { $Null })
                        $SearchComputerFQDN = $(try { Get-ADComputer -Filter "DNSHostName -eq '$($ComputerName)'" -properties DNSHostName, samaccountname, name } catch { $Null })

                        if ($Null -ne $SearchComputerName) {
                            $ComputerName = $SearchComputerName.samaccountname -replace ".$"
                            $ConvertToComputerName = $SearchComputerName.name
                            $SearchFor = $SearchComputerName.name
                        }
                        elseif ($Null -ne $SearchComputerSam) {
                            $ComputerName = $SearchComputerSam.samaccountname -replace ".$"
                            $ConvertToComputerName = $SearchComputerSam.name
                            $SearchFor = $SearchComputerSam.samaccountname
                        }
                        elseif ($NULL -ne $SearchComputerDisplayName) {
                            $ComputerName = $SearchComputerDisplayName.samaccountname -replace ".$"
                            $ConvertToComputerName = $SearchComputerDisplayName.name
                            $SearchFor = $SearchComputerDisplayName.DisplayName
                        }
                        elseif ($Null -ne $SearchComputerFQDN) {
                            $ComputerName = $SearchComputerFQDN.samaccountname -replace ".$"
                            $ConvertToComputerName = $SearchComputerFQDN.name
                            $SearchFor = $SearchComputerFQDN.DNSHostName
                        }

                        if ($Null -ne $SearchFor) { 
                            if ($ActiveEventLog -eq "True") {
                                Write-EventLog -LogName $EventLogName -Source "ComputerSearch" -EventID 10 -EntryType Information -Message "$($User) did search for $($ComputerName)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                            }
                            New-UDDynamic -Id 'ComputerSearch' -content {
                                if (Test-WSMan -ComputerName $ConvertToComputerName -ErrorAction SilentlyContinue) {
                                    $SystInfo = Get-SysInfo -Computer $ConvertToComputerName                                  
                                }
                                else {
                                    $SystInfo = ""
                                    New-UDGrid -Item -Size 12 -Content {
                                        New-UDAlert -Severity 'error' -Text "Could not establish a connection to $($ConvertToComputerName), the administrating options are limited!"
                                    }
                                }
                                $SearchADComputer = Get-ADComputer -Filter "samaccountname -eq '$($ComputerName)$'"  -Properties CN, DisplayName, DNSHostName, OperatingSystem, Description, CanonicalName, DistinguishedName, Created, SamAccountName, OperatingSystemVersion, whenChanged, SID, IPv4Address, IPv6Address, PrimaryGroup, ManagedBy, Location, Enabled, LastLogonDate
                                New-UDGrid -Item -Size 12 -Content {
                                    Disconnect-UserFromComputer -EventLogName $EventLogName -ActiveEventLog $ActiveEventLog -Computer $ConvertToComputerName -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                    Restart-ADComputer -EventLogName $EventLogName -ActiveEventLog $ActiveEventLog -Computer $ConvertToComputerName -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                    Ping-ADComputer -EventLogName $EventLogName -ActiveEventLog $ActiveEventLog -Computer $ConvertToComputerName -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                    Show-MonitorInfoBtn -EventLogName $EventLogName -ActiveEventLog $ActiveEventLog -Computer $ConvertToComputerName -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                    Compare-ComputerGrpsBtn -EventLogName $EventLogName -ActiveEventLog $ActiveEventLog -Computer $ComputerName -YourFullDomain $YourFullDomain -RefreshOnClose "ComputerSearchGroupList" -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                    Remove-UserProfilesBtn -EventLogName $EventLogName -ActiveEventLog $ActiveEventLog -Computer $ConvertToComputerName -YourDomain $YourDomain.ToUpper() -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                    Remove-EdgeSettings -EventLogName $EventLogName -ActiveEventLog $ActiveEventLog -Computer $ConvertToComputerName -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                    Show-ProcessTableBtn -EventLogName $EventLogName -ActiveEventLog $ActiveEventLog -Computer $ConvertToComputerName -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                    Show-ServicesTableBtn -EventLogName $EventLogName -ActiveEventLog $ActiveEventLog -Computer $ConvertToComputerName -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                    Show-NetAdpBtn -EventLogName $EventLogName -ActiveEventLog $ActiveEventLog -Computer $ConvertToComputerName -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                    Show-SchedualTaskTableBtn -EventLogName $EventLogName -ActiveEventLog $ActiveEventLog -Computer $ConvertToComputerName -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                    Show-InstalledDriversBtn -EventLogName $EventLogName -ActiveEventLog $ActiveEventLog -Computer $ConvertToComputerName -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                    Show-AutostartTableBtn -EventLogName $EventLogName -ActiveEventLog $ActiveEventLog -Computer $ConvertToComputerName -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                    Show-InstalledSoftwareBtn -EventLogName $EventLogName -ActiveEventLog $ActiveEventLog -Computer $ConvertToComputerName -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                    Remove-ADObjectBtn -RefreshOnClose "ComputerSearchStart" -EventLogName $EventLogName -ActiveEventLog $ActiveEventLog -ObjectType "Computer" -ObjectName $ComputerName -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                    if (-Not([string]::IsNullOrEmpty($AppToken))) {
                                        Remove-TempFilesClientBtn -CurrentHost $CurrentHost -AppToken $AppToken -RefreshOnClose "ComputerSearch" -Computer $ConvertToComputerName -EventLogName $EventLogName -ActiveEventLog $ActiveEventLog -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                    }
                                    New-RefreshUDElementBtn -RefreshUDElement 'ComputerSearch'
                                }
                                New-UDGrid -Item -Size 12 -Content {
                                    New-UDHTML -Markup "</br>"
                                }
                                New-UDGrid -Item -Size 12 -Content {
                                    New-UDHtml -Markup "<b>Information about $($ComputerName)</b>"
                                }
                                New-UDGrid -Item -Size 4 -Content {
                                    New-UDTypography -Text "Enabled?"
                                }
                                New-UDGrid -Item -Size 6 -Content {
                                    New-UDTypography -Text "$($SearchADComputer.Enabled)"
                                }
                                New-UDGrid -Item -Size 2 -Content {
                                    Set-EnableDisableADAccountBtn -CurrentDescription $SearchADComputer.Description -ObjectStatus $SearchADComputer.Enabled -ObjectToChange "Computer" -EventLogName $EventLogName -ActiveEventLog $ActiveEventLog -RefreshOnClose "ComputerSearch" -ObjectName $ComputerName -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                }
                                New-UDGrid -Item -Size 4 -Content {
                                    New-UDTypography -Text "Display name"
                                }
                                New-UDGrid -Item -Size 6 -Content {
                                    New-UDTypography -Text "$($SearchADComputer.DisplayName)"
                                }
                                New-UDGrid -Item -Size 2 -Content {
                                    Rename-ADObjectBtn -BoxToSync "txtComputerNameStart" -EventLogName $EventLogName -WhatToChange "DisplayName" -ActiveEventLog $ActiveEventLog -RefreshOnClose "ComputerSearchStart" -CurrentValue $SearchADComputer.DisplayName -ObjectToRename 'Computer' -ObjectName $ComputerName -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                }
                                New-UDGrid -Item -Size 4 -Content {
                                    New-UDTypography -Text "CN name"
                                }
                                New-UDGrid -Item -Size 6 -Content {
                                    New-UDTypography -Text "$($SearchADComputer.CN)"
                                }
                                New-UDGrid -Item -Size 2 -Content {
                                    Rename-ADObjectBtn -BoxToSync "txtComputerNameStart" -EventLogName $EventLogName -WhatToChange "CN" -ActiveEventLog $ActiveEventLog -RefreshOnClose "ComputerSearchStart" -CurrentValue $SearchADComputer.CN -ObjectToRename 'Computer' -ObjectName $ComputerName -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                }
                                New-UDGrid -Item -Size 4 -Content {
                                    New-UDTypography -Text "SamAccountName"
                                }
                                New-UDGrid -Item -Size 6 -Content {
                                    New-UDTypography -Text "$($SearchADComputer.SamAccountName)"
                                }
                                New-UDGrid -Item -Size 2 -Content {
                                    Rename-ADObjectBtn -BoxToSync "txtComputerNameStart" -EventLogName $EventLogName -WhatToChange "SamAccountName" -ActiveEventLog $ActiveEventLog -RefreshOnClose "ComputerSearchStart" -CurrentValue $SearchADComputer.SamAccountName -ObjectToRename 'Computer' -ObjectName $ComputerName -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                }
                                New-UDGrid -Item -Size 4 -Content {
                                    New-UDTypography -Text "Description"
                                }
                                New-UDGrid -Item -Size 6 -Content {
                                    New-UDTypography -Text "$($SearchADComputer.Description)"
                                }
                                New-UDGrid -Item -Size 2 -Content { 
                                    Edit-DescriptionBtn -EventLogName $EventLogName -ActiveEventLog $ActiveEventLog -RefreshOnClose "ComputerSearch" -CurrentValue $SearchADComputer.Description -ChangeDescriptionObject 'Computer' -ChangeObjectName $ComputerName -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                }
                                New-UDGrid -Item -Size 4 -Content {
                                    New-UDTypography -Text "SID"
                                }
                                New-UDGrid -Item -Size 6 -Content {
                                    New-UDTypography -Text "$($SearchADComputer.SID)"
                                }
                                New-UDGrid -Item -Size 2 -Content { }
                                New-UDGrid -Item -Size 4 -Content {
                                    New-UDTypography -Text "OU Placement"
                                }
                                New-UDGrid -Item -Size 6 -Content {
                                    New-UDTypography -Text "$($SearchADComputer.DistinguishedName)"
                                }
                                New-UDGrid -Item -Size 2 -Content {
                                    Move-ADObjectBtn -EventLogName $EventLogName -ActiveEventLog $ActiveEventLog -RefreshOnClose "ComputerSearch" -CurrentValue $SearchADComputer.DistinguishedName -ObjectToMove 'Computer' -ComputerName $ComputerName -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                }
                                New-UDGrid -Item -Size 4 -Content {
                                    New-UDTypography -Text "Location"
                                }
                                New-UDGrid -Item -Size 6 -Content {
                                    New-UDTypography -Text "$($SearchADComputer.Location)"
                                }
                                New-UDGrid -Item -Size 2 -Content { }
                                New-UDGrid -Item -Size 4 -Content {
                                    New-UDTypography -Text "Primary Group"
                                }
                                New-UDGrid -Item -Size 6 -Content {
                                    $ConvertPrimaryGroup = $(try { $SearchADComputer.PrimaryGroup | ForEach-Object { $_.Replace("CN=", "").Split(",") | Select-Object -First 1 } } catch { $null })
                                    if ($null -ne $ConvertPrimaryGroup) {
                                        New-UDTypography -Text "$($ConvertPrimaryGroup)"
                                    }
                                }
                                New-UDGrid -Item -Size 2 -Content { }
                                New-UDGrid -Item -Size 4 -Content {
                                    New-UDTypography -Text "Managed By"
                                }
                                New-UDGrid -Item -Size 6 -Content {
                                    $ComputerManagedBy = $(try { $SearchADComputer.ManagedBy | ForEach-Object { $_.Replace("CN=", "").Split(",") | Select-Object -First 1 } } catch { $null })
                                    if ($null -ne $ComputerManagedBy) {
                                        New-UDTypography -Text "$($ComputerManagedBy)"
                                    }
                                }
                                New-UDGrid -Item -Size 2 -Content {
                                    $ComputerManagedBy = $(try { $SearchADComputer.ManagedBy | ForEach-Object { $_.Replace("CN=", "").Split(",") | Select-Object -First 1 } } catch { $null })
                                    Edit-ManagedByBtn -CurrentValue $ComputerManagedBy -ObjectType "Computer" -ObjectName $ComputerName -RefreshOnClose "ComputerSearch" -EventLogName $EventLogName -ActiveEventLog $ActiveEventLog -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                }
                                New-UDGrid -Item -Size 4 -Content {
                                    New-UDTypography -Text "Object was created"
                                }
                                New-UDGrid -Item -Size 6 -Content {
                                    New-UDTypography -Text "$($SearchADComputer.Created)"
                                }
                                New-UDGrid -Item -Size 2 -Content { }
                                New-UDGrid -Item -Size 4 -Content {
                                    New-UDTypography -Text "Object was last changed"
                                }
                                New-UDGrid -Item -Size 6 -Content {
                                    New-UDTypography -Text "$($SearchADComputer.whenChanged)"
                                }
                                New-UDGrid -Item -Size 2 -Content { }
                                New-UDGrid -Item -Size 4 -Content {
                                    New-UDTypography -Text "Last seen in the domain"
                                }
                                New-UDGrid -Item -Size 6 -Content {
                                    $GetLastDate = Get-ADLastSeen -ObjectName $ComputerName -ObjectType "Computer"
                                    New-UDTypography -Text "$($GetLastDate)"
                                }
                                New-UDGrid -Item -Size 2 -Content { }

                                New-UDGrid -Item -Size 12 -Content {
                                    New-UDHtml -Markup "</br>"
                                    New-UDHtml -Markup "<B>OS information</b>"
                                    New-UDTransition -Id 'OSInformation' -Content {
                                        New-UDGrid -Spacing '1' -Container -Content {
                                            New-UDGrid -Item -Size 12 -Content {
                                                New-UDHtml -Markup "</br>"
                                            }
                                            New-UDGrid -Item -Size 4 -Content {
                                                New-UDTypography -Text "Version"
                                            }
                                            New-UDGrid -Item -Size 6 -Content {
                                                New-UDTypography -Text "$($SearchADComputer.OperatingSystem) Version: $($SearchADComputer.OperatingSystemVersion)"
                                            }
                                            New-UDGrid -Item -Size 2 -Content { }
                                            New-UDGrid -Item -Size 4 -Content {
                                                New-UDTypography -Text "Installation date"
                                            }
                                            New-UDGrid -Item -Size 6 -Content {
                                                if ([string]::IsNullOrEmpty($SystInfo)) {
                                                    New-UDTypography -Text "N/A"
                                                }
                                                else {
                                                    New-UDTypography -Text "$($SystInfo.OS.InstallDate)"
                                                }
                                            }
                                            New-UDGrid -Item -Size 2 -Content { }
                                            New-UDGrid -Item -Size 4 -Content {
                                                New-UDTypography -Text "Up-Time"
                                            }
                                            New-UDGrid -Item -Size 6 -Content {
                                                if ([string]::IsNullOrEmpty($SystInfo)) {
                                                    New-UDTypography -Text "N/A"
                                                }
                                                else {
                                                    New-UDTypography -Text "$($SystInfo.UpTime.days) Days $($SystInfo.UpTime.hours) h $($SystInfo.UpTime.minutes) min"
                                                }
                                            }
                                            New-UDGrid -Item -Size 2 -Content { }
                                            New-UDGrid -Item -Size 4 -Content {
                                                New-UDTypography -Text "Current logged in user"
                                            }
                                            New-UDGrid -Item -Size 6 -Content {
                                                if (([string]::IsNullOrEmpty($SystInfo.Computer.UserName))) {
                                                    New-UDTypography -Text "No user are logged in"
                                                }
                                                else {
                                                    New-UDTypography -Text "$($SystInfo.Computer.UserName)"
                                                }
                                            }
                                            New-UDGrid -Item -Size 2 -Content { }
                                            New-UDGrid -Item -Size 4 -Content {
                                                New-UDTypography -Text "Last logged in user"
                                            }
                                            New-UDGrid -Item -Size 6 -Content {
                                                if ([string]::IsNullOrEmpty($SystInfo)) {
                                                    New-UDTypography -Text "N/A"
                                                }
                                                else {
                                                    $LastLoggedOn = Get-WinEvent -Computer $ConvertToComputerName -FilterHashtable @{Logname = 'Security'; ID = 4672 } -MaxEvents 1 | Select-Object @{N = 'User'; E = { $_.Properties[1].Value } }, TimeCreated
                                                    New-UDTypography -Text "$($LastLoggedOn.User) ($($LastLoggedOn.TimeCreated))"
                                                }
                                            }
                                            New-UDGrid -Item -Size 2 -Content { }
                                        }
                                    } -Collapse -CollapseHeight 100 -Timeout 1000
                                }

                                New-UDSwitch -OnChange {
                                    Set-UDElement -Id 'OSInformation' -Properties @{
                                        in = $EventData -eq 'true'
                                    } 
                                }

                                New-UDGrid -Item -Size 12 -Content {
                                    New-UDHtml -Markup "<B>Hardware information</b>"
                                    New-UDTransition -Id 'HardwareInformation' -Content {
                                        New-UDGrid -Spacing '1' -Container -Content {
                                            New-UDGrid -Item -Size 12 -Content {
                                                New-UDHtml -Markup "</br>"
                                            }
                                            New-UDGrid -Item -Size 4 -Content {
                                                New-UDTypography -Text "Manufacturer"
                                            }
                                            New-UDGrid -Item -Size 6 -Content {
                                                if ([string]::IsNullOrEmpty($SystInfo)) {
                                                    New-UDTypography -Text "N/A"
                                                }
                                                else {
                                                    New-UDTypography -Text "$($SystInfo.Computer.Manufacturer)"
                                                }
                                            }
                                            New-UDGrid -Item -Size 2 -Content { }
                                            New-UDGrid -Item -Size 4 -Content {
                                                New-UDTypography -Text "Model"
                                            }
                                            New-UDGrid -Item -Size 6 -Content {
                                                if ([string]::IsNullOrEmpty($SystInfo)) {
                                                    New-UDTypography -Text "N/A"
                                                }
                                                else {
                                                    New-UDTypography -Text "$($SystInfo.Computer.SystemFamily)"
                                                }
                                            }
                                            New-UDGrid -Item -Size 2 -Content {
                                                if ([string]::IsNullOrEmpty($SystInfo)) {
                                                    New-UDTypography -Text "N/A"
                                                }
                                                else {
                                                    New-UDTypography -Text "$($SystInfo.Computer.Model)"
                                                }
                                            }
                                            New-UDGrid -Item -Size 4 -Content {
                                                New-UDTypography -Text "Serial number"
                                            }
                                            New-UDGrid -Item -Size 6 -Content {
                                                if ([string]::IsNullOrEmpty($SystInfo)) {
                                                    New-UDTypography -Text "N/A"
                                                }
                                                else {
                                                    New-UDTypography -Text "$($SystInfo.BIOS.SerialNumber)"
                                                }
                                            }
                                            New-UDGrid -Item -Size 2 -Content { }
                                            New-UDGrid -Item -Size 4 -Content {
                                                New-UDTypography -Text "Bios Version"
                                            }
                                            New-UDGrid -Item -Size 6 -Content {
                                                if ([string]::IsNullOrEmpty($SystInfo)) {
                                                    New-UDTypography -Text "N/A"
                                                }
                                                else {
                                                    New-UDTypography -Text "$($SystInfo.BIOS.BIOSVersion)"
                                                }
                                            }
                                            New-UDGrid -Item -Size 2 -Content { }
                                            New-UDGrid -Item -Size 4 -Content {
                                                New-UDTypography -Text "RAM"
                                            }
                                            New-UDGrid -Item -Size 6 -Content {
                                                if ([string]::IsNullOrEmpty($SystInfo)) {
                                                    New-UDTypography -Text "N/A"
                                                }
                                                else {
                                                    New-UDTypography -Text "$($SystInfo.RAM)GB"
                                                }
                                            }
                                            New-UDGrid -Item -Size 2 -Content { }
                                            New-UDGrid -Item -Size 4 -Content {
                                                New-UDTypography -Text "C:"
                                            }
                                            New-UDGrid -Item -Size 6 -Content { 
                                                if ([string]::IsNullOrEmpty($SystInfo)) {
                                                    New-UDTypography -Text "N/A"
                                                }
                                                else {
                                                    New-UDTypography -Text "$($SystInfo.HDD.Free)GB free of $($SystInfo.HDD.total)GB"
                                                }
                                            }
                                            New-UDGrid -Item -Size 2 -Content { }
                                        }
                                    } -Collapse -CollapseHeight 100 -Timeout 1000
                                }

                                New-UDSwitch -OnChange {
                                    Set-UDElement -Id 'HardwareInformation' -Properties @{
                                        in = $EventData -eq 'true'
                                    } 
                                }


                                New-UDGrid -Item -Size 12 -Content {
                                    New-UDHtml -Markup "<B>Network information</b>"
                                    New-UDTransition -Id 'NetworkInformation' -Content {
                                        New-UDGrid -Spacing '1' -Container -Content {
                                            New-UDGrid -Item -Size 12 -Content {
                                                New-UDHtml -Markup "</br>"
                                            }
                                            New-UDGrid -Item -Size 4 -Content {
                                                New-UDTypography -Text "DNS/Hostname"
                                            }
                                            New-UDGrid -Item -Size 6 -Content {
                                                New-UDTypography -Text "$($SearchADComputer.DNSHostName)"
                                            }
                                            New-UDGrid -Item -Size 2 -Content { }
                                            New-UDGrid -Item -Size 4 -Content {
                                                New-UDTypography -Text "IPv4 Address"
                                            }
                                            New-UDGrid -Item -Size 6 -Content {
                                                New-UDTypography -Text "$($SearchADComputer.IPv4Address)"
                                            }
                                            New-UDGrid -Item -Size 2 -Content { }
                                            New-UDGrid -Item -Size 4 -Content {
                                                New-UDTypography -Text "IPv6 Address"
                                            }
                                            New-UDGrid -Item -Size 6 -Content {
                                                New-UDTypography -Text "$($SearchADComputer.IPv6Address)"
                                            }
                                            New-UDGrid -Item -Size 2 -Content { }
                                            New-UDGrid -Item -Size 4 -Content {
                                                New-UDTypography -Text "MAC address"
                                            }
                                            New-UDGrid -Item -Size 6 -Content {
                                                if ([string]::IsNullOrEmpty($SystInfo)) {
                                                    New-UDTypography -Text "N/A"
                                                }
                                                else {
                                                    New-UDTypography -Text "$($SystInfo.NetworkMac)"
                                                }
                                            }
                                            New-UDGrid -Item -Size 2 -Content { }
                                        }
                                    } -Collapse -CollapseHeight 100 -Timeout 1000
                                }

                                New-UDSwitch -OnChange {
                                    Set-UDElement -Id 'NetworkInformation' -Properties @{
                                        in = $EventData -eq 'true'
                                    } 
                                }

                                New-UDGrid -Item -Size 12 -Content {
                                    New-UDHTML -Markup "</br>"
                                }
                            } -LoadingComponent {
                                New-UDProgress -Circular
                            }
                            New-UDDynamic -Id 'ComputerSearchGroupList' -content {
                                $SearchComputerGroup = (Get-ADComputer -Filter "samaccountname -eq '$($ComputerName)$'"  -Properties memberOf | Select-Object -ExpandProperty memberOf) | ForEach-Object { $_.Replace("CN=", "").Split(", ") | Select-Object -First 1 }
                                $SearchComputerGroupData = $SearchComputerGroup | Foreach-Object { 
                                    if ($null -ne ($grpComputer = Get-ADGroup -Filter "Name -eq '$($_)'" -Properties samAccountName, info, Description )) {
                                        [PSCustomObject]@{
                                            Name        = $grpComputer.samAccountName
                                            Description = $grpComputer.Description
                                            Info        = $grpComputer.Info
                                        }
                                    }
                                }

                                $SearchComputerGroupColumns = @(
                                    New-UDTableColumn -Property Name -Title "Groupname" -IncludeInExport -IncludeInSearch -DefaultSortColumn
                                    New-UDTableColumn -Property Description -Title "Description" -IncludeInExport -IncludeInSearch
                                )

                                if ([string]::IsNullOrEmpty($SearchComputerGroupData)) {
                                    New-UDGrid -Item -Size 12 -Content {
                                        New-UDAlert -Severity 'info' -Text "$($ComputerName) are not a member of any groups"
                                    }
                                }
                                else {
                                    New-UDGrid -Item -Size 12 -Content {
                                        $SearchComputerOption = New-UDTableTextOption -Search "Search"
                                        New-UDTable -Id 'ComputerSearchTable' -Data $SearchComputerGroupData -Columns $SearchComputerGroupColumns -DefaultSortDirection "Ascending" -TextOption $SearchComputerOption -ShowSearch -ShowPagination -Dense -Export -ExportOption "xlsx, PDF" -Sort -PageSize 10 -PageSizeOptions @(10, 20, 30, 40, 50) -ShowSelection
                                    }
                                    New-UDGrid -Item -Size 5 -Content {
                                        New-UDTooltip -TooltipContent {
                                            New-UDTypography -Text "Remove $($ComputerName) from the selected groups"
                                        } -content { 
                                            New-UDButton -Icon (New-UDIcon -Icon trash_alt) -Size large -OnClick {
                                                $ComputerSearchTable = Get-UDElement -Id "ComputerSearchTable"
                                                $ComputerSearchLog = @($ComputerSearchTable.selectedRows.name)
                                                if ($Null -ne $ComputerSearchTable.selectedRows.name) {                  
                                                    try {
                                                        @($ComputerSearchTable.selectedRows.name.ForEach( { 
                                                                    Remove-ADGroupMember -Identity $_ -Members "$($ComputerName)$"  -Confirm:$False
                                                                    if ($ActiveEventLog -eq "True") {
                                                                        Write-EventLog -LogName $EventLogName -Source "RemoveFromGroup" -EventID 10 -EntryType Information -Message "$($User) did remove $($ComputerName) from $($_)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                                                    }
                                                                } ) )
                                                        Show-UDToast -Message "$($ComputerName) are not a member of $($ComputerSearchLog -join ",") anymore!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                        Sync-UDElement -Id 'ComputerSearchGroupList'
                                                    }
                                                    catch {
                                                        Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                        Break
                                                    }
                                                }
                                                else {
                                                    Show-UDToast -Message "You have not selected any group!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                    Break
                                                }
                                            }
                                        }
                                    }
                                    New-UDGrid -Item -Size 1 -Content { }
                                }
                                New-UDGrid -Item -Size 3 -Content { 
                                    New-UDTextbox -Id "txtSearchComputerADD" -Icon (New-UDIcon -Icon 'users') -Label "Enter group name" -FullWidth
                                }
                                New-UDGrid -Item -Size 3 -Content { 
                                    New-UDTooltip -TooltipContent {
                                        New-UDTypography -Text "Add $($ComputerName) to the group"
                                    } -content { 
                                        New-UDButton -Icon (New-UDIcon -Icon user_plus) -size large -Onclick { 
                                            $SearchComputerADGroup = (Get-UDElement -Id "txtSearchComputerADD").value
                                            $SearchComputerADGroup = $SearchComputerADGroup.trim()

                                            if (Get-ADGroup -Filter "samaccountname -eq '$($SearchComputerADGroup)'" ) {
                                                try {
                                                    Add-ADGroupMember -Identity $SearchComputerADGroup -Members "$($ComputerName)$" 
                                                    Show-UDToast -Message "$($ComputerName) are now a member of $($SearchComputerADGroup)!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                    Sync-UDElement -Id 'ComputerSearchGroupList'
                                                    if ($ActiveEventLog -eq "True") {
                                                        Write-EventLog -LogName $EventLogName -Source "AddToGroup" -EventID 10 -EntryType Information -Message "$($User) did add $($ComputerName) to $($SearchComputerADGroup)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                                    }
                                                }
                                                catch {
                                                    Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                    Break
                                                }
                                            }
                                            else {
                                                Show-UDToast -Message "Can't find $($SearchComputerADGroup) in the AD!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Break
                                            }
                                        }
                                    }
                                    Add-MultiGroupBtn -RefreshOnClose "ComputerSearchGroupList" -EventLogName $EventLogName -ActiveEventLog $ActiveEventLog -ObjToAdd "$($ComputerName)$" -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                                }
                            } -LoadingComponent {
                                New-UDProgress -Circular
                            }
                        }
                        else { 
                            New-UDGrid -Item -Size 12 -Content {
                                New-UDAlert -Severity 'error' -Text "Could not find $($ComputerName) in the AD!"
                            }
                        }
                    }
                }
            } -LoadingComponent {
                New-UDProgress -Circular
            }
        }
    }
    New-UDGrid -Item -Size 1 -Content { }
}