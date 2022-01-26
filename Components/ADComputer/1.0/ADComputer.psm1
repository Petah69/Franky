﻿<#
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

Function Show-MonitorInfoBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][bool]$ActiveEventLog,
        [Parameter(Mandatory)][String]$Computer,
        [Parameter(Mandatory = $false)][string]$EventLogName,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )

    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Show information about connected displays on $($Computer)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon desktop) -size medium -Onclick {
            Show-UDModal -Header { "Monitor information from $Computer" } -Content {
                New-UDDynamic -Id 'DisplayInfo' -content {
                    New-UDGrid -Spacing '1' -Container -Content {
                        if ($ActiveEventLog -eq "True") {
                            Write-EventLog -LogName $EventLogName -Source "ShowMonitorInfo" -EventID 10 -EntryType Information -Message "$($User) did look at monitor info for $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                        }

                        $Columns = @(
                            New-UDTableColumn -Title 'Active' -Property 'Active' -IncludeInExport -IncludeInSearch -DefaultSortColumn
                            New-UDTableColumn -Title 'Manufacturer' -Property 'ManufacturerName' -IncludeInExport -IncludeInSearch -Render {
                                switch ($EventData.ManufacturerName) {
                                    'PHL' { "Philips" }
                                    'SMS' { "Samsung" }
                                    Default { $EventData.UserFriendlyName }
                                }
                            }
                            New-UDTableColumn -Title 'Model' -Property 'UserFriendlyName' -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Title 'Serial Number' -Property 'SerialNumberID' -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Title 'Year Of Manufacture' -Property 'YearOfManufacture' -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Title 'Week Of Manufacture' -Property 'WeekOfManufacture' -IncludeInExport -IncludeInSearch
                        )

                        $DisplayData = Get-CimInstance -ComputerName $Computer -ClassName WmiMonitorID -Namespace root\wmi | Foreach-Object {
                            if ($null -ne $_) {
                                [PSCustomObject]@{
                                    Active            = $_.Active
                                    ManufacturerName  = ($_.Manufacturername | ForEach-Object { [char]$_ }) -join ""
                                    UserFriendlyName  = ($_.UserFriendlyName | ForEach-Object { [char]$_ }) -join ""
                                    SerialNumberID    = ($_.SerialNumberID | ForEach-Object { [char]$_ }) -join ""
                                    YearOfManufacture = $_.YearOfManufacture
                                    WeekOfManufacture = $_.WeekOfManufacture
                                }
                            }
                        }

                        if ([string]::IsNullOrEmpty($DisplayData)) {
                            New-UDGrid -Item -Size 12 -Content {
                                New-UDAlert -Severity 'error' -Text "Could not establish a connection to $($Computer)"
                            }
                        }
                        else {
                            New-UDGrid -Item -Size 12 -Content {
                                $SearchOption = New-UDTableTextOption -Search "Search"
                                New-UDTable -Columns $Columns -Data $DisplayData -DefaultSortDirection "Ascending" -Sort -TextOption $SearchOption -ShowSearch -ShowPagination -Dense -Export -ExportOption "xlsx, PDF" -PageSize 50
                            }
                        }
                    }
                } -LoadingComponent {
                    New-UDProgress -Circular
                }
            } -Footer {
                New-UDButton -Text "Refresh" -OnClick { 
                    Sync-UDElement -id 'DisplayInfo'
                }
                New-UDButton -Text "Close" -OnClick {
                    Hide-UDModal
                }
                                        
            } -FullWidth -MaxWidth 'md' -Persistent
        }
    }
}

function Show-InstalledDriversBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][bool]$ActiveEventLog,
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory = $false)][string]$EventLogName,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )

    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Show installed drivers on $($Computer)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon screwdriver) -size medium -Onclick {
            Show-UDModal -Header { "All installed drivers on $($Computer)" } -Content {
                New-UDDynamic -Id 'DriversData' -content {
                    New-UDGrid -Spacing '1' -Container -Content {
                        if ($ActiveEventLog -eq "True") {
                            Write-EventLog -LogName $EventLogName -Source "ShowInstalledDrivers" -EventID 10 -EntryType Information -Message "$($User) did look at installed drivers for $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                        }
                        $DriversData = Get-CimInstance -Computer $Computer win32_PnpSignedDriver | select-object Description, DeviceClass, DeviceName, DriverDate, DriverProviderName, DriverVersion, Manufacturer | Foreach-Object {
                            if ($null -ne $_) {
                                [PSCustomObject]@{
                                    dManufacturer       = $_.Manufacturer
                                    dDriverProviderName = $_.DriverProviderName
                                    dDeviceName         = $_.DeviceName
                                    dDescription        = $_.Description
                                    dDeviceClass        = $_.DeviceClass
                                    dDriverVersion      = $_.DriverVersion
                                    dDriverDate         = if ($null -eq $_.DriverDate) { (Get-Date -Year 1970 -Month 01 -Day 01).ToShortDateString() } else { $_.DriverDate.ToShortDateString() }
                                }
                            }
                        }

                        $DriversColumns = @(
                            New-UDTableColumn -Property dManufacturer -Title "Manufacturer" -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Property dDriverProviderName -Title "Driver Provider Name" -IncludeInExport -IncludeInSearch -DefaultSortColumn
                            New-UDTableColumn -Property dDeviceName -Title "Device name" -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Property dDescription -Title "Description" -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Property dDeviceClass -Title "Device Class" -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Property dDriverVersion -Title "Version" -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Property dDriverDate -Title "Date" -IncludeInExport -IncludeInSearch
                        )
                        if ([string]::IsNullOrEmpty($DriversData)) {
                            New-UDGrid -Item -Size 12 -Content {
                                New-UDAlert -Severity 'error' -Text "Could not establish a connection to $($Computer)"
                            }
                        }
                        else {
                            New-UDGrid -Item -Size 12 -Content {
                                $SearchOption = New-UDTableTextOption -Search "Search"
                                New-UDTable -Id 'DriversSearchTable' -Data $DriversData -Columns $DriversColumns -DefaultSortDirection "Ascending" -Sort -TextOption $SearchOption -ShowSearch -ShowPagination -Dense -Export -ExportOption "xlsx, PDF" -PageSize 20
                            }
                        }
                    }
                } -LoadingComponent {
                    New-UDProgress -Circular
                }
            } -Footer {
                New-UDButton -Text "Refresh" -OnClick {
                    Sync-UDElement -Id 'DriversData'
                }
                New-UDButton -Text "Close" -Size medium -OnClick {
                    Hide-UDModal
                }
                                        
            } -FullWidth -MaxWidth 'xl' -Persistent
        }
    }
}

Function Get-SysInfo {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][String]$Computer,
        [Parameter(Mandatory = $false)][string]$EventLogName,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )
    try {
        Invoke-Command -ComputerName $Computer -Scriptblock {
            [pscustomobject]@{
                Computer   = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object Manufacturer, Model, SystemFamily, UserName
                OS         = Get-CimInstance -ClassName Win32_OperatingSystem | select-object LastBootUpTime, InstallDate
                UpTime     = (get-date) - (gcim Win32_OperatingSystem).LastBootUpTime | Select-Object days, hours, minutes
                BIOS       = Get-CimInstance -ClassName Win32_BIOS | Select-Object BIOSVersion, SerialNumber
                RAM        = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum).sum / 1gb
                HDD        = Get-CimInstance -ClassName Win32_LogicalDisk | where-object DeviceID -eq "C:" | Select-Object -Property DeviceID, @{'Name' = 'Total'; Expression = { [int]($_.Size / 1GB) } }, @{'Name' = 'Free'; Expression = { [int]($_.FreeSpace / 1GB) } }
                NetworkMac = (Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled = 'True'").MACAddress
            }
        }
    }
    catch {
        New-UDGrid -Item -Size 12 -Content {
            New-UDAlert -Severity 'error' -Text "Could not establish a connection to $($Computer)"
        }
    }
}

function Show-NetAdpBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][bool]$ActiveEventLog,
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory = $false)][string]$EventLogName,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )

    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Show network adapters on $($Computer)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon ethernet) -size medium -Onclick {
            Show-UDModal -Header { "All network adpaters on $Computer" } -Content {
                New-UDDynamic -Id 'AdapterData' -content {
                    New-UDGrid -Spacing '1' -Container -Content {
                        if ($ActiveEventLog -eq "True") {
                            Write-EventLog -LogName $EventLogName -Source "ShowNetworkAdapters" -EventID 10 -EntryType Information -Message "$($User) did look at network adapters for $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                        }
                        $AllAdapters = Get-NetAdapter -Name * -CimSession $Computer | select-object @("Name", "InterfaceDescription", "Status", "LinkSpeed", "MacAddress")

                        $AdaptersColumns = @(
                            New-UDTableColumn -Property Name -Title "Name" -IncludeInExport -IncludeInSearch -DefaultSortColumn
                            New-UDTableColumn -Property InterfaceDescription -Title "Description" -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Property Status -Title "Status" -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Property LinkSpeed -Title "Link Speed" -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Property MacAddress -Title "MAC Address" -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Property Functions -Title '.' -Render {
                                if ($EventData.Status -eq "Up") {
                                    New-UDTooltip -TooltipContent {
                                        New-UDTypography -Text "Disable Network adapter"
                                    } -content { 
                                        New-UDButton -Icon (New-UDIcon -Icon stop) -size small -Onclick {
                                            $AdapterName = $EventData.Name
                                            try {
                                                Invoke-Command -ComputerName $Computer -Scriptblock {
                                                    Param($AdapterName)
                                                    Disable-NetAdapter -Name $AdapterName
                                                } -ArgumentList $AdapterName
                                                if ($ActiveEventLog -eq "True") {
                                                    Write-EventLog -LogName $EventLogName -Source "DisableNetworkAdapter" -EventID 10 -EntryType Information -Message "$($User) did disable network adapter for $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                                }
                                                Show-UDToast -Message "$($EventData.Name) has been disabled!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Sync-UDElement -Id 'AdapterData'
                                            }
                                            catch {
                                                Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Break
                                            }
                                        }
                                    }
                                }
                                else {
                                    New-UDTooltip -TooltipContent {
                                        New-UDTypography -Text "Enable Network adapter"
                                    } -content { 
                                        New-UDButton -Icon (New-UDIcon -Icon play) -size small -Onclick {
                                            $AdapterName = $EventData.Name
                                            try {
                                                Invoke-Command -ComputerName $Computer -Scriptblock {
                                                    Param($AdapterName)
                                                    Enable-NetAdapter -Name $AdapterName
                                                } -ArgumentList $AdapterName
                                                if ($ActiveEventLog -eq "True") {
                                                    Write-EventLog -LogName $EventLogName -Source "EnableNetworkAdapter" -EventID 10 -EntryType Information -Message "$($User) did enable network adapter for $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                                }
                                                Show-UDToast -Message "$($EventData.Name) has been enabled!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Sync-UDElement -Id 'AdapterData'
                                            }
                                            catch {
                                                Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Break
                                            }
                                        }
                                    }
                                }

                                New-UDTooltip -TooltipContent {
                                    New-UDTypography -Text "Restart network adapter"
                                } -content { 
                                    New-UDButton -Icon (New-UDIcon -Icon undo_alt) -size small -Onclick {
                                        $AdapterName = $EventData.Name
                                        try {
                                            Invoke-Command -ComputerName $Computer -Scriptblock {
                                                Param($AdapterName)
                                                Restart-NetAdapter -Name $AdapterName
                                            } -ArgumentList $AdapterName
                                            if ($ActiveEventLog -eq "True") {
                                                Write-EventLog -LogName $EventLogName -Source "RestartNetworkAdapter" -EventID 10 -EntryType Information -Message "$($User) did restart network adapter for $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                            }
                                            Show-UDToast -Message "$($EventData.Name) has been restarted!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                            Sync-UDElement -Id 'AdapterData'
                                        }
                                        catch {
                                            Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                            Break
                                        }
                                    }
                                }
                            }
                        )
                        if ([string]::IsNullOrEmpty($AllAdapters)) {
                            New-UDGrid -Item -Size 12 -Content {
                                New-UDAlert -Severity 'error' -Text "Could not establish a connection to $($Computer)"
                            }
                        }
                        else {
                            New-UDGrid -Item -Size 12 -Content {
                                $SearchOption = New-UDTableTextOption -Search "Search"
                                New-UDTable -Id 'AdapterSearchTable' -Data $AllAdapters -Columns $AdaptersColumns -DefaultSortDirection "Ascending" -Sort -TextOption $SearchOption -ShowSearch -ShowPagination -Dense -Export -ExportOption "xlsx, PDF" -PageSize 20
                            }
                        }
                    }
                } -LoadingComponent {
                    New-UDProgress -Circular
                }
            } -Footer {
                New-UDButton -Text "Refresh" -OnClick { 
                    Sync-UDElement -Id 'AdapterData'
                }
                New-UDButton -Text "Close" -OnClick {
                    Hide-UDModal
                }                
            } -FullWidth -MaxWidth 'lg' -Persistent
        }
    }
}

function Show-ProcessTableBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][bool]$ActiveEventLog,
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory = $false)][string]$EventLogName,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )
    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Show processes on $($Computer)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon tasks) -size medium -Onclick {
            Show-UDModal -Header { "Show process on $($Computer)" } -Content {
                New-UDDynamic -Id 'ProcessStart' -content {
                    New-UDGrid -Spacing '1' -Container -Content {
                        if ($ActiveEventLog -eq "True") {
                            Write-EventLog -LogName $EventLogName -Source "ShowProcess" -EventID 10 -EntryType Information -Message "$($User) did look at processes for $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                        }
                        
                        $Columns = @(
                            New-UDTableColumn -Title 'Id' -Property 'ID' -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Title 'Name' -Property 'ProcessName' -IncludeInExport -IncludeInSearch -DefaultSortColumn
                            New-UDTableColumn -Title 'User' -Property 'UserName' -IncludeInExport
                            New-UDTableColumn -Title 'CPU' -Property 'CPU' -IncludeInExport
                            New-UDTableColumn -Title 'RAM' -Property 'WorkingSet' -IncludeInExport -Render {
                                $EventData.WorkingSet | ConvertTo-ByteString
                            }
                            New-UDTableColumn -Property Delete -Title "." -Render {
                                New-UDTooltip -TooltipContent {
                                    New-UDTypography -Text "Stop process"
                                } -content { 
                                    New-UDButton -Icon (New-UDIcon -Icon stop) -size small -Onclick {
                                        $KillProcessID = $EventData.id
                                        try {
                                            Invoke-Command -ComputerName $Computer -Scriptblock {
                                                Param($KillProcessID)
                                                Stop-Process -Id $KillProcessID -Force
                                            } -ArgumentList $KillProcessID
                                            if ($ActiveEventLog -eq "True") {
                                                Write-EventLog -LogName $EventLogName -Source "KillProcess" -EventID 10 -EntryType Information -Message "$($User) did kill process $($EventData.ProcessName) ID $($KillProcessID) for $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                            }
                                            Show-UDToast -Message "The Process $($EventData.ProcessName) has been terminated!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                            Sync-UDElement -id 'ProcessStart'
                                        }
                                        catch {
                                            Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                            Break
                                        }
                                    }
                                }
                            }    
                        )
                        $Processes = Invoke-Command -ComputerName $Computer -Scriptblock { Get-Process -IncludeUserName | Select-Object @("Id", "ProcessName", "CPU", "WorkingSet", "UserName") }
                        if ([string]::IsNullOrEmpty($Processes)) {
                            New-UDGrid -Item -Size 12 -Content {
                                New-UDAlert -Severity 'error' -Text "Could not establish a connection to $($Computer)"
                            }
                        }
                        else {
                            New-UDGrid -Item -Size 12 -Content {
                                $SearchOption = New-UDTableTextOption -Search "Search"
                                New-UDTable -Columns $Columns -Data $Processes -DefaultSortDirection "Ascending" -Sort -TextOption $SearchOption -ShowSearch -ShowPagination -Dense -Export -ExportOption "xlsx, PDF" -PageSize 50
                            }
                        }
                    }
                } -LoadingComponent {
                    New-UDProgress -Circular
                }
            } -Footer {
                New-UDButton -Text "Refresh" -OnClick { 
                    Sync-UDElement -id 'ProcessStart'
                }
                New-UDButton -Text "Close" -OnClick {
                    Hide-UDModal
                }
                                        
            } -FullWidth -MaxWidth 'lg' -Persistent
        }
    }
}

function Show-InstalledSoftwareBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][bool]$ActiveEventLog,
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory = $false)][string]$EventLogName,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )

    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "List installed softwares on $($Computer)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon list_ul) -size medium -Onclick {
            Show-UDModal -Header { "All installed softwares on $($Computer)" } -Content {
                New-UDDynamic -Id 'InstallSWData' -content {
                    New-UDGrid -Spacing '1' -Container -Content {
                        if ($ActiveEventLog -eq "True") {
                            Write-EventLog -LogName $EventLogName -Source "ShowInstalledSoftware" -EventID 10 -EntryType Information -Message "$($User) did look at installed software for $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                        }
                        $InstallData = Get-CimInstance -Computer $Computer -ClassName win32_product | Select-Object Name, PackageName, InstallDate

                        $InstallColumns = @(
                            New-UDTableColumn -Property Name -Title "Name" -IncludeInExport -IncludeInSearch -DefaultSortColumn
                            New-UDTableColumn -Property PackageName -Title "Package Name" -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Property InstallDate -Title "Installation Date" -IncludeInExport -IncludeInSearch
                        )
                        if ([string]::IsNullOrEmpty($InstallData)) {
                            New-UDGrid -Item -Size 12 -Content {
                                New-UDAlert -Severity 'error' -Text "Could not establish a connection to $($Computer)"
                            }
                        }
                        else {
                            New-UDGrid -Item -Size 12 -Content {
                                $SearchOption = New-UDTableTextOption -Search "Search"
                                New-UDTable -Id 'InstallSWSearchTable' -Data $InstallData -Columns $InstallColumns -DefaultSortDirection "Ascending" -Sort -TextOption $SearchOption -ShowSearch -ShowPagination -Dense -Export -ExportOption "xlsx, PDF" -PageSize 20
                            }
                        }
                    }
                } -LoadingComponent {
                    New-UDProgress -Circular
                }
            } -Footer {
                New-UDButton -Text "Refresh" -OnClick {
                    Sync-UDElement -Id 'InstallSWData'
                }
                New-UDButton -Text "Close" -Size medium -OnClick {
                    Hide-UDModal
                }
                                        
            } -FullWidth -MaxWidth 'md' -Persistent
        }
    }
}

function Show-AutostartTableBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][bool]$ActiveEventLog,
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory = $false)][string]$EventLogName,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )

    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Show autostarts on $($Computer)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon play) -size medium -Onclick {
            Show-UDModal -Header { "Autostart on $($Computer)" } -Content {
                New-UDDynamic -Id 'Autostart' -content {
                    New-UDGrid -Spacing '1' -Container -Content {
                        if ($ActiveEventLog -eq "True") {
                            Write-EventLog -LogName $EventLogName -Source "ShowAutostart" -EventID 10 -EntryType Information -Message "$($User) did look at autostart for $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                        }
                        $Columns = @(
                            New-UDTableColumn -Title 'Name' -Property 'Name' -IncludeInExport -IncludeInSearch -DefaultSortColumn
                            New-UDTableColumn -Title 'User' -Property 'User' -IncludeInExport -IncludeInSearch -Render {
                                switch ($EventData.User) {
                                    Public { "All users" }
                                    Default { $EventData.User }
                                }
                            }
                        )
                        $Autostarts = Get-CimInstance -Computer $Computer Win32_StartupCommand | Select-Object @("Name", "User")
                        if ([string]::IsNullOrEmpty($Autostarts)) {
                            New-UDGrid -Item -Size 12 -Content {
                                New-UDAlert -Severity 'error' -Text "Could not establish a connection to $($Computer)"
                            }
                        }
                        else {
                            New-UDGrid -Item -Size 12 -Content {
                                $SearchOption = New-UDTableTextOption -Search "Search"
                                New-UDTable -Columns $Columns -Data $Autostarts -DefaultSortDirection "Ascending" -Sort -TextOption $SearchOption -ShowSearch -ShowPagination -Dense -Export -ExportOption "xlsx, PDF" -PageSize 50
                            }
                        }
                    }
                } -LoadingComponent {
                    New-UDProgress -Circular
                }
            } -Footer {
                New-UDButton -Text "Refresh" -OnClick { 
                    Sync-UDElement -id 'Autostarts'
                }
                New-UDButton -Text "Close" -OnClick {
                    Hide-UDModal
                }
                                        
            } -FullWidth -MaxWidth 'md' -Persistent
        }
    }
}

function Show-ServicesTableBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][bool]$ActiveEventLog,
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory = $false)][string]$EventLogName,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )

    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Show services on $($Computer)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon clipboard_list) -size medium -Onclick {
            Show-UDModal -Header { "Services on $($Computer)" } -Content {
                New-UDDynamic -Id 'serviceTable' -Content {
                    New-UDGrid -Spacing '1' -Container -Content {
                        if ($ActiveEventLog -eq "True") {
                            Write-EventLog -LogName $EventLogName -Source "ShowServices" -EventID 10 -EntryType Information -Message "$($User) did look at Services for $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                        }

                        $Columns = @(
                            New-UDTableColumn -Title 'Name' -Property 'Name' -IncludeInExport -IncludeInSearch -DefaultSortColumn
                            New-UDTableColumn -Title 'Description' -Property 'DisplayName' -IncludeInExport
                            New-UDTableColumn -Title 'Start Type' -Property 'StartType' -IncludeInExport -IncludeInSearch -Hidden
                            New-UDTableColumn -Title 'Start Type' -Property '.' -IncludeInExport -IncludeInSearch -Render {
                                New-UDSelect -id "$($Eventdata.Name)StartupTypeSelect" -Option {
                                    switch ($Eventdata.StartType) {
                                        Manual {
                                            New-UDSelectOption -Name 'Manual' -Value "Manual"
                                            New-UDSelectOption -Name 'Automatic' -Value "Automatic"
                                            New-UDSelectOption -Name 'Disabled' -Value "Disabled"
                                        }
                                        Automatic {
                                            New-UDSelectOption -Name 'Automatic' -Value "Automatic"
                                            New-UDSelectOption -Name 'Manual' -Value "Manual"
                                            New-UDSelectOption -Name 'Disabled' -Value "Disabled"

                                        }
                                        Disabled {
                                            New-UDSelectOption -Name 'Disabled' -Value "Disabled"
                                            New-UDSelectOption -Name 'Automatic' -Value "Automatic"
                                            New-UDSelectOption -Name 'Manual' -Value "Manual"
                                        }
                                    }
                                }
                                New-UDTooltip -TooltipContent {
                                    New-UDTypography -Text "Change startup type"
                                } -content { 
                                    New-UDButton  -Icon (New-UDIcon -Icon exchange_alt) -size small -OnClick { 
                                        $StartupTypeSelectSwitch = Get-UDElement -Id "$($Eventdata.Name)StartupTypeSelect"
                                        $StartupService = $EventData.Name
                                        $StartUpTypeChoosen = $StartupTypeSelectSwitch.Value
                                        if ([string]::IsNullOrEmpty($StartupTypeSelectSwitch) -or $Eventdata.StartType -eq $StartUpTypeChoosen) {
                                            Show-UDToast -Message "You must choose a startup type!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                            Break
                                        }

                                        try {
                                            switch ($StartupTypeSelectSwitch.Value) {
                                                Automatic {
                                                    Invoke-Command -ComputerName $Computer -Scriptblock {
                                                        Param($StartUpTypeChoosen, $StartupService)
                                                        Set-Service -Name $StartupService -StartupType $StartUpTypeChoosen
                                                    } -ArgumentList $StartUpTypeChoosen, $StartupService
                                                }
                                                Manual {
                                                    Invoke-Command -ComputerName $Computer -Scriptblock {
                                                        Param($StartUpTypeChoosen, $StartupService)
                                                        Set-Service -Name $StartupService -StartupType $StartUpTypeChoosen
                                                    } -ArgumentList $StartUpTypeChoosen, $StartupService
                                                }
                                                Disabled {
                                                    Invoke-Command -ComputerName $Computer -Scriptblock {
                                                        Param($StartUpTypeChoosen, $StartupService)
                                                        Set-Service -Name $StartupService -StartupType $StartUpTypeChoosen
                                                    } -ArgumentList $StartUpTypeChoosen, $StartupService
                                                }
                                            }
                                            if ($ActiveEventLog -eq "True") {
                                                Write-EventLog -LogName $EventLogName -Source "ChangeServiceStartUp" -EventID 10 -EntryType Information -Message "$($User) did change startup type for service $($StartupService) to $($StartUpTypeChoosen)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                            }
                                            Show-UDToast -Message "The Services $($StartupService) has changed startup type to $($StartUpTypeChoosen)" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                            Sync-UDElement -Id 'serviceTable'
                                        }
                                        catch {
                                            Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                            Break
                                        }
                                    }
                                }
                            }
                            New-UDTableColumn -Title 'Status' -Property 'Status' -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Title '.' -Property 'Actions' -Render {
                                if ($EventData.Status -eq 'Running') {
                                    New-UDTooltip -TooltipContent {
                                        New-UDTypography -Text "Stop"
                                    } -content { 
                                        New-UDButton  -Icon (New-UDIcon -Icon stop) -size small -OnClick { 
                                            try {
                                                $KillService = $EventData.Name
                                                Invoke-Command -ComputerName $Computer -Scriptblock {
                                                    Param($KillService)
                                                    Stop-Service $KillService -ErrorAction stop
                                                } -ArgumentList $KillService
                                                if ($ActiveEventLog -eq "True") {
                                                    Write-EventLog -LogName $EventLogName -Source "StopServices" -EventID 10 -EntryType Information -Message "$($User) did stop the services $($EventData.Name) for $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                                }
                                                Show-UDToast -Message "The Services $($EventData.Name) has been stopped!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Sync-UDElement -Id 'serviceTable'
                                            }
                                            catch {
                                                Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Break
                                            }
                                        }
                                    }
                                    New-UDTooltip -TooltipContent {
                                        New-UDTypography -Text "Restart"
                                    } -content { 
                                        New-UDButton -Icon (New-UDIcon -Icon redo_alt) -size small -OnClick { 
                                            try {
                                                $RestartService = $EventData.Name
                                                Invoke-Command -ComputerName $Computer -Scriptblock {
                                                    Param($RestartService)
                                                    Restart-Service $RestartService -ErrorAction stop
                                                } -ArgumentList $RestartService
                                                if ($ActiveEventLog -eq "True") {
                                                    Write-EventLog -LogName $EventLogName -Source "RestartServices" -EventID 10 -EntryType Information -Message "$($User) did restart the services $($EventData.Name) for $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                                }
                                                Show-UDToast -Message "The services $($EventData.Name) has restarted!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Sync-UDElement -Id 'serviceTable'
                                            }
                                            catch {
                                                Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Break
                                            }

                                        }
                                    }
                                }
                                else {
                                    New-UDTooltip -TooltipContent {
                                        New-UDTypography -Text "Start"
                                    } -content { 
                                        New-UDButton -Icon (New-UDIcon -Icon play) -size small -OnClick { 
                                            try {
                                                $StartService = $EventData.Name
                                                Invoke-Command -ComputerName $Computer -Scriptblock {
                                                    Param($StartService)
                                                    Start-Service $StartService -ErrorAction stop
                                                } -ArgumentList $StartService
                                                if ($ActiveEventLog -eq "True") {
                                                    Write-EventLog -LogName $EventLogName -Source "StartServices" -EventID 10 -EntryType Information -Message "$($User) did start the services $($EventData.Name) for $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                                }
                                                Show-UDToast -Message "The services $($EventData.Name) has started!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Sync-UDElement -Id 'serviceTable'
                                            }
                                            catch {
                                                Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Break
                                            }

                                        }
                                    }
                                }
                            }
                        )

                        $Services = Invoke-Command -ComputerName $Computer -Scriptblock { Get-Service }
                        if ([string]::IsNullOrEmpty($Services)) {
                            New-UDGrid -Item -Size 12 -Content {
                                New-UDAlert -Severity 'error' -Text "Could not establish a connection to $($Computer)"
                            }
                        }
                        else {
                            New-UDGrid -Item -Size 12 -Content {
                                $SearchOption = New-UDTableTextOption -Search "Search"
                                New-UDTable -Columns $Columns -Data $Services -DefaultSortDirection "Ascending" -Sort -TextOption $SearchOption -ShowSearch -ShowPagination -Dense -Export -ExportOption "xlsx, PDF" -PageSize 50
                            }
                        }
                    }
                } -LoadingComponent {
                    New-UDProgress -Circular
                }
            } -Footer {
                New-UDButton -Text "Refresh" -OnClick { 
                    Sync-UDElement -id 'serviceTable'
                }
                New-UDButton -Text "Close" -OnClick {
                    Hide-UDModal
                }
                                        
            } -FullWidth -MaxWidth 'lg' -Persistent
        }
    }
}

function Remove-UserProfilesBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][bool]$ActiveEventLog,
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory)][string]$YourDomain,
        [Parameter(Mandatory = $false)][string]$EventLogName,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )
    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Delete user profiles from $($Computer)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon user_slash) -size medium -Onclick {
            Show-UDModal -Header { "Delete user profile from $($Computer)" } -Content {
                New-UDDynamic -Id 'ShowUsrProfdata' -content {
                    New-UDGrid -Spacing '1' -Container -Content {
                        if ($ActiveEventLog -eq "True") {
                            Write-EventLog -LogName $EventLogName -Source "ShowComputerUserProfiles" -EventID 10 -EntryType Information -Message "$($User) has been looking at $($Computer) user profiles`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                        }
                        $Profiles = Get-WMIObject -ComputerName $Computer -class Win32_UserProfile | Where-Object { (!$_.Special) -and ($_.LocalPath -ne 'C:\Users\Administrator') -and ($_.LocalPath -ne 'C:\Users\Administratör') }

                        $SearchComputerGroupData = foreach ($Profile in $Profiles) {
                            $SID = $Profile.SID
                            $ProfileInfo = Invoke-Command -ComputerName $Computer { Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$using:SID" }
    
                            If ($null -ne $ProfileInfo.LocalProfileUnloadTimeHigh) {
                                $PUHigh = '{0:x}' -f $ProfileInfo.LocalProfileUnloadTimeHigh
                                $PULow = '{0:x}' -f $ProfileInfo.LocalProfileUnloadTimeLow
                                $PUcomb = -join ('0x', $PUHigh, $PULow)
                                $ProfileUsed = [datetime]::FromFileTime([uint64]$PUcomb)                    
 
                                $ProfileAge = (New-TimeSpan -Start $ProfileUsed).Days #$ts.Days

                                if ($ProfileAge -ge 3000) {
                                    $ProfileUsed = "N/A"
                                    $ProfileAge = "N/A"
                                }
                            }
                            Else {
                                $ProfileUsed = "N/A"
                                $ProfileAge = "N/A"
                            }
 
                            try {
                                $ProfileUser = (New-Object System.Security.Principal.SecurityIdentifier ($Profile.SID)).Translate( [System.Security.Principal.NTAccount]).Value
                            }
                            catch {
                                $ProfileUser = $Profile.LocalPath
                            }
                            $ConProfileUsed = $ProfileUsed -as [datetime]

                            [PSCustomObject]@{
                                User          = $ProfileUser
                                ProfilePath   = $Profile.LocalPath
                                LastUsed      = $ConProfileUsed
                                ProfileAge    = "$($ProfileAge) days"
                                ProfileLoaded = $Profile.Loaded
                            }
                        }
                        $SearchComputerGroupColumns = @(
                            New-UDTableColumn -Property User -Title "User" -IncludeInExport -IncludeInSearch -DefaultSortColumn
                            New-UDTableColumn -Property ProfilePath -Title "Search path" -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Property LastUsed -Title "Last Used" -IncludeInExport -IncludeInSearch -Render {
                                if ([string]::IsNullOrEmpty($EventData.LastUsed)) {
                                    "N/A"
                                }
                                else {
                                    $LastUsedDate = $EventData.LastUsed -as [datetime]
                                    "$($LastUsedDate)"
                                }
                            }
                            New-UDTableColumn -Property ProfileAge -Title "Profile age" -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Property ProfileLoaded -Title "Loaded?"
                            New-UDTableColumn -Property Delete -Title "." -Render {
                                New-UDTooltip -TooltipContent {
                                    New-UDTypography -Text "Delete the user profile"
                                } -content { 
                                    New-UDButton -Icon (New-UDIcon -Icon backspace) -size small -Onclick {
                                        if ($EventData.ProfileLoaded -eq "True") {
                                            Show-UDToast -Message "You can't delete a profile that are loaded!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                        }
                                        else {
                                            $UserRmProfileName = $EventData.User.Replace("$($YourDomain)\", "")
                                            try {
                                                $Btns = @("CloseBtn", "SelectedBtn", "RefreshBtn")
                                                foreach ($btn in $btns) {
                                                    Set-UDElement -Id $btn -Properties @{
                                                        disabled = $true 
                                                        text     = "Deleting..."
                                                    }
                                                }
                                                Get-WmiObject -ComputerName $Computer Win32_UserProfile | Where-Object { $_.LocalPath -eq "C:\Users\$($UserRmProfileName)" } | Remove-WmiObject
                                                if ($ActiveEventLog -eq "True") {
                                                    Write-EventLog -LogName $EventLogName -Source "DeletedUserProfile" -EventID 10 -EntryType Information -Message "$($User) did delete $($UserRmProfileName) user profile from $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                                }
                                                Show-UDToast -Message "The profile for $($UserRmProfileName) has been deleted!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Set-UDElement -Id "CloseBtn" -Properties @{
                                                    disabled = $false
                                                    text     = "Close"
                                                }
                                                Set-UDElement -Id "RefreshBtn" -Properties @{
                                                    disabled = $false
                                                    text     = "Refresh"
                                                }
                                                Set-UDElement -Id "SelectedBtn" -Properties @{
                                                    disabled = $false 
                                                    text     = "Delete selected"
                                                }
                                                Sync-UDElement -id 'ShowUsrProfdata'
                                            }
                                            catch {
                                                Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Sync-UDElement -id 'ShowUsrProfdata'
                                                Break
                                            }
                                        }
                                    }
                                }
                            }
                        )
                        if ([string]::IsNullOrEmpty($SearchComputerGroupData)) {
                            New-UDGrid -Item -Size 12 -Content {
                                New-UDAlert -Severity 'error' -Text "$($Computer) has no user profiles or could not establish a connection to $($Computer)"
                            }
                        }
                        else {
                            New-UDGrid -Item -Size 12 -Content {
                                $SearchOption = New-UDTableTextOption -Search "Search"
                                New-UDTable -Id 'ComputerSearchTable' -Data $SearchComputerGroupData -Columns $SearchComputerGroupColumns -DefaultSortDirection "Ascending" -Sort -TextOption $SearchOption -ShowSearch -ShowPagination -Dense -Export -ExportOption "xlsx, PDF" -PageSize 20 -ShowSelection
                            }
                            New-UDGrid -Item -Size 12 -Content {
                                New-UDButton -Text "Delete selected" -OnClick {
                                    $ComputerSearchTable = Get-UDElement -Id "ComputerSearchTable"
                                    $ComputerSearchLog = @($ComputerSearchTable.selectedRows.User)
                                    if ($Null -ne $ComputerSearchTable.selectedRows.User) {                  
                                        try {
                                            $Btns = @("CloseBtn", "SelectedBtn", "RefreshBtn")
                                            foreach ($btn in $btns) {
                                                Set-UDElement -Id $btn -Properties @{
                                                    disabled = $true 
                                                    text     = "Deleting..."
                                                }
                                            }
                                            @($ComputerSearchTable.selectedRows.ForEach( { 
                                                        if ($_.ProfileLoaded -like "False") {
                                                            $UserRmProfileName = $_.User.Replace("$($YourDomain)\", "")
                                                            Get-WmiObject -ComputerName $Computer Win32_UserProfile | Where-Object { $_.LocalPath -eq "C:\Users\$($UserRmProfileName)" } | Remove-WmiObject
                                                            if ($ActiveEventLog -eq "True") {
                                                                Write-EventLog -LogName $EventLogName -Source "DeletedUserProfile" -EventID 10 -EntryType Information -Message "$($User) did delete $($UserRmProfileName) user profile from $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                                            }
                                                        }
                                                    } ) )
                                            Show-UDToast -Message "The profiles for $($ComputerSearchLog -join ",") has been deleted!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                            Set-UDElement -Id "CloseBtn" -Properties @{
                                                disabled = $false
                                                text     = "Close"
                                            }
                                            Set-UDElement -Id "RefreshBtn" -Properties @{
                                                disabled = $false
                                                text     = "Refresh"
                                            }
                                            Set-UDElement -Id "SelectedBtn" -Properties @{
                                                disabled = $false 
                                                text     = "Delete selected"
                                            }
                                            Sync-UDElement -id 'ShowUsrProfdata'
                                        }
                                        catch {
                                            Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                            Break
                                        }
                                    }
                                    else {
                                        Show-UDToast -Message "You have not selected any profile!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                        Break
                                    }
                                } -id "SelectedBtn"
                            }
                        }
                    }
                } -LoadingComponent {
                    New-UDProgress -Circular
                }                
            } -Footer {
                New-UDButton -Text "Refresh" -OnClick { 
                    Sync-UDElement -id 'ShowUsrProfdata'
                } -id "RefreshBtn"
                New-UDButton -Text "Close" -OnClick {
                    Hide-UDModal
                } -id "CloseBtn"
                                        
            } -FullWidth -MaxWidth 'lg' -Persistent
        }
    }
}

Function Compare-ComputerGrpsBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][bool]$ActiveEventLog,
        [Parameter(Mandatory)][String]$Computer,
        [Parameter(Mandatory)][String]$YourFullDomain,
        [Parameter(Mandatory = $false)][string]$EventLogName,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress,
        [Parameter(Mandatory = $false)][String]$RefreshOnClose
    )
    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Compare $($Computer)s AD group memberships against an other computer"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon not_equal) -size medium -Onclick {
            Show-UDModal -Header { "Compare $($Computer)" } -Content {
                New-UDGrid -Spacing '1' -Container -Content {
                    New-UDGrid -Item -Size 5 -Content {
                        New-UDTextbox -Id 'txtCompComputer' -Label "Compare against?"
                    }
                    New-UDGrid -Item -Size 7 -Content { }
                }
                New-UDDynamic -Id 'CompUsrGrpsTable' -content {
                    New-UDGrid -Spacing '1' -Container -Content {
                        $CompComputer = (Get-UDElement -Id "txtCompComputer").value
                        if ($NULL -ne $CompComputer) {
                            $CompComputer = $CompComputer.trim()
                        }

                        if ($null -ne $CompComputer) {
                            if (Get-ADComputer -Filter "samaccountname -eq '$($CompComputer)$'") {
                                if ($Computer -eq $CompComputer) {
                                    New-UDGrid -Item -Size 12 -Content {
                                        New-UDHtml -Markup "</br>"
                                        New-UDAlert -Severity 'error' -Text "You can't compare $($Computer) to it self! "
                                    }
                                }
                                else {
                                    try {
                                        if ($ActiveEventLog -eq "True") {
                                            Write-EventLog -LogName $EventLogName -Source "CompareComputerADGroups" -EventID 10 -EntryType Information -Message "$($User) did compare $($Computer) against $($CompComputer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                        }
                                        $Columns = @(
                                            New-UDTableColumn -Title '.' -Property '.' -render {
                                                New-UDTooltip -TooltipContent {
                                                    New-UDTypography -Text "Add $($Computer) to this group"
                                                } -content { 
                                                    New-UDButton -Icon (New-UDIcon -Icon sign_in_alt) -size small -Onclick {
                                                        try {
                                                            Add-ADGroupMember -Identity $EventData.SamAccountName -Members "$($Computer)$" 
                                                            Show-UDToast -Message "$($Computer) are now member of $($EventData.SamAccountName)" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                            if ($ActiveEventLog -eq "True") {
                                                                Write-EventLog -LogName $EventLogName -Source "AddToGroup" -EventID 10 -EntryType Information -Message "$($User) did add $($Computer) to the group $($EventData.SamAccountName)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                                            }
                                                            Sync-UDElement -Id 'CompUsrGrpsTable'
                                                        }
                                                        catch {
                                                            Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                            Break
                                                        }
                                                    }
                                                }
                                            }
                                            New-UDTableColumn -Title 'Group' -Property 'SamAccountName' -IncludeInExport -IncludeInSearch -DefaultSortColumn
                                            New-UDTableColumn -Title 'Description' -Property 'Description' -IncludeInExport -IncludeInSearch
                                        )
                                        $obj = Get-ADPrincipalGroupMembership -Identity "$($Computer)$"  -ResourceContextServer $YourFullDomain | Sort-Object -Property SamAccountName
                                        $obj2 = Get-ADPrincipalGroupMembership -Identity "$($CompComputer)$"  -ResourceContextServer $YourFullDomain | Sort-Object -Property SamAccountName
                                        $CompData = Compare-Object -ReferenceObject $obj -DifferenceObject $obj2 -Property SamAccountName | Where-Object { $_.SideIndicator -eq "=>" } | Foreach-Object { Get-ADGroup -Identity $_.SamAccountName -Property Displayname, Description | Select-Object SamAccountName, Description }
                
                                        if ([string]::IsNullOrEmpty($CompData)) {
                                            New-UDGrid -Item -Size 12 -Content {
                                                New-UDHtml -Markup "</br>"
                                                New-UDAlert -Severity 'success' -Text "$($Computer) are member in all groups that $($CompComputer) are member in!"
                                            }
                                        }
                                        else {
                                            New-UDGrid -Item -Size 12 -Content {
                                                $SearchOption = New-UDTableTextOption -Search "Search"
                                                New-UDTable -id "CompTable" -Data $CompData -Columns $Columns -DefaultSortDirection "Ascending" -TextOption $SearchOption -ShowSearch -ShowSelection -ShowPagination -Dense -Sort -Export -ExportOption "xlsx, PDF" -PageSize 200                      
                                            }
                                            New-UDGrid -Item -Size 12 -Content { 
                                                New-UDButton -Text "Add to selected" -OnClick {
                                                    $CompTable = Get-UDElement -Id "CompTable"
                                                    $SelectedGrp = @($CompTable.selectedRows.SamAccountName)

                                                    if ($null -ne $CompTable.selectedRows.SamAccountName) {
                                                        try {
                                                            @($CompTable.selectedRows.SamAccountName.ForEach( { 
                                                                        Add-ADGroupMember -Identity $_ -Members "$($Computer)$" 
                                                                        if ($ActiveEventLog -eq "True") {
                                                                            Write-EventLog -LogName $EventLogName -Source "AddToGroup" -EventID 10 -EntryType Information -Message "$($User) did add $($Computer) to the group $($_)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                                                        }
                                                                    } ) )
                                    
                                                            Show-UDToast -Message "$($Computer) are now member of $($SelectedGrp -join ",")!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                            Sync-UDElement -Id 'CompUsrGrpsTable'
                                                        }
                                                        catch {
                                                            Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                            Break
                                                        }

                                                    }
                                                    else {
                                                        Show-UDToast -Message "You have not selected any group, you need to select at least one group!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                        Break
                                                    }

                                                }
                                            }
                                        }
                                    }
                                    catch {
                                        Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                        Break
                                    }
                                }
                            }
                            else {
                                New-UDGrid -Item -Size 12 -Content {
                                    New-UDHtml -Markup "</br>"
                                    New-UDAlert -Severity 'error' -Text "Could not find $($CompComputer) in the AD!"
                                }
                            }
                        }
                        else {
                            New-UDGrid -Item -Size 12 -Content {
                                New-UDHtml -Markup "</br>"
                                New-UDAlert -Severity 'error' -Text "You need to type a computer name that you want to compare $($Computer) against!"
                            }
                        }
                    }
                } -LoadingComponent {
                    New-UDProgress -Circular
                } 
            } -Footer {
                New-UDGrid -Item -Size 6 -Content { }
                New-UDGrid -Item -Size 4 -Content { }
                New-UDGrid -Item -Size 2 -Content { 
                    New-UDButton -text 'Compare' -Onclick {
                        Sync-UDElement -Id 'CompUsrGrpsTable'
                    }

                    New-UDButton -Text "Close" -OnClick {
                        Sync-UDElement -Id $RefreshOnClose
                        Hide-UDModal
                    }
                }
            } -FullWidth -MaxWidth 'lg' -Persistent
        }
    }
}

function Show-SchedualTaskTableBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][bool]$ActiveEventLog,
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory = $false)][string]$EventLogName,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )

    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Show scheduled tasks on $($Computer)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon business_time) -size medium -Onclick {
            Show-UDModal -Header { "Schedual Tasks on $($Computer)" } -Content {
                New-UDDynamic -Id 'Schedual' -content {
                    New-UDGrid -Spacing '1' -Container -Content {
                        if ($ActiveEventLog -eq "True") {
                            Write-EventLog -LogName $EventLogName -Source "ShowSchedualTask" -EventID 10 -EntryType Information -Message "$($User) did look at SchedualTask for $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                        }

                        $Columns = @(
                            New-UDTableColumn -Title '.' -Property '.' -Render {
                                if ($EventData.State -notlike 'Running' ) {
                                    if ($EventData.State -like 'Disabled') {
                                        New-UDTooltip -TooltipContent {
                                            New-UDTypography -Text "Enable"
                                        } -content { 
                                            New-UDButton -Icon (New-UDIcon -Icon play) -size small -OnClick {
                                                try {
                                                    Enable-ScheduledTask -TaskName $EventData.TaskName
                                                    Sync-UDElement -id "Schedual"
                                                    if ($ActiveEventLog -eq "True") {
                                                        Write-EventLog -LogName $EventLogName -Source "EnableSchedualTask" -EventID 10 -EntryType Information -Message "$($User) did enable $($EventData.TaskName) on $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                                    }
                                                }
                                                catch {
                                                    Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                    Break
                                                }
                                            }
                                        }
                                    }
                                    elseif ($EventData.State -like 'Ready') {
                                        New-UDTooltip -TooltipContent {
                                            New-UDTypography -Text "Disable"
                                        } -content { 
                                            New-UDButton -Icon (New-UDIcon -Icon stop) -size small -OnClick {
                                                try {
                                                    Disable-ScheduledTask -TaskName $EventData.TaskName
                                                    Sync-UDElement -id "Schedual"
                                                    if ($ActiveEventLog -eq "True") {
                                                        Write-EventLog -LogName $EventLogName -Source "DisableSchedualTask" -EventID 10 -EntryType Information -Message "$($User) did disable $($EventData.TaskName) on $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                                    }
                                                }
                                                catch {
                                                    Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                    Break
                                                }
                                            }    
                                        }
                                    }
                                    New-UDTooltip -TooltipContent {
                                        New-UDTypography -Text "Run"
                                    } -content { 
                                        New-UDButton -Icon (New-UDIcon -Icon play_circle) -size small -OnClick {
                                            try {
                                                Start-ScheduledTask -TaskName $EventData.TaskName
                                                Sync-UDElement -id "Schedual"
                                                if ($ActiveEventLog -eq "True") {
                                                    Write-EventLog -LogName $EventLogName -Source "RunSchedualTask" -EventID 10 -EntryType Information -Message "$($User) did run $($EventData.TaskName) on $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                                }
                                            }
                                            catch {
                                                Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Break
                                            }
                                        }
                                    }      
                                }
                            }
                            New-UDTableColumn -Title 'State' -Property 'State' -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Title 'Task Name' -Property 'TaskName' -IncludeInExport -IncludeInSearch -DefaultSortColumn
                            New-UDTableColumn -Title 'Description' -Property 'Description' -IncludeInExport -IncludeInSearch
                        )
                        $Scheduals = Invoke-Command -ComputerName $Computer -ScriptBlock { Get-ScheduledTask -taskpath "\" | select-object State, TaskName, Description }
                        if ([string]::IsNullOrEmpty($Scheduals)) {
                            New-UDGrid -Item -Size 12 -Content {
                                New-UDAlert -Severity 'error' -Text "Could not establish a connection to $($Computer)"
                            }
                        }
                        else {
                            New-UDGrid -Item -Size 12 -Content {
                                $SearchOption = New-UDTableTextOption -Search "Search"
                                New-UDTable -Columns $Columns -Data $Scheduals -DefaultSortDirection "Ascending" -Sort -TextOption $SearchOption -ShowSearch -ShowPagination -Dense -Export -ExportOption "xlsx, PDF" -PageSize 50
                            }
                        }
                    }
                } -LoadingComponent {
                    New-UDProgress -Circular
                }
            } -Footer {
                New-UDButton -Text "Refresh" -OnClick { 
                    Sync-UDElement -id 'Schedual'
                }
                New-UDButton -Text "Close" -OnClick {
                    Hide-UDModal
                }
                                        
            } -FullWidth -Persistent
        }
    }
}

Function Restart-ADComputer {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][bool]$ActiveEventLog,
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory = $false)][string]$EventLogName,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )

    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Reboot $($Computer)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon power_off) -size medium -Onclick {
            Show-UDModal -Header { "Reboot $($Computer)" } -Content {
                New-UDGrid -Spacing '1' -Container -Content {
                    New-UDGrid -Item -Size 1 -Content { }
                    New-UDGrid -Item -Size 10 -Content {
                        New-UDTypography -Text "Are you sure that you want to reboot $($Computer)?"
                    }
                    New-UDGrid -Item -Size 1 -Content { }
                }
            } -Footer {
                New-UDButton -Text "Yes" -OnClick { 
                    Show-UDToast -Message "$($Computer) has now been rebooted!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                    Invoke-Command -ComputerName $Computer -ScriptBlock { Restart-Computer -Force }
                    if ($ActiveEventLog -eq "True") {
                        Write-EventLog -LogName $EventLogName -Source "RebootComputer" -EventID 10 -EntryType Information -Message "$($User) did reboot $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                    }
                    Hide-UDModal
                }
                New-UDButton -Text "No" -OnClick {
                    Hide-UDModal
                }
            } -FullWidth -MaxWidth 'xs' -Persistent
        }
    }
}

Function Disconnect-UserFromComputer {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][bool]$ActiveEventLog,
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory = $false)][string]$EventLogName,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )

    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Logout user from $($Computer)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon sign_out_alt) -size medium -Onclick {
            Show-UDModal -Header { "Logout user from $($Computer)" } -Content {
                New-UDGrid -Spacing '1' -Container -Content {
                    New-UDGrid -Item -Size 12 -Content {
                        New-UDTypography -Text "Are you sure that you want to logout the user from $($Computer)?"
                    }
                }
            } -Footer {
                New-UDButton -Text "Yes" -OnClick { 
                    Show-UDToast -Message "$($SystInfo.Computer.UserName) has been logged out from $($Computer)" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                    Hide-UDModal
                    Invoke-CimMethod -ClassName Win32_Operatingsystem -ComputerName $Computer -MethodName Win32Shutdown -Arguments @{ Flags = 0 }
                    if ($ActiveEventLog -eq "True") {
                        Write-EventLog -LogName $EventLogName -Source "LogOutUser" -EventID 10 -EntryType Information -Message "$($User) did logout $($SystInfo.Computer.UserName) from $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                    }
                }
                New-UDButton -Text "No" -OnClick { Hide-UDModal }
            } -FullWidth -MaxWidth 'xs' -Persistent
        }
    }
}

function Remove-TempFilesClientBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)][bool]$ActiveEventLog,
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory = $false)][string]$EventLogName,
        [Parameter(Mandatory)][string]$AppToken,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory)][string]$CurrentHost,
        [Parameter(Mandatory = $false)][string]$RefreshOnClose
    )
    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Clean temp files from $($Computer)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon broom) -size medium -Onclick {
            Show-UDModal -Header { "Clean temp files from $($Computer)" } -Content {
                New-UDGrid -Spacing '1' -Container -Content {
                    New-UDGrid -Item -Size 12 -Content {
                        New-UDCodeEditor -Id 'CleanClientCode' -ReadOnly -Height 450
                    }
                }
            } -Footer {
                New-UDButton -Text "Start" -OnClick {
                    $Btns = @("StartBtn", "CloseBtn")

                    foreach ($btn in $Btns) {
                        Set-UDElement -Id "$($btn)" -Properties @{
                            disabled = $true 
                            text     = "Cleaning..."
                        }
                    }

                    try {
                        Connect-PSUServer -ComputerName https://$CurrentHost -AppToken $AppToken
                        $Job = Invoke-PSUScript -Script 'CleanClient.ps1' -EventLogName $EventLogName -ActiveEventLog $ActiveEventLog -CleanComputer $Computer -User $User -LocalIpAddress $LocalIpAddress -RemoteIpAddress $RemoteIpAddress
                        while ($Job.Status -ne 'Completed') {
                            $JobOutput = (Get-PSUJobOutput -Job $Job).Data -join ([Environment]::NewLine)
                            Set-UDElement -Id 'CleanClientCode' -Properties @{
                                code = $JobOutput
                            } 
                            # Refresh job object
                            $Job = Get-PSUJob -Id $Job.Id
                        }
                        Set-UDElement -Id 'CloseBtn' -Properties @{
                            disabled = $false 
                            text     = "Close"
                        }

                        Set-UDElement -Id 'StartBtn' -Properties @{
                            disabled = $false 
                            text     = "Start"
                        }
                        Sync-UDElement -Id $RefreshOnClose
                    }
                    catch {
                        Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
 
                        Set-UDElement -Id 'CloseBtn' -Properties @{
                            disabled = $false 
                            text     = "Close"
                        }

                        Set-UDElement -Id 'StartBtn' -Properties @{
                            disabled = $false 
                            text     = "Start"
                        }
                        Break
                    }
                } -id 'StartBtn'

                New-UDButton -Text "Close" -OnClick {
                    Hide-UDModal
                } -id 'CloseBtn'
                                        
            } -FullWidth -MaxWidth 'md' -Persistent
        }
    }
}

Function Ping-ADComputer {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)][bool]$ActiveEventLog,
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory = $false)][string]$EventLogName,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress
    )
    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Send ping to $($Computer)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon hands_helping) -size medium -Onclick {
            Show-UDModal -Header { "Send ping to $($Computer)" } -Content {
                New-UDGrid -Spacing '1' -Container -Content {
                    New-UDDynamic -Id 'Ping' -content {
                        $PingColumns = @(
                            New-UDTableColumn -Property PingSucceeded  -Title "Ping Success" -IncludeInExport -IncludeInSearch -DefaultSortColumn
                            New-UDTableColumn -Property NameResolutionSucceeded  -Title "NS Success" -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Property TcpTestSucceeded  -Title "TCP Test Success" -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Property RemoteAddress  -Title "Remote Address" -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Property InterfaceAlias  -Title "Interface Alias" -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Property InterfaceDescription  -Title "Interface Description" -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Property ResolvedAddresses  -Title "Resolved Addresses" -IncludeInExport -IncludeInSearch
                        )

                        $PingResults = Test-NetConnection -ComputerName $Computer -InformationLevel "Detailed" | Foreach-Object {
                            if ($null -ne $_) {
                                [PSCustomObject]@{
                                    PingSucceeded           = $_.PingSucceeded
                                    NameResolutionSucceeded = $_.NameResolutionSucceeded
                                    TcpTestSucceeded        = $_.TcpTestSucceeded
                                    RemoteAddress           = $_.RemoteAddress
                                    InterfaceAlias          = $_.InterfaceAlias
                                    InterfaceDescription    = $_.InterfaceDescription
                                    ResolvedAddresses       = [string]$_.ResolvedAddresses
                                }
                            }
                        }

                        if ([string]::IsNullOrEmpty($PingResults)) {
                            New-UDGrid -Item -Size 12 -Content {
                                New-UDAlert -Severity 'error' -Text "Could not establish a connection to $($Computer)"
                            }
                        }
                        else {
                            New-UDGrid -Item -Size 12 -Content {
                                $SearchOption = New-UDTableTextOption -Search "Search"
                                New-UDTable -Id 'PingTable' -Data $PingResults -Columns $PingColumns -DefaultSortDirection "Ascending" -Sort -TextOption $SearchOption -ShowSearch -ShowPagination -Dense -Export -ExportOption "xlsx, PDF" -PageSize 20
                            }
                            if ($ActiveEventLog -eq "True") {
                                Write-EventLog -LogName $EventLogName -Source "SendPing" -EventID 10 -EntryType Information -Message "$($User) did ping $($Computer)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                            }
                        }
                    } -LoadingComponent {
                        New-UDProgress -Circular
                    }
                }
            } -Footer {
                New-UDButton -Text "Ping" -OnClick {
                    $Btns = @("PingBtn", "CloseBtn")

                    foreach ($btn in $Btns) {
                        Set-UDElement -Id "$($btn)" -Properties @{
                            disabled = $true 
                            text     = "Pinging..."
                        }
                    }
                    try {
                        
                        Sync-UDElement -Id "Ping"
                        
                        Set-UDElement -Id 'CloseBtn' -Properties @{
                            disabled = $false 
                            text     = "Close"
                        }
                        Set-UDElement -Id 'PingBtn' -Properties @{
                            disabled = $false 
                            text     = "Ping"
                        }
                    }
                    catch {
                        Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
 
                        Set-UDElement -Id 'CloseBtn' -Properties @{
                            disabled = $false 
                            text     = "Close"
                        }

                        Set-UDElement -Id 'PingBtn' -Properties @{
                            disabled = $false 
                            text     = "Ping"
                        }
                        Break
                    }
                } -id 'PingBtn'

                New-UDButton -Text "Close" -OnClick {
                    Hide-UDModal
                } -id 'CloseBtn'
            } -FullWidth
        }
    }
}

Function Remove-EdgeSettings {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][bool]$ActiveEventLog,
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory = $false)][string]$EventLogName,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )

    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Delete Edge settings on $($Computer)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon edge) -size medium -Onclick {
            $Profiles = Get-WmiObject -ClassName Win32_UserProfile -ComputerName $Computer | Select-Object localpath | where-object { $_.LocalPath -like "C:\Users\*" } | ForEach-Object { $_.localpath.Replace("C:\Users\", "") }
            Show-UDModal -Header { "Delete Edge settings on $($Computer)" } -Content {
                New-UDDynamic -Id 'EdgeStart' -content {
                    New-UDGrid -Spacing '1' -Container -Content {
                        New-UDGrid -Item -Size 1 -Content { }
                        New-UDGrid -Item -Size 10 -Content {
                            New-UDSelect -Id 'EdgeUser' -Option {
                                New-UDSelectOption -Name 'Select user...' -Value 1
                                foreach ($user in $profiles) {
                                    New-UDSelectOption -Name $user -Value $user
                                }
                            }
                        }
                        New-UDGrid -Item -Size 1 -Content { }
                    }
                } -LoadingComponent {
                    New-UDProgress -Circular
                }
            } -Footer {
                New-UDButton -Text "Delete" -OnClick { 
                    $UserToClean = Get-UDElement -Id 'EdgeUser'
                    $UserToClean = $UserToClean.value
                    if ([string]::IsNullOrEmpty($UserToClean) -or $UserToClean -eq 1) {
                        Show-UDToast -Message "You need to select a user!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        Break
                    }
                    else {
                        try {
                            Set-UDElement -Id "EdgeUser" -Properties @{
                                Disabled = $true
                            }
                            Set-UDElement -Id "DeleteBtn" -Properties @{
                                Text     = "Deleting..."
                                Disabled = $true
                            }
                           
                            Set-UDElement -Id "CloseBtn" -Properties @{
                                Text     = "Deleting..."
                                Disabled = $true
                            }
                            Invoke-Command -ComputerName $Computer -Scriptblock {
                                Param($UserToClean)
                                $edgestatus = $(try { Get-Process -Name msedge -ErrorAction stop } catch { $Null })
                                $msedgepath = "C:\Users\$($UserToClean)\AppData\Local\Microsoft\Edge\User Data\"

                                if ($Null -ne $edgestatus) {
                                    Stop-Process -Name msedge -Force
                                }

                                if (Test-Path -Path $msedgepath) {
                                    Remove-Item $msedgepath -Recurse -Force
                                }
                            } -ArgumentList $UserToClean

                            Show-UDToast -Message "Edge settings for $($UserToClean) on $($Computer) has now been deleted!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                            if ($ActiveEventLog -eq "True") {
                                Write-EventLog -LogName $EventLogName -Source "DeleteEdgeSettings" -EventID 10 -EntryType Information -Message "$($User) deleted Edge settings on $($Computer) for $($UserToClean)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                            }
                            Hide-UDModal
                            
                        }
                        catch {
                            Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                            Break
                            Set-UDElement -Id "EdgeUser" -Properties @{
                                Disabled = $false
                            }
                            Set-UDElement -Id "DeleteBtn" -Properties @{
                                Text     = "Delete"
                                Disabled = $false
                            }
                           
                            Set-UDElement -Id "CloseBtn" -Properties @{
                                Text     = "Close"
                                Disabled = $false
                            }
                        }
                    }
                } -Id "DeleteBtn"
                New-UDButton -Text "Close" -OnClick {
                    Hide-UDModal
                } -id "CloseBtn"
            } -FullWidth -MaxWidth 'xs' -Persistent
        }
    }
}

Export-ModuleMember -Function "Remove-EdgeSettings", "Ping-ADComputer", "Disconnect-UserFromComputer", "Restart-ADComputer", "Show-MonitorInfoBtn", "Show-InstalledDriversBtn", "Get-SysInfo", "Show-NetAdpBtn", "Show-ProcessTableBtn", "Show-InstalledSoftwareBtn", "Show-AutostartTableBtn", "Show-ServicesTableBtn", "Remove-UserProfilesBtn", "Compare-ComputerGrpsBtn", "Show-SchedualTaskTableBtn", "Remove-TempFilesClientBtn"