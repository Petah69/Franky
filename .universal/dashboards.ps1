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

New-PSUDashboard -Name "Franky" -FilePath "dashboards\Franky\Dashboard.ps1" -BaseUrl "/" -Framework "UniversalDashboard:Latest" -Environment "Franky" -Authenticated -Role @('Administrator', 'Franky') -Component @("Reports:1.0", "LoadBalancing:1.0", "ADComputer:1.0", "ADUser:1.0", "ADFunctions:1.0", "ADGroup:1.0", "PSUSpecific:1.0", "UniversalDashboard.Style:1.0.0", "UniversalDashboard.CodeEditor:1.2.0", "Other:1.0") -SessionTimeout 660 -IdleTimeout 180 -AutoDeploy -Description "Franky Support Dashboard!" 