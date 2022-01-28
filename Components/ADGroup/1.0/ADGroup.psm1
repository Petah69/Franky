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

Function New-ADGrp {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][bool]$ActiveEventLog,
        [Parameter(Mandatory = $false)][string]$EventLogName,
        [Parameter(Mandatory = $false)][string]$BoxToSync,
        [Parameter(Mandatory = $false)][string]$RefreshOnClose,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )
    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Create new group"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon users_cog) -size large -Onclick {
            Show-UDModal -Header { "Create new group" } -Content {
                New-UDGrid -Spacing '1' -Container -Content {
                    New-UDGrid -Item -Size 5 -Content {
                        New-UDTextbox -Id 'txtGrpCN' -Label 'Enter group name (CN/Name) (Required)' -FullWidth
                    }
                    New-UDGrid -Item -Size 2 -Content { }
                    New-UDGrid -Item -Size 5 -Content {
                        New-UDTextbox -Id 'txtGrpDisplayName' -Label 'Enter Display Name for the group' -FullWidth
                    }
                    New-UDGrid -Item -Size 5 -Content {
                        New-UDTextbox -Id 'txtGrpsAmAccountName' -Label 'Enter sAmAccountName for the group (Required)' -FullWidth
                    }
                    New-UDGrid -Item -Size 2 -Content { }
                    New-UDGrid -Item -Size 5 -Content {
                        New-UDTextbox -Id 'txtGrpDescription' -Label 'Enter description' -FullWidth
                    }
                    New-UDGrid -Item -Size 5 -Content {
                        New-UDTextbox -Id 'txtGrpInfo' -Label 'Enter Info' -FullWidth
                    }
                    New-UDGrid -Item -Size 2 -Content { }
                    New-UDGrid -Item -Size 5 -Content {
                        New-UDTextbox -Id 'txtGrpOwner' -Label 'Enter manage by (AD-User)' -FullWidth
                    }
                    New-UDGrid -Item -Size 12 -Content {
                        New-UDHtml -Markup "</br>"
                    }
                    New-UDGrid -Item -Size 6 -Content {
                        New-UDTypography -Text "Select Group Scope (Required)"
                        New-UDRadioGroup -id "radioScope" -Label "Group Scope" -Content {
                            New-UDRadio -Label Global -Value 'Global'
                            New-UDRadio -Label Universal -Value 'Universal'
                        }
                    }
                    New-UDGrid -Item -Size 6 -Content {
                        New-UDTypography -Text "Select Group Category (Required)"
                        New-UDRadioGroup -id "radioCategory" -Label "Group Category" -Content {
                            New-UDRadio -Label Security -Value 'Security'
                            New-UDRadio -Label Distribution -Value 'Distribution'
                        }
                    }
                }
            } -Footer {
                New-UDButton -text 'Create' -Onclick {
                    $GrpCN = (Get-UDElement -Id "txtGrpCN").value
                    $GrpsAmAccountName = (Get-UDElement -Id "txtGrpsAmAccountName").value
                    $GrpDisplayName = (Get-UDElement -Id "txtGrpDisplayName").value
                    $GrpDescription = (Get-UDElement -Id "txtGrpDescription").value
                    $GrpInfo = (Get-UDElement -Id "txtGrpInfo").value
                    $GrpScope = (Get-UDElement -Id "radioScope").value
                    $GrpCategory = (Get-UDElement -Id "radioCategory").value
                    $GrpOwner = (Get-UDElement -Id "txtGrpOwner").value
                    $GrpCN = $GrpCN.trim()
                    $GrpsAmAccountName = $GrpsAmAccountName.trim()
                    $GrpDisplayName = $GrpDisplayName.trim()
                    $GrpOwner = $GrpOwner.trim()

                  
                    if ([string]::IsNullOrEmpty($GrpsAmAccountName) -or [string]::IsNullOrEmpty($GrpCN) -or [string]::IsNullOrEmpty($GrpScope) -or [string]::IsNullOrEmpty($GrpCategory)) {
                        Show-UDToast -Message "You must enter all the required options above!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        Break
                    }
                    else {
                        if ([string]::IsNullOrEmpty($GrpInfo)) {
                            $GrpInfo = "."
                        }
                        if ([string]::IsNullOrEmpty($GrpDisplayName)) {
                            $GrpDisplayName = $GrpsAmAccountName
                        }

                        if (Get-ADGroup -Filter "samaccountname -eq '$($GrpsAmAccountName)'" -properties SamAccountName) {
                            Show-UDToast -Message "It's already a group with the SamAccountName $($GrpsAmAccountName) in the AD!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                            Break
                        }
                        else {
                            try {
                                New-ADGroup -Name $GrpCN -SamAccountName $GrpsAmAccountName -GroupCategory $GrpCategory -GroupScope $GrpScope -DisplayName $GrpDisplayName -Path $OUGrpPath -Description $GrpDescription -ManagedBy $GrpOwner -OtherAttributes @{ 'info' = $GrpInfo }
                                Show-UDToast -Message "$($GrpCN) has been created!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                if ($ActiveEventLog -eq "True") {
                                    Write-EventLog -LogName $EventLogName -Source "CreatedGroup" -EventID 10 -EntryType Information -Message "$($User) did create the group $($GrpCN)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                }
                                Set-UDElement -Id $BoxToSync -Properties @{
                                    Value = $GrpsAmAccountName
                                }
                                Sync-UDElement -id $RefreshOnClose
                                Hide-UDModal
                            }
                            catch {
                                Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                Break
                            }
                        }
                    }
                }
                New-UDButton -Text "Close" -OnClick {
                    Hide-UDModal
                }
            } -FullWidth -MaxWidth 'md' -Persistent
        }
    }
}

function Add-MultiGroupBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][bool]$ActiveEventLog,
        [Parameter(Mandatory)][string]$ObjToAdd,
        [Parameter(Mandatory = $false)][string]$EventLogName,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress,
        [Parameter(Mandatory = $false)][string]$RefreshOnClose

    )

    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Add $($ObjToAdd) to multiple groups at the same time"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon users) -size large -Onclick {
            Show-UDModal -Header { "Add $($ObjToAdd) to multiple groups at the same time" } -Content {
                New-UDDynamic -Id 'MoreComputerSearchGroupList' -content {
                    $MoreADGroupData = Get-ADGroup -Filter * -Properties Info, samAccountName, Description | Select-Object @("samAccountName", "info", "Description")
                    $MoreADGroupColumns = @(
                        New-UDTableColumn -Property samAccountName -Title "Group name" -IncludeInSearch
                        New-UDTableColumn -Property Description -Title "Description" -IncludeInSearch
                        New-UDTableColumn -Property Info -Title "Info" -IncludeInSearch
                    )
                    New-UDTable -Id 'MoreADTable' -Data $MoreADGroupData -Columns $MoreADGroupColumns -Title "Select group" -ShowSearch -ShowPagination -Dense -Sort -PageSize 10 -PageSizeOptions @(10, 20) -DisablePageSizeAll -ShowSelection
                } -LoadingComponent {
                    New-UDProgress -Circular
                }
            } -Footer {
                New-UDButton -Text "Add selected" -OnClick {
                    $MoreADTable = Get-UDElement -Id "MoreADTable"
                    $MoreADLog = @($MoreADTable.selectedRows.samAccountName)
                    if ($null -ne $MoreADTable.selectedRows.samAccountName) {
                        try {
                            @($MoreADTable.selectedRows.samAccountName.ForEach( { 
                                        Add-ADGroupMember -Identity $_ -Members $ObjToAdd  -Confirm:$False
                                        if ($ActiveEventLog -eq "True") {
                                            Write-EventLog -LogName $EventLogName -Source "AddToGroup" -EventID 10 -EntryType Information -Message "$($User) did add $($_) to $($ObjToAdd)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                        }
                                    } ) )
                            Show-UDToast -Message "$($ObjToAdd) are now member in $($MoreADLog -join ",")!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                            Sync-UDElement -Id $RefreshOnClose
                            Hide-UDModal
                        }
                        catch {
                            Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                            Break
                        }
                    }
                    else {
                        Show-UDToast -Message "You must select a group!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        Break
                    }
                }
                New-UDButton -Text "Close" -OnClick {
                    Hide-UDModal
                }
                                        
            } -FullWidth -Persistent
        }
    }
}

function Edit-GroupInfoBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][bool]$ActiveEventLog,
        [Parameter(Mandatory)][string]$GroupName,
        [Parameter(Mandatory = $false)][string]$EventLogName,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$CurrentValue,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )
    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Change info for $($GroupName)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon pencil_square) -size small -Onclick { 
            Show-UDModal -Header { "Change info for $($GroupName)" } -Content {
                New-UDGrid -Spacing '1' -Container -Content {
                    New-UDGrid -Item -Size 12 -Content {
                        New-UDTextbox -Id "txtChangeinfo" -Label "Enter Info" -Value $CurrentValue -FullWidth
                    }
                }
            } -Footer {
                New-UDButton -Text "Save" -OnClick {
                    $NewInfo = (Get-UDElement -Id "txtChangeinfo").value

                    try {
                        Set-ADGroup -Identity $GroupName  -Replace @{info = "$($NewInfo)" }
                        if ($ActiveEventLog -eq "True") {
                            Write-EventLog -LogName $EventLogName -Source "EditGroupInfo" -EventID 10 -EntryType Information -Message "$($User) did edit info on $($GroupName) to $($NewInfo)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                        }
                        Sync-UDElement -Id 'GroupSearch'
                        Show-UDToast -Message "Info for $($GroupName) has now been changed!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        Hide-UDModal
                    }
                    catch {
                        Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        Break
                    }
                }
                New-UDButton -Text "Clear" -OnClick {
                    try {
                        Set-ADGroup -Identity $GroupName  -Replace @{info = "$($null)" }
                        if ($ActiveEventLog -eq "True") {
                            Write-EventLog -LogName $EventLogName -Source "ClearGroupInfo" -EventID 10 -EntryType Information -Message "$($User) did clear info on $($GroupName)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                        }
                        Sync-UDElement -Id 'GroupSearch'
                        Show-UDToast -Message "Info for $($GroupName) has now been cleared!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        Hide-UDModal
                    }
                    catch {
                        Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        Break
                    }
                }
                New-UDButton -Text "Close" -OnClick {
                    Hide-UDModal
                }
            } -FullWidth -MaxWidth 'sm' -Persistent
        }
    }
}

function Set-GroupScopeBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][bool]$ActiveEventLog,
        [Parameter(Mandatory)][string]$GroupName,
        [Parameter(Mandatory = $false)][string]$CurrentGroupScope,
        [Parameter(Mandatory = $false)][string]$EventLogName,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )
    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Change group scope for $($GroupName)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon pencil_square) -size small -Onclick { 
            Show-UDModal -Header { "Change group scope for $($GroupName)" } -Content {
                New-UDGrid -Spacing '1' -Container -Content {
                    New-UDGrid -Item -Size 12 -Content {
                        New-UDRadioGroup -id "radioScope" -Label "Group Scope" -Content {
                            New-UDRadio -Label Global -Value 'Global'
                            New-UDRadio -Label Universal -Value 'Universal'
                        }
                    }
                }
            } -Footer {
                New-UDButton -Text "Save" -OnClick {
                    $NewScope = (Get-UDElement -Id "radioScope").value
                    try {
                        Set-ADGroup -Identity $GroupName  -GroupScope $NewScope
                        if ($ActiveEventLog -eq "True") {
                            Write-EventLog -LogName $EventLogName -Source "ChangeGroupScope" -EventID 10 -EntryType Information -Message "$($User) did change group scope for $($GroupName) from $($CurrentGroupScope) to $($NewScope)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                        }
                        Sync-UDElement -Id 'GroupSearch'
                        Show-UDToast -Message "Group Scope for $($GroupName) are now set to $($NewScope)" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        Hide-UDModal
                    }
                    catch {
                        Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        Break
                    }
                }
                New-UDButton -Text "Close" -OnClick {
                    Hide-UDModal
                }
            } -FullWidth -MaxWidth 'xs' -Persistent
        }
    }
}

function Set-GroupCategoryBtn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][bool]$ActiveEventLog,
        [Parameter(Mandatory)][string]$GroupName,
        [Parameter(Mandatory = $false)][string]$CurrentGroupCategory,
        [Parameter(Mandatory = $false)][string]$EventLogName,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )

    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "Change group category for $($GroupName)"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon pencil_square) -size small -Onclick { 
            Show-UDModal -Header { "Change group category for $($GroupName)" } -Content {
                New-UDGrid -Spacing '1' -Container -Content {
                    New-UDGrid -Item -Size 12 -Content {
                        New-UDRadioGroup -id "radioCategory" -Label "Group Category" -Content {
                            New-UDRadio -Label Security -Value 'Security'
                            New-UDRadio -Label Distribution -Value 'Distribution'
                        }
                    }
                }
            } -Footer {
                New-UDButton -Text "Save" -OnClick {
                    $NewCategory = (Get-UDElement -Id "radioCategory").value
                    try {
                        Set-ADGroup -Identity $GroupName -GroupCategory $NewCategory
                        if ($ActiveEventLog -eq "True") {
                            Write-EventLog -LogName $EventLogName -Source "ChangeGroupCategory" -EventID 10 -EntryType Information -Message "$($User) did change group category for $($GroupName) from $($CurrentGroupCategory) to $($NewCategory)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                        }
                        Sync-UDElement -Id 'GroupSearch'
                        Show-UDToast -Message "Group Category for $($GroupName) are now set to $($NewCategory)" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        Hide-UDModal
                    }
                    catch {
                        Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                        Break
                    }
                }
                New-UDButton -Text "Close" -OnClick {
                    Hide-UDModal
                }
            } -FullWidth -MaxWidth 'xs' -Persistent
        }
    }
}

Function Show-ADGroupMemberOf {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][bool]$ActiveEventLog,
        [Parameter(Mandatory)][string]$ObjectName,
        [Parameter(Mandatory = $false)][string]$EventLogName,
        [Parameter(Mandatory = $false)][string]$RefreshOnClose,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$LocalIpAddress,
        [Parameter(Mandatory = $false)][string]$RemoteIpAddress
    )
    New-UDTooltip -TooltipContent {
        New-UDTypography -Text "See what groups $($ObjectName) are member of"
    } -content { 
        New-UDButton -Icon (New-UDIcon -Icon users) -size medium -Onclick { 
            Show-UDModal -Header { "$($ObjectName) are member of" } -Content {
                New-UDDynamic -Id 'MemberOf' -content {
                    New-UDGrid -Spacing '1' -Container -Content {
                        $Columns = @(
                            New-UDTableColumn -Title 'Name' -Property 'Name' -IncludeInExport -IncludeInSearch -DefaultSortColumn
                            New-UDTableColumn -Title 'SamAccountName' -Property 'SamAccountName' -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Title 'Description' -Property 'Description' -IncludeInExport -IncludeInSearch
                            New-UDTableColumn -Title 'Info' -Property 'Info' -IncludeInExport -IncludeInSearch
                        )

                        $DisplayData = Get-ADPrincipalGroupMembership -Identity $ObjectName | Get-ADGroup -properties info, name, SamAccountName, Description  | Select-Object @("Name", "Samaccountname", "Description", "info")

                        if ([string]::IsNullOrEmpty($DisplayData)) {
                            New-UDGrid -Item -Size 12 -Content {
                                New-UDAlert -Severity 'info' -Text "$($ObjectName) are not member of any group!"
                            }
                        }
                        else {
                            New-UDGrid -Item -Size 12 -Content {
                                $SearchOption = New-UDTableTextOption -Search "Search"
                                New-UDTable -id 'MemberOfTable' -Columns $Columns -Data $DisplayData -DefaultSortDirection "Ascending" -Sort -ShowSelection -TextOption $SearchOption -ShowSearch -ShowPagination -Dense -Export -ExportOption "xlsx, PDF" -PageSize 50
                            }
                        }
                        if ($null -ne $DisplayData) {
                            New-UDGrid -Item -Size 2 -Content {
                                New-UDTooltip -TooltipContent {
                                    New-UDTypography -Text "Delete from selected groups"
                                } -content { 
                                    New-UDButton -Icon (New-UDIcon -Icon trash_alt) -Size large -OnClick {
                                        $MemberOfTable = Get-UDElement -Id "MemberOfTable"
                                        if ($Null -ne $MemberOfTable.selectedRows.SamAccountName) {
                                            try {
                                                $MemberOfTableSelect = @($MemberOfTable.selectedRows.SamAccountName.ForEach( { 
                                                            Remove-ADGroupMember -Identity $_ -Members $ObjectName  -Confirm:$False
                                                            if ($ActiveEventLog -eq "True") {
                                                                Write-EventLog -LogName $EventLogName -Source "RemoveFromGroup" -EventID 10 -EntryType Information -Message "$($User) did remove $($ObjectName) from $($_)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                                            }
                                                        } ) )
                                                Show-UDToast -Message "$($ObjectName) has been removed from $($MemberOfTable.selectedRows.SamAccountName -join ",")" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Sync-UDElement -Id 'MemberOf'
                                            }
                                            catch {
                                                Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Break
                                            }
                                        }
                                        else {
                                            Show-UDToast -Message "You have not selected anything, you need to do that to delete a member!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                            Break
                                        }
                                    }
                                }
                            }
                            New-UDGrid -Item -Size 3 -Content { }
                        }
                        else {
                            New-UDGrid -Item -Size 5 -Content { }
                        }
                        New-UDGrid -Item -Size 5 -Content {
                            New-UDTextbox -Id "txtAddTo" -Label "Enter the group you want to join" -FullWidth
                        }
                        New-UDGrid -Item -Size 2 -Content { 
                            New-UDTooltip -TooltipContent {
                                New-UDTypography -Text "Join group"
                            } -content { 
                                New-UDButton -Icon (New-UDIcon -Icon user_plus) -size large -Onclick { 
                                    $AddToGroup = (Get-UDElement -Id "txtAddTo").value
                                    $AddToGroup = $AddToGroup.trim()
                                    
                                    if (Get-ADGroup -Filter "Samaccountname -eq '$($AddToGroup)'") { 
                                        if ($Null -ne $AddToGroup) {
                                            try {
                                                Add-ADGroupMember -Identity $AddToGroup -Members $ObjectName 
                                                if ($ActiveEventLog -eq "True") {
                                                    Write-EventLog -LogName $EventLogName -Source "AddToGroup" -EventID 10 -EntryType Information -Message "$($User) did add $($ObjectName) to $($AddToGroup)`nLocal IP:$($LocalIpAddress)`nExternal IP: $($RemoteIpAddress)" -Category 1 -RawData 10, 20 
                                                }
                                                Show-UDToast -Message "$($AddToGroup) are now member of $($AddToGroup)!" -MessageColor 'green' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Sync-UDElement -Id 'MemberOf'
                                            }
                                            catch {
                                                Show-UDToast -Message "$($PSItem.Exception)" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                                Break
                                            }
                                        }
                                        else {
                                            Show-UDToast -Message "You must enter a group name!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                            Break
                                        }
                                    }
                                    else {
                                        Show-UDToast -Message "$($AddToGroup) did not exist in the AD!" -MessageColor 'red' -Theme 'light' -TransitionIn 'bounceInUp' -CloseOnClick -Position center -Duration 3000
                                        Break
                                    }
                                }
                            }
                        }
                        
                    }
                } -LoadingComponent {
                    New-UDProgress -Circular
                }
            } -Footer {
                New-UDButton -Text "Refresh" -OnClick {
                    Sync-UDElement -id 'MemberOf'
                }
                New-UDButton -Text "Close" -OnClick {
                    Hide-UDModal
                }
            } -FullWidth -MaxWidth 'lg' -Persistent
        }
    }
}

Export-ModuleMember -Function "New-ADGrp", "Add-MultiGroupBtn", "Edit-GroupInfoBtn", "Set-GroupScopeBtn", "Set-GroupCategoryBtn", "Show-ADGroupMemberOf"