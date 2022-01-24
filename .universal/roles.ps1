
# Enter your Domain LDAP adress here like LDAP://DC=FR,DC=SE
$RoleDomain = 'LDAP://'

New-PSURole -Name "Reader" -Description "Readers have read-only access to UA. They cannot make changes to any entity within the system." -Policy {
    param(
        $User
    )
        
    $UserName = ($User.Identity.Name)
    $UserName = $UserName.Split('\') | Select-Object -Last 1
        
    $IsMember = $false;
        

    $Searcher = New-Object DirectoryServices.DirectorySearcher
    $Searcher.SearchRoot = $RoleDomain
    $Searcher.Filter = "(&(objectCategory=person)(memberOf=))"
    $Users = $Searcher.FindAll()
    $Users | ForEach-Object {
        If ($_.Properties.samaccountname -eq $UserName) {
            $IsMember = $true;
        }
        else {

        }
    }
        
    return $IsMember
} 
New-PSURole -Name "Execute" -Description "Execute scripts within Universal Automation." -Policy {
    param(
        $User
    )
        
    $UserName = ($User.Identity.Name)
    $UserName = $UserName.Split('\') | Select-Object -Last 1
        
    $IsMember = $false;
        
    $Searcher = New-Object DirectoryServices.DirectorySearcher
    $Searcher.SearchRoot = $RoleDomain
    $Searcher.Filter = "(&(objectCategory=person)(memberOf=))"
    $Users = $Searcher.FindAll()
    $Users | ForEach-Object {
        If ($_.Properties.samaccountname -eq $UserName) {
            $IsMember = $true;
        }
        else {

        }
    }
        
    return $IsMember
} 
New-PSURole -Name "Administrator" -Description "Administrators can manage settings of UA, create and edit any entity within UA and view all the entities within UA." -Policy {
    param(
        $User
    )
        
    $UserName = ($User.Identity.Name)
    $UserName = $UserName.Split('\') | Select-Object -Last 1
        
    $IsMember = $false;
        
    $Searcher = New-Object DirectoryServices.DirectorySearcher
    $Searcher.SearchRoot = $RoleDomain
    $Searcher.Filter = "(&(objectCategory=person)(memberOf=))"
    $Users = $Searcher.FindAll()
    $Users | ForEach-Object {
        If ($_.Properties.samaccountname -eq $UserName) {
            $IsMember = $true;
        }
        else {

        }
    }
        
    return $IsMember
} 
New-PSURole -Name "Operator" -Description "Operators have access to manage and execute scripts, create other entities within UA but cannot manage UA itself." -Policy {
    param(
        $User
    )
        
    $UserName = ($User.Identity.Name)
    $UserName = $UserName.Split('\') | Select-Object -Last 1
        
    $IsMember = $false;
        
    $Searcher = New-Object DirectoryServices.DirectorySearcher
    $Searcher.SearchRoot = $RoleDomain
    $Searcher.Filter = "(&(objectCategory=person)(memberOf=))"
    $Users = $Searcher.FindAll()
    $Users | ForEach-Object {
        If ($_.Properties.samaccountname -eq $UserName) {
            $IsMember = $true;
        }
        else {

        }
    }
        
    return $IsMember
} 
New-PSURole -Name "PowerUser" -Description "User with rights to all sites and functions" -Policy {
    param(
        $User
    )
        
    $UserName = ($User.Identity.Name)
    $UserName = $UserName.Split('\') | Select-Object -Last 1
        
    $IsMember = $false;
        
    $Searcher = New-Object DirectoryServices.DirectorySearcher
    $Searcher.SearchRoot = $RoleDomain
    $Searcher.Filter = "(&(objectCategory=person)(memberOf=))"
    $Users = $Searcher.FindAll()
    $Users | ForEach-Object {
        If ($_.Properties.samaccountname -eq $UserName) {
            $IsMember = $true;
        }
        else {

        }
    }
        
    return $IsMember
} 

New-PSURole -Name "Franky" -Description "Gives change access to Franky Dashboard" -Policy {
    param(
        $User
    )
        
    $UserName = ($User.Identity.Name)
    $UserName = $UserName.Split('\') | Select-Object -Last 1
        
    $IsMember = $false;
        
    $Searcher = New-Object DirectoryServices.DirectorySearcher
    $Searcher.SearchRoot = $RoleDomain
    $Searcher.Filter = "(&(objectCategory=person)(memberOf=))"
    $Users = $Searcher.FindAll()
    $Users | ForEach-Object {
        If ($_.Properties.samaccountname -eq $UserName) {
            $IsMember = $true;
        }
        else {

        }
    }
        
    return $IsMember
}