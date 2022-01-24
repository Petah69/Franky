Set-PSUAuthenticationMethod -ScriptBlock {
    param(
        [PSCredential]$Credential
    )

    $Result = [Security.AuthenticationResult]::new()

    # Write your domain here for example; "LDAP://DC=FR,DC=SE"
    $CurrentDomain = "LDAP://"
    
    $domain = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain, ($Credential.UserName), $Credential.GetNetworkCredential().password)
    
    if ($domain.name -eq $null) {
        write-host "Authentication failed - please verify your username and password."
        $Result.UserName = ($Credential.UserName)
        $Result.Success = $false 
    }
    else {
        write-host "Successfully authenticated with domain $($domain.name)"
        $Result.UserName = ($Credential.UserName)
        $winident = [System.Security.Principal.WindowsIdentity]::new($domain.UserName)
        #Replace xxx below with the ID for your group that can access PSU
        if ($winident.HasClaim("http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", 'xxx')) {
            $Result.Success = $true
                
        }
        else {
            $Result.Success = $false
        }

    }
    
    $Result
}