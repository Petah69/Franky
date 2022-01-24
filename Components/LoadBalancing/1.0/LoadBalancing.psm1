<# Change the Host1 etc. to the right hostname it should NOT be FQDN. Create one AppToken on each PowerShell Universal server
and remember the expiration date if you don't set it to never expire.
Then paste it inside matching hostname below inside the ""#>
function Get-AppToken {
    $CurrentHostName = [System.Net.Dns]::GetHostName()

    switch ($CurrentHostName) {
        Host1 {
            [PSCustomObject]@{
                CurrentAppToken = ""
            }
        }
        Host2 {
            [PSCustomObject]@{
                CurrentAppToken = ""
            }
        }
        Host3 {
            [PSCustomObject]@{
                CurrentAppToken = ""
            }
        }
    }
}

Export-ModuleMember -Function "Get-AppToken"