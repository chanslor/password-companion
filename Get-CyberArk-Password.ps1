param (

    [string]$System,

    [switch]$Min

)

 

if ($System) {

    $list = $System -split ' '

} else {

    # Prompt for the list of systems

    $listInput = Read-Host "Please enter the system in which you would like password, space separated"

    $list = $listInput -split ' '

}

 

$Server = 'vault' + '.' + $ENV:userdnsdomain

$msg = 'Please enter RSA Pin + Tokencode to access CyberArk'

 

#$searchtype = 'startswith'

$searchtype = 'contains'

 

$AUTH_URI = https://$Server/PasswordVault/API/auth/Radius/Logon

$Headers = @{

    'accept' = 'application/json'

    'content-type' = 'application/json'

}

 

$token = try {

    Invoke-RestMethod –Method Post –Uri $AUTH_URI –Headers $Headers -Body $(

        @{

            username = "$($env:UserName)"

            password = "$($(Get-Credential –Message $msg –UserName $env:UserName).GetNetworkCredential().password)"

        } | ConvertTo-Json

    )

} catch {

    Write-Error 'Auth Error: Verify PIN + RSAtoken'

    break

}

 

$Headers = $Headers + @{ Authorization = $token }

 

function Get-SecretVersions {

    param (

        [string]$accountId

    )

 

    $Versions_URI = https://$Server/PasswordVault/API/Accounts/$accountId/Secret/Versions?showTemporary=false

    Write-Output "Retrieving secret versions for account ID: $accountId"

    $versions = Invoke-RestMethod -Method Get -Uri $Versions_URI -Headers $Headers

    Write-Output "Secret versions retrieval complete for account ID: $accountId"

    return $versions.Versions

}

 

function Get-Password {

    param (

        [string]$accountId,

        [string]$reason,

        [string]$ticketingSystemName,

        [string]$ticketId,

        [int]$version,

        [string]$actionType,

        [bool]$isUse,

        [string]$machine

    )

 

    $Password_URI = https://$Server/PasswordVault/api/Accounts/$accountId/Password/Retrieve

    $body = @{

        reason = $reason

        TicketingSystemName = $ticketingSystemName

        TicketId = $ticketId

        Version = $version

        ActionType = $actionType

        isUse = $isUse

        Machine = $machine

    } | ConvertTo-Json

 

    Write-Output "Attempting to retrieve password for account ID: $accountId with version: $version"

    $password = Invoke-RestMethod -Method Post -Uri $Password_URI -Headers $Headers -Body $body

    Write-Output "Password retrieval complete for account ID: $accountId"

    return $password

}

 

$res = $list | % {

    $query = $_

    $this = Invoke-RestMethod –Headers $Headers –Method GET –Uri https://$Server/PasswordVault/API/Accounts?search=$query&searchtype=$searchtype

    if ($this.count -eq 0) {

        $this = [pscustomobject]@{

            value = [pscustomobject]@{

                query = $query

                address = 'NONE'

                userName = 'NONE'

                platformId = 'NONE'

                safeName = 'NONE'

                secretType = 'NONE'

                secret = 'NONE'

                platformAccountProperties = @{}

                secretManagement = [pscustomobject]@{

                    automaticManagementEnabled = $false

                    manualManagementReason = 'NONE'

                    status = 'NONE'

                    lastModifiedTime = 0

                    lastReconciledTime = 0

                    lastVerifiedTime = 0

                }

                remoteMachinesAccess = [pscustomobject]@{

                    remoteMachines = 'NONE'

                    accessRestrictedToRemoteMachines = $false

                }

                createdTime = 0

            }

        }

    } else {

        $this.value | Add-Member -NotePropertyName Query -NotePropertyValue $query

        $versions = Get-SecretVersions -accountId $this.value.id

        $latestVersion = $versions | Sort-Object -Property versionId -Descending | Select-Object -First 1

        $this.value | Add-Member -NotePropertyName Password -NotePropertyValue (Get-Password -accountId $this.value.id -reason "Access required" -ticketingSystemName "System" -ticketId "12345" -version $latestVersion.versionId -actionType "show" -isUse $false -machine "localhost")

    }

    $this

}

 

if ($Min) {

    $passwords = $res | ForEach-Object { $_.value.Password }

    $passwords -join "`n" | Set-Clipboard

    Write-Host "Passwords have been copied to the clipboard." -ForegroundColor Green

    $passwords

} else {

    Write-Output 'CyberArk API Query - ' + (Get-Date).ToString()

 

    if ($accounts) {

        $results = $accounts | % {

            $UN = $NULL

            $UN = $_

            $res.value | ? username -Match $UN | Select-Object query, address, userName, platformId, safeName, secretType, secret, platformAccountProperties, secretManagement, remoteMachinesAccess, createdTime, Password

        }

    } else {

        $results = $res.value | Select-Object query, address, userName, platformId, safeName, secretType, secret, platformAccountProperties, secretManagement, remoteMachinesAccess, createdTime, Password

    }

 

    Write-Output '', "$($results.count) Records returned for $($list.count) systems matching $($accounts.count) account name filter(s): $($accounts -join ',')"

 

    $results

}

