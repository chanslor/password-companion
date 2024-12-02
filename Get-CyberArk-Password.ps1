param (
    [string]$System,
    [switch]$Min,
    [switch]$All,
    [switch]$Change
)

if ($All) {
    $list = @('mdchansl')
} elseif ($System) {
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

$AUTH_URI = "https://$Server/PasswordVault/API/auth/Radius/Logon"
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

    $Versions_URI = "https://$Server/PasswordVault/API/Accounts/$accountId/Secret/Versions?showTemporary=false"
    Write-Output "Retrieving secret versions for account ID: $accountId"
    Write-Output "Versions URI: $Versions_URI"
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

    $Password_URI = "https://$Server/PasswordVault/api/Accounts/$accountId/Password/Retrieve"
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
    Write-Output "Password URI: $Password_URI"
    $password = Invoke-RestMethod -Method Post -Uri $Password_URI -Headers $Headers -Body $body
    Write-Output "Password retrieval complete for account ID: $accountId"
    return [pscustomobject]@{
        AccountId = $accountId
        Password = $password
    }
}

function Change-Password {
    param (
        [string]$accountId
    )

    $Change_URI = "https://$Server/PasswordVault/api/Accounts/$accountId/Change"
    $body = @{
        ChangeEntireGroup = $true
    } | ConvertTo-Json

    Write-Output "Attempting to change password for account ID: $accountId"
    Write-Output "Change URI: $Change_URI"
    $response = Invoke-RestMethod -Method Post -Uri $Change_URI -Headers $Headers -Body $body
    Write-Output "Password change complete for account ID: $accountId"
    return $response
}

$res = $list | % {
    $query = $_
    $Accounts_URI = "https://$Server/PasswordVault/API/Accounts?search=$query&searchtype=$searchtype"
    Write-Output "Accounts URI: $Accounts_URI"
    $this = Invoke-RestMethod –Headers $Headers –Method GET –Uri $Accounts_URI
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
        Write-Host "Account ID: $($this.value.id)"
        $versions = Get-SecretVersions -accountId $this.value.id
        $latestVersion = $versions | Sort-Object -Property versionId -Descending | Select-Object -First 1
        $passwordResult = Get-Password -accountId $this.value.id -reason "Access required" -ticketingSystemName "System" -ticketId "12345" -version $latestVersion.versionId -actionType "show" -isUse $false -machine "localhost"
        $this.value | Add-Member -NotePropertyName Password -NotePropertyValue $passwordResult.Password
        $this.value | Add-Member -NotePropertyName AccountId -NotePropertyValue $passwordResult.AccountId

        if ($Change) {
            Write-Host "`n`n`n`n`n Starting the change password process in CyberArk for AccountId: $($this.value.id) on $($this.value.address) `n`n`n`n`n" -ForegroundColor Red
			Start-Sleep -Seconds 5
			Change-Password -accountId $passwordResult.AccountId
        }
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
            $res.value | ? username -Match $UN | Select-Object query, address, userName, platformId, safeName, secretType, secret, platformAccountProperties, secretManagement, remoteMachinesAccess, createdTime, Password, AccountId
        }
    } else {
        $results = $res.value | Select-Object query, address, userName, platformId, safeName, secretType, secret, platformAccountProperties, secretManagement, remoteMachinesAccess, createdTime, Password, AccountId
    }

    Write-Output '', "$($results.count) Records returned for $($list.count) systems matching $($accounts.count) account name filter(s): $($accounts -join ',')"

    $results
}
