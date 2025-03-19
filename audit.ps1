<#
.SYNOPSIS
    Audits folder security permissions and generates detailed reports. Working on cross-platform support.

.DESCRIPTION
    This script analyzes folder permissions and creates CSV reports of access rights.
    Can optionally use LDAP to enrich AD account information and use SMTP for email reports.

.PARAMETER Path
    The root folder path to audit. Must be specified if CsvPaths is not specified.

.PARAMETER CsvPaths
    Path to a CSV file containing multiple folder paths to audit. Must be specified if Path is not specified.
    The schema of the CSV file should be: Path, FolderLevel, Exclude.

.PARAMETER OutputPath
    Where to save the CSV report (folder or direct .csv path).

.PARAMETER FolderLevel
    How many subfolder levels deep to audit (default: 1). Use 0 to audit all levels.

.PARAMETER DropInheritance
    Switch to omit folders with inherited permissions.

.PARAMETER ConfigFile
    Path to JSON configuration file allowing use of LDAP and email. See SecurityAuditConfig class for available settings.

.INPUTS
    None.

.OUTPUTS
    CSV report with columns: Path, Account, AccessType, Rights, Inherited, AccountType, Enabled, AccountExpires.

.EXAMPLE
    Basic local audit:
    .\audit.ps1 -Path "D:\SharedFolder" -OutputPath "D:\Reports"

.EXAMPLE
    With custom config:
    .\audit.ps1 -Path "D:\SharedFolder" -OutputPath "D:\Reports" -ConfigFile "config.json"

.EXAMPLE
    With inheritance check:
    .\audit.ps1 -Path "D:\SharedFolder" -OutputPath "D:\Reports" -DropInheritance

.EXAMPLE
    With CSV input:
    .\audit.ps1 -CsvPaths "D:\PathsToAudit.csv" -OutputPath "D:\Reports"

.NOTES
    Requirements:
    - PowerShell 7.0+
#>

# Requires -Version 7.0

[CmdletBinding(DefaultParameterSetName = "SinglePath")]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "SinglePath")]
    [string]$Path,

    [Parameter(Mandatory = $true, ParameterSetName = "CsvInput")]
    [string]$CsvPaths,

    [Parameter(Mandatory)]
    [string]$OutputPath,

    [int]$FolderLevel = 1,

    [switch]$DropInheritance = $false,

    [string]$ConfigFile
)

class SecurityAuditConfig {
    [string[]]$IgnoreLocalSystem = @(
        "NT AUTHORITY\SYSTEM",
        "NT AUTHORITY\NETWORK SERVICE",
        "NT AUTHORITY\LOCAL SERVICE",
        "CREATOR OWNER",
        "NT AUTHORITY\INTERACTIVE",
        "BUILTIN\Users",
        "Everyone"
    )
    [string[]]$IgnoreLocalGroups = @(
        "BUILTIN\Administrators",
        "BUILTIN\Users",
        "BUILTIN\Power Users"
    )
    [string[]]$IgnoreLocalMembers = @(
        "NT AUTHORITY\SYSTEM",
        "Administrator",
        "ASPNET"
    )
    [string[]]$IgnoreADGroups = @(
        "Domain Users",
        "Domain Admins",
        "Enterprise Admins"
    )
    [string[]]$IgnoreADMembers = @("Administrator")

    [bool]$EnableLdap = $false
    [string]$GCServer
    [int]$GCPort
    [bool]$GCAnonAuth
    [string]$GCUser
    [string]$GCPassword
    [string]$GCBaseDN

    [bool]$EnableEmail = $false
    [string]$SmtpServer
    [int]$SmtpPort
    [bool]$SmtpAuth
    [string]$SmtpUser
    [string]$SmtpPassword
    [string]$EmailFrom
    [string]$EmailTo
    [string]$EmailCc
    [string]$EmailSubject
}

function ProcessCsvPathsInput {
    param ([string]$csvPaths)
    $csvData = Import-Csv -Path $csvPaths
    $csvData | ForEach-Object {
        $folderPath = Resolve-Path -Path $_.Path | Select-Object -ExpandProperty Path
        $folderLevel = if ($null -eq $_.FolderLevel) { 1 } else { $_.FolderLevel }
        $exclude = if ($_.Exclude -eq "1") { $true } else { $false }
        return [PSCustomObject]@{
            Path        = $folderPath
            FolderLevel = $folderLevel
            Exclude     = $exclude
        }
    }
}

function TranslateUnixPerms {
    param (
        [string]$perms,
        [string]$position
    )

    Write-Debug "Processing permission string: $perms for position: $position"

    if ([string]::IsNullOrEmpty($perms)) {
        Write-Warning "Empty permission string received"
        return "Unknown"
    }

    $rights = @()

    if (-not ($perms -match '^[-drwx]{10}$')) {
        Write-Warning "Invalid permission format: $perms"
        return "Unknown"
    }
    
    $start = switch ($position) {
        "user" { 1 }
        "group" { 4 }
        "other" { 7 }
        default { 
            Write-Warning "Invalid position: $position"
            return "Unknown"
        }
    }

    try {
        $chunk = $perms.Substring($start, 3)
        
        if ($chunk[0] -eq 'r') { $rights += "Read" }
        if ($chunk[1] -eq 'w') { $rights += "Write" }
        if ($chunk[2] -eq 'x') { $rights += "Execute" }

        if ($rights.Count -eq 0) { return "None" }
        return $rights -join ", "
    }
    catch {
        Write-Warning "Error processing permission string: $_"
        return "Unknown"
    }
}

function Get-WindowsPermissions {
    param([string]$folderPath)

    $acl = Get-Acl -Path $folderPath
    return $acl.Access | ForEach-Object {
        [PSCustomObject]@{
            Path           = $folderPath
            Account        = $_.IdentityReference.Value
            AccessType     = $_.AccessControlType.ToString()
            Rights         = TranslateAccessMask -AccessMask $_.FileSystemRights.Value__
            Inherited      = $_.IsInherited
            AccountType    = ""
            Enabled        = ""
            AccountExpires = ""
        }
    }
}

function Get-UnixPermissions {
    param([string]$folderPath)

    try {
        if (-not (Test-Path -Path $folderPath)) {
            throw "Path not found: $folderPath"
        }

        $rawPerms = if ($IsLinux) {
            $result = & stat -c '%a %U %G' $folderPath
            if ($LASTEXITCODE -ne 0) { throw "stat command failed" }
            $result
        }
        else {
            $result = & stat -f '%Op %Su %Sg' $folderPath
            if ($LASTEXITCODE -ne 0) { throw "stat command failed" }
            $result
        }

        $parts = $rawPerms.Split()
        $perms = $parts[0]
        $owner = $parts[1]
        $group = $parts[2]
        
        Write-Debug "Raw permissions: $rawPerms"
        Write-Debug "Parsed: perms=$perms owner=$owner group=$group"

        $permBits = [Convert]::ToString([Convert]::ToInt32($perms, 8), 2).PadLeft(9, '0')
        $userPerms = $permBits.Substring(0, 3)
        $groupPerms = $permBits.Substring(3, 3)

        return @(
            [PSCustomObject]@{
                Path           = $folderPath
                Account        = $owner
                AccessType     = "Owner"
                Rights         = ConvertPermBitsToRights -bits $userPerms
                Inherited      = $false
                AccountType    = ""
                Enabled        = ""
                AccountExpires = ""
            },
            [PSCustomObject]@{
                Path           = $folderPath
                Account        = $group
                AccessType     = "Group"
                Rights         = ConvertPermBitsToRights -bits $groupPerms
                Inherited      = $false
                AccountType    = ""
                Enabled        = ""
                AccountExpires = ""
            }
        )
    }
    catch {
        throw "Error getting permissions: $_"
    }
}

function ConvertPermBitsToRights {
    param([string]$bits)

    $rights = @()
    if ($bits[0] -eq '1') { $rights += "Read" }
    if ($bits[1] -eq '1') { $rights += "Write" }
    if ($bits[2] -eq '1') { $rights += "Execute" }

    return $rights -join ", "
}

function Get-FilePermissions {
    param([string]$folderPath)

    if ($IsWindows) {
        return Get-WindowsPermissions -folderPath $folderPath
    }
    elseif ($IsLinux -or $IsMacOS) {
        return Get-UnixPermissions -folderPath $folderPath
    }
    else {
        throw "Unsupported operating system"
    }
}

function AuditFolder {
    param(
        [string[]]$folderPaths,
        [int]$maxDepth,
        [SecurityAuditConfig]$config,
        [System.Collections.ArrayList]$results,
        [System.Collections.ArrayList]$errors,
        [string[]]$excludedPaths,
        [switch]$DropInheritance
    )

    foreach ($folderPath in $folderPaths) {
        if ($folderPath -in $excludedPaths) {
            Write-Host "Skipping folder: $folderPath"
            continue
        }

        try {
            $filePerms = Get-FilePermissions -folderPath $folderPath

            foreach ($ace in $filePerms) {
                if ($DropInheritance -and $ace.Inherited) {
                    continue
                }
                if (ShouldProcessAce $ace $config) {
                    ProcessAccessRule -ace $ace -path $folderPath -config $config -results $results
                }
            }

            if ($maxDepth -ne 0) {
                Get-ChildItem -Path $folderPath -Directory | ForEach-Object {
                    AuditFolder -folderPaths @($_.FullName) `
                                -maxDepth ($maxDepth -eq -1 ? -1 : $maxDepth - 1) `
                                -config $config `
                                -results $results `
                                -errors $errors `
                                -excludedPaths $excludedPaths `
                                -DropInheritance:$DropInheritance
                }
            }
        }
        catch {
            $null = $errors.Add("Error processing folder $folderPath : $_")
        }
    }
}

function TranslateAccessMask {
    param ([int]$AccessMask)
    $permissions = @()

    $accessMap = @{
        0x1F01FF   = "Full Control"
        0x1301BF   = "Modify"
        0x1200A9   = "Read & Execute"
        0x1200FF   = "Read & Execute & Write"
        0x10000000 = "Generic Read"
        0x20000000 = "Generic Write"
        0x40000000 = "Generic Execute"
        0x80000000 = "Generic All"
        0x00000001 = "List Directory"
        0x00000002 = "Add File"
        0x00000004 = "Add Subdirectory"
        0x00000008 = "Read EA"
        0x00000010 = "Write EA"
        0x00000020 = "Execute"
        0x00000040 = "Delete Child"
        0x00000080 = "Read Attributes"
        0x00000100 = "Write Attributes"
        0x00010000 = "Delete"
        0x00020000 = "Read Control"
        0x00040000 = "Write DAC"
        0x00080000 = "Write Owner"
        0x00100000 = "Synchronize"
    }

    foreach ($key in $accessMap.Keys) {
        if (($AccessMask -band $key) -eq $key) {
            $permissions += $accessMap[$key]
        }
    }

    if ($permissions.Count -eq 0) { return "Special Permissions" }

    return $permissions -join ", "
}

function ProcessAccessRule {
    param (
        [PSCustomObject]$ace,
        [string]$path,
        [SecurityAuditConfig]$config,
        [System.Collections.ArrayList]$results
    )
    
    $result = [PSCustomObject]@{
        Path           = (Resolve-Path -Path $path).Path
        Account        = $ace.Account
        AccessType     = $ace.AccessType
        Rights         = $ace.Rights
        Inherited      = $ace.Inherited
        AccountType    = if ($config.EnableLdap) { Get-AccountType $ace.Account $config } else { "" }
        Enabled        = if ($config.EnableLdap) { $null } else { "" }
        AccountExpires = if ($config.EnableLdap) { $null } else { "" }
    }

    if ($config.EnableLdap -and $result.AccountType -like "AD*") {
        EnrichADAccountInfo -result $result -config $config
    }

    $null = $results.Add($result)
}

function Get-AccountType {
    param (
        [string]$account,
        [SecurityAuditConfig]$config
    )
    if (-not $config.EnableLdap) {
        if ($account -match "^S-1-5-21") { 
            return "Unknown" 
        }
        else { 
            return "BuiltIn" 
        }
    }

    if ($account -match "^S-1-5-21") {
        try {
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($account)
            $objUser = $objSID.Translate([System.Security.Principal.NTAccount])

            if ($objUser.Value -like "*\*") {
                try {
                    $ldapConnection = New-Object System.DirectoryServices.Protocols.LdapConnection($config.GCServer)
                    $ldapConnection.Credential = New-Object System.Net.NetworkCredential($config.GCUser, $config.GCPassword)
                    $ldapConnection.Bind()

                    $searchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest(
                        $config.GCBaseDN,
                        "(objectSID=$account)",
                        [System.DirectoryServices.Protocols.SearchScope]::Subtree,
                        @("objectSID")
                    )

                    $searchResponse = $ldapConnection.SendRequest($searchRequest)
                    if ($searchResponse.Entries.Count -gt 0) { 
                        return "ADAccount" 
                    }
                    else { 
                        return "LocalAccount" 
                    }
                }
                catch {
                    return "LocalAccount"
                }
            }
            return "LocalAccount"
        }
        catch {
            return "Unknown"
        }
    }
    return "BuiltIn"
}

function EnrichADAccountInfo {
    param (
        [hashtable]$result,
        [SecurityAuditConfig]$config
    )
    if (-not $config.EnableLdap) {
        $result.Enabled = $null
        $result.AccountExpires = $null
        return
    }

    try {
        $account = $result.Account -replace "^.*\\"
        $ldapConnection = New-Object System.DirectoryServices.Protocols.LdapConnection($config.GCServer)
        $ldapConnection.Credential = New-Object System.Net.NetworkCredential($config.GCUser, $config.GCPassword)
        $ldapConnection.Bind()

        $searchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest(
            $config.GCBaseDN,
            "(sAMAccountName=$account)",
            [System.DirectoryServices.Protocols.SearchScope]::Subtree,
            @("sAMAccountName", "accountExpires", "userAccountControl")
        )

        $searchResponse = $ldapConnection.SendRequest($searchRequest)
        if ($searchResponse.Entries.Count -gt 0) {
            $entry = $searchResponse.Entries[0]
            $result.Enabled = -not ($entry.Attributes["userAccountControl"][0] -band 2)
            $result.AccountExpires = if ($entry.Attributes["accountExpires"][0] -eq 0) {
                "Never"
            }
            else {
                [datetime]::FromFileTime([int64]$entry.Attributes["accountExpires"][0]).ToString("yyyy-MM-dd")
            }
        }
    }
    catch {
        $null = $errors.Add("Error getting AD info for $($result.Account): $_")
    }
}

function ShouldProcessAce {
    param (
        $ace,
        [SecurityAuditConfig]$config
    )
    $account = if ($ace.Account) { $ace.Account } else { $ace.IdentityReference.Value }

    if ($account -in $config.IgnoreLocalSystem) { return $false }
    if ($account -in $config.IgnoreLocalGroups) { return $false }
    if ($account -in $config.IgnoreLocalMembers) { return $false }
    if ($account -in $config.IgnoreADGroups) { return $false }
    # if ($account -in $config.IgnoreADMembers) { return $false }

    return $true
}

function Export-ToCsv {
    param (
        [System.Collections.ArrayList]$results,
        [string]$path
    )
    $results | Select-Object Path, Account, AccessType, Rights, Inherited, AccountType, Enabled, AccountExpires | Export-Csv -Path $path -NoTypeInformation
}

function Send-EmailReport {
    param (
        [string]$csvPath,
        [SecurityAuditConfig]$config,
        [System.Collections.ArrayList]$errors
    )
    if (-not $config.EnableEmail) { return }

    try {
        $emailParams = @{
            From        = $config.EmailFrom
            To          = $config.EmailTo
            Subject     = $config.EmailSubject
            Body        = GenerateEmailBody -results $results -errors $errors
            SmtpServer  = $config.SmtpServer
            Port        = $config.SmtpPort
            Attachments = $csvPath
        }

        if ($config.SmtpAuth) {
            $securePass = ConvertTo-SecureString $config.SmtpPassword -AsPlainText -Force
            $cred = New-Object PSCredential($config.SmtpUser, $securePass)
            $emailParams.Credential = $cred
        }

        Send-MailMessage @emailParams
    }
    catch {
        $null = $errors.Add("Error sending email: $_")
    }
}

function GenerateEmailBody {
    param (
        [System.Collections.ArrayList]$results,
        [System.Collections.ArrayList]$errors
    )
    $body = "Folder Security Audit Report`n"
    $body += "Generated: $(Get-Date)`n`n"
    $body += "Folders Processed:`n"
    $body += ($results | Select-Object -Unique Path | ForEach-Object { $_.Path }) -join "`n"

    if ($errors.Count -gt 0) {
        $body += "`n`nErrors:`n"
        $body += ($errors -join "`n")
    }

    return $body
}

function Main {
    try {
        $config = [SecurityAuditConfig]::new()
        if ($ConfigFile -and (Test-Path $ConfigFile)) {
            $configData = Get-Content $ConfigFile | ConvertFrom-Json
            foreach ($prop in $configData.PSObject.Properties) {
                $config.$($prop.Name) = $prop.Value
            }
        }
        $config.EnableLdap = $EnableLdap

        $results = [System.Collections.ArrayList]::new()
        $errors = [System.Collections.ArrayList]::new()

        Write-Host "Starting folder security audit..."

        if ($PSCmdlet.ParameterSetName -eq "SinglePath") {
            $Path = Resolve-Path -Path $Path | Select-Object -ExpandProperty Path
            AuditFolder -folderPaths @($Path) `
                        -maxDepth ($FolderLevel -eq 0 ? -1 : $FolderLevel) `
                        -config $config `
                        -results $results `
                        -errors $errors `
                        -excludedPaths @() `
                        -DropInheritance:$DropInheritance
        }
        elseif ($PSCmdlet.ParameterSetName -eq "CsvInput") {
            $csvData = ProcessCsvPathsInput -csvPaths $CsvPaths
            $folderPaths = @()
            $excludedPaths = @()
            foreach ($row in $csvData) {
                if (-not $row.Exclude) {
                    $folderPaths += (Resolve-Path -Path $row.Path | Select-Object -ExpandProperty Path)
                }
                else {
                    $excludedPaths += (Resolve-Path -Path $row.Path | Select-Object -ExpandProperty Path)
                }
            }
            AuditFolder -folderPaths $folderPaths `
                        -maxDepth ($FolderLevel -eq 0 ? -1 : $FolderLevel) `
                        -config $config `
                        -results $results `
                        -errors $errors `
                        -excludedPaths $excludedPaths `
                        -DropInheritance:$DropInheritance
        }

        $csvPath = if ($OutputPath -like "*.csv") { $OutputPath } else { Join-Path $OutputPath "FolderSecurity_$(Get-Date -f "yyyyMMdd_HHmmss").csv" }

        Export-ToCsv -results $results -path $csvPath
        Write-Host "Results exported to $csvPath"

        if ($config.EnableEmail) {
            Write-Host "Sending email report..."
            Send-EmailReport -csvPath $csvPath -config $config -errors $errors
        }

        if ($errors.Count -gt 0) {
            Write-Warning "The following errors occurred:"
            $errors | ForEach-Object { Write-Warning $_ }
        }
    }
    catch {
        Write-Error "Fatal error: $_"
        exit 1
    }
}

Main
