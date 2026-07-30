[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("prepare", "resume", "cleanup")]
    [string]$Phase,

    [string]$ServiceHost,

    [ValidateRange(1, [long]::MaxValue)]
    [long]$Generation = 1,

    [string]$StateRoot = (Join-Path $env:ProgramData "SlipstreamPhysicalRebootQualificationV1")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$ContractName = "slipstream.windows_production_host_physical_reboot"
$ResultName = "slipstream.windows_production_host_physical_reboot_result"
$ServiceName = "dev.slipstream.service"
$ProductRoot = Join-Path $env:ProgramData "Slipstream"
$OwnerRecordPath = Join-Path $ProductRoot "service-owner-v1.json"
$IntentRecordPath = Join-Path $ProductRoot "service-intent-v1.json"
$ActiveInstallRecordPath = Join-Path $ProductRoot "service-active-v1.json"
$TransactionPath = Join-Path $StateRoot "transaction-v1.json"
$ResultPath = Join-Path $StateRoot "result-v1.json"
$SentinelPath = Join-Path $StateRoot "independent-owner.sentinel"
$StateRootMarkerPath = Join-Path $StateRoot ".slipstream-physical-reboot-v1"
$Utf8NoBom = [Text.UTF8Encoding]::new($false)
$MaximumRecordBytes = 32KB
$MaximumManagementOutputBytes = 1MB
$MaximumErrorOutputCharacters = 8192
$ServiceReadyTimeoutSeconds = 30
$TerminalTimeoutSeconds = 30

function Assert-WindowsAdministrator {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw "The physical reboot qualification requires Windows."
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $administrator = [Security.Principal.WindowsBuiltInRole]::Administrator
    if (-not $principal.IsInRole($administrator)) {
        throw "The physical reboot qualification requires an elevated Administrator shell."
    }
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-Equal {
    param(
        [Parameter(Mandatory = $true)]$Actual,
        [Parameter(Mandatory = $true)]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($Actual -ne $Expected) {
        throw "$Label mismatch."
    }
}

function Assert-PathEqual {
    param(
        [Parameter(Mandatory = $true)][string]$Actual,
        [Parameter(Mandatory = $true)][string]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $actualPath = [IO.Path]::GetFullPath($Actual)
    $expectedPath = [IO.Path]::GetFullPath($Expected)
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals($actualPath, $expectedPath)) {
        throw "$Label path mismatch."
    }
}

function Read-BoundedJson {
    param([Parameter(Mandatory = $true)][string]$Path)

    $file = Get-Item -LiteralPath $Path
    if ($file.PSIsContainer -or $file.Length -le 0 -or $file.Length -gt $MaximumRecordBytes) {
        throw "Refusing an empty, directory, or oversized JSON record at $Path."
    }
    return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json)
}

function Write-AtomicJson {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value
    )

    $parent = Split-Path -Parent $Path
    $temporary = Join-Path $parent (".{0}.pending-v1" -f [IO.Path]::GetFileName($Path))
    if (Test-Path -LiteralPath $temporary) {
        Remove-Item -LiteralPath $temporary -Force
    }
    $json = $Value | ConvertTo-Json -Depth 12 -Compress
    [IO.File]::WriteAllText($temporary, $json, $Utf8NoBom)
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Protect-StateRoot {
    $created = $false
    if (-not (Test-Path -LiteralPath $StateRoot)) {
        New-Item -ItemType Directory -Path $StateRoot | Out-Null
        $created = $true
    }
    $directory = Get-Item -LiteralPath $StateRoot
    if (-not $directory.PSIsContainer -or
        ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "The qualification state root must be a real directory, not a reparse point."
    }
    if (-not $created -and -not (Test-Path -LiteralPath $StateRootMarkerPath -PathType Leaf)) {
        $existingEntries = @(Get-ChildItem -LiteralPath $StateRoot -Force)
        if ($existingEntries.Count -gt 0) {
            throw "The qualification state root must be newly created, empty, or already owned by this harness."
        }
    }
    if (Test-Path -LiteralPath $StateRootMarkerPath -PathType Leaf) {
        $marker = Get-Content -LiteralPath $StateRootMarkerPath -Raw
        if ($marker -ne $ContractName) {
            throw "The qualification state root ownership marker is invalid."
        }
    }

    $administrators = [Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
    $system = [Security.Principal.SecurityIdentifier]::new("S-1-5-18")
    $rights = [Security.AccessControl.FileSystemRights]::FullControl
    $inheritance = [Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($administrators)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $administrators, $rights, $inheritance, $propagation, $allow
    ))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $system, $rights, $inheritance, $propagation, $allow
    ))
    Set-Acl -LiteralPath $StateRoot -AclObject $acl
    if (-not (Test-Path -LiteralPath $StateRootMarkerPath -PathType Leaf)) {
        [IO.File]::WriteAllText($StateRootMarkerPath, $ContractName, $Utf8NoBom)
    }
}

function Get-BootIdentity {
    $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
    return $operatingSystem.LastBootUpTime.ToUniversalTime().ToString("o")
}

function Get-ExactService {
    return Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'"
}

function Get-ExactProcess {
    param([Parameter(Mandatory = $true)][uint32]$ProcessId)

    return Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$ProcessId"
}

function Get-RegistryValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }
    $item = Get-ItemProperty -LiteralPath $Path
    $property = $item.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}

function Get-RegistryBinaryValueBase64 {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $value = Get-RegistryValue -Path $Path -Name $Name
    if ($null -eq $value) {
        return $null
    }
    if ($value -isnot [byte[]]) {
        throw "Expected a binary registry value at $Path\$Name."
    }
    return [Convert]::ToBase64String($value)
}

function Get-NetworkSettingsSnapshot {
    $dns = @(
        Get-DnsClientServerAddress |
            Sort-Object InterfaceIndex, AddressFamily |
            ForEach-Object {
                [ordered]@{
                    interface_index = [int]$_.InterfaceIndex
                    address_family = [string]$_.AddressFamily
                    server_addresses = @($_.ServerAddresses)
                }
            }
    )

    $internetSettings = "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    $machineInternetSettings = "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    $userConnections = Join-Path $internetSettings "Connections"
    $machineConnections = Join-Path $machineInternetSettings "Connections"
    $snapshot = [ordered]@{
        dns = $dns
        user_proxy = [ordered]@{
            proxy_enable = Get-RegistryValue -Path $internetSettings -Name "ProxyEnable"
            proxy_server = Get-RegistryValue -Path $internetSettings -Name "ProxyServer"
            auto_config_url = Get-RegistryValue -Path $internetSettings -Name "AutoConfigURL"
            auto_detect = Get-RegistryValue -Path $internetSettings -Name "AutoDetect"
        }
        machine_proxy = [ordered]@{
            proxy_enable = Get-RegistryValue -Path $machineInternetSettings -Name "ProxyEnable"
            proxy_server = Get-RegistryValue -Path $machineInternetSettings -Name "ProxyServer"
            auto_config_url = Get-RegistryValue -Path $machineInternetSettings -Name "AutoConfigURL"
            auto_detect = Get-RegistryValue -Path $machineInternetSettings -Name "AutoDetect"
        }
        connection_proxy = [ordered]@{
            user_default = Get-RegistryBinaryValueBase64 -Path $userConnections -Name "DefaultConnectionSettings"
            user_legacy = Get-RegistryBinaryValueBase64 -Path $userConnections -Name "SavedLegacySettings"
            machine_default = Get-RegistryBinaryValueBase64 -Path $machineConnections -Name "DefaultConnectionSettings"
            machine_legacy = Get-RegistryBinaryValueBase64 -Path $machineConnections -Name "SavedLegacySettings"
            winhttp = Get-RegistryBinaryValueBase64 -Path $machineConnections -Name "WinHttpSettings"
        }
    }
    $canonical = $snapshot | ConvertTo-Json -Depth 8 -Compress
    $bytes = [Text.Encoding]::UTF8.GetBytes($canonical)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = [BitConverter]::ToString($hasher.ComputeHash($bytes)).Replace("-", "").ToLowerInvariant()
    } finally {
        $hasher.Dispose()
    }
    return [ordered]@{
        value = $snapshot
        sha256 = $hash
    }
}

function Invoke-Management {
    param(
        [Parameter(Mandatory = $true)][string]$HostPath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$ExpectedCommand
    )

    if (-not (Test-Path -LiteralPath $HostPath -PathType Leaf)) {
        throw "The exact service host is unavailable at $HostPath."
    }
    $output = @(& $HostPath @Arguments 2>&1)
    $exitCode = $LASTEXITCODE
    $text = ($output | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
    if ([Text.Encoding]::UTF8.GetByteCount($text) -gt $MaximumManagementOutputBytes) {
        throw "The exact service host returned an oversized management response."
    }
    $shortText = $text
    if ($shortText.Length -gt $MaximumErrorOutputCharacters) {
        $shortText = $shortText.Substring(0, $MaximumErrorOutputCharacters)
    }
    if ($exitCode -ne 0) {
        throw "The exact service host command failed with exit code $exitCode`: $shortText"
    }
    $result = $text | ConvertFrom-Json
    Assert-Equal -Actual $result.schema_version -Expected 1 -Label "management schema_version"
    Assert-Equal -Actual $result.service_name -Expected $ServiceName -Label "management service_name"
    Assert-Equal -Actual $result.command -Expected $ExpectedCommand -Label "management command"
    if (-not $result.lifecycle.accepted -or $null -ne $result.lifecycle.error) {
        throw "The exact service host did not accept the $ExpectedCommand command."
    }
    return $result
}

function Read-InstalledIdentity {
    $owner = Read-BoundedJson -Path $OwnerRecordPath
    Assert-Equal -Actual $owner.schema_version -Expected 1 -Label "owner schema_version"
    Assert-Equal -Actual $owner.service_name -Expected $ServiceName -Label "owner service_name"
    if ([string]::IsNullOrWhiteSpace($owner.executable_path)) {
        throw "The owner record has no executable path."
    }
    if (-not (Test-Path -LiteralPath $owner.executable_path -PathType Leaf)) {
        throw "The installed service payload is missing."
    }
    Assert-Equal -Actual (Get-Sha256 -Path $owner.executable_path) -Expected $owner.executable_sha256 -Label "installed payload SHA-256"

    $intent = Read-BoundedJson -Path $IntentRecordPath
    $active = Read-BoundedJson -Path $ActiveInstallRecordPath
    Assert-Equal -Actual $intent.schema_version -Expected 1 -Label "intent schema_version"
    Assert-Equal -Actual $intent.record_kind -Expected "slipstream.windows_service_intent" -Label "intent record_kind"
    Assert-Equal -Actual $intent.desired -Expected "running" -Label "intent desired"
    Assert-Equal -Actual $active.schema_version -Expected 1 -Label "active-install schema_version"
    Assert-Equal -Actual $active.record_kind -Expected "slipstream.windows_active_install" -Label "active-install record_kind"
    Assert-Equal -Actual $intent.identity.service_name -Expected $ServiceName -Label "intent identity service_name"
    Assert-Equal -Actual $active.identity.service_name -Expected $ServiceName -Label "active-install identity service_name"
    Assert-Equal -Actual $intent.identity.executable_sha256 -Expected $owner.executable_sha256 -Label "intent executable SHA-256"
    Assert-Equal -Actual $active.identity.executable_sha256 -Expected $owner.executable_sha256 -Label "active-install executable SHA-256"
    Assert-Equal -Actual $intent.identity.generation -Expected $owner.generation -Label "intent generation"
    Assert-Equal -Actual $active.identity.generation -Expected $owner.generation -Label "active-install generation"
    return $owner
}

function Wait-ExactServiceReady {
    param([Parameter(Mandatory = $true)]$Owner)

    $deadline = [DateTime]::UtcNow.AddSeconds($ServiceReadyTimeoutSeconds)
    do {
        $service = Get-ExactService
        if ($null -ne $service -and $service.State -eq "Running" -and [uint32]$service.ProcessId -gt 0) {
            Assert-Equal -Actual $service.StartMode -Expected "Auto" -Label "SCM start mode"
            Assert-Equal -Actual $service.PathName -Expected $Owner.scm_binary_path -Label "SCM binary command"
            $process = Get-ExactProcess -ProcessId ([uint32]$service.ProcessId)
            if ($null -ne $process -and -not [string]::IsNullOrWhiteSpace($process.ExecutablePath)) {
                Assert-PathEqual -Actual $process.ExecutablePath -Expected $Owner.executable_path -Label "service process executable"
                return [ordered]@{
                    service = $service
                    process = $process
                }
            }
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "The exact automatic-start service did not reach verified Running readiness."
}

function Assert-ExactTerminalAbsence {
    param(
        [Parameter(Mandatory = $true)][string]$InstalledPath,
        [Parameter(Mandatory = $true)][uint32]$LastProcessId
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TerminalTimeoutSeconds)
    do {
        $service = Get-ExactService
        $ownerAbsent = -not (Test-Path -LiteralPath $OwnerRecordPath)
        $activeAbsent = -not (Test-Path -LiteralPath $ActiveInstallRecordPath)
        $payloadAbsent = -not (Test-Path -LiteralPath $InstalledPath)
        if ($null -eq $service -and $ownerAbsent -and $activeAbsent -and $payloadAbsent) {
            if ($LastProcessId -gt 0) {
                $process = Get-ExactProcess -ProcessId $LastProcessId
                if ($null -ne $process -and -not [string]::IsNullOrWhiteSpace($process.ExecutablePath)) {
                    if ([StringComparer]::OrdinalIgnoreCase.Equals(
                        [IO.Path]::GetFullPath($process.ExecutablePath),
                        [IO.Path]::GetFullPath($InstalledPath)
                    )) {
                        Start-Sleep -Milliseconds 250
                        continue
                    }
                }
            }
            $intent = Read-BoundedJson -Path $IntentRecordPath
            Assert-Equal -Actual $intent.desired -Expected "absent" -Label "terminal intent"
            return
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "The exact service did not reach terminal product absence."
}

function Assert-TransactionIdentity {
    param(
        [Parameter(Mandatory = $true)]$Transaction,
        [Parameter(Mandatory = $true)]$Owner
    )

    Assert-Equal -Actual $Transaction.schema_version -Expected 1 -Label "transaction schema_version"
    Assert-Equal -Actual $Transaction.contract -Expected $ContractName -Label "transaction contract"
    Assert-Equal -Actual $Transaction.phase -Expected "prepared" -Label "transaction phase"
    Assert-Equal -Actual $Transaction.identity.service_name -Expected $ServiceName -Label "transaction service_name"
    Assert-PathEqual -Actual $Transaction.independent_sentinel.path -Expected $SentinelPath -Label "transaction sentinel"
    Assert-Equal -Actual $Owner.service_name -Expected $ServiceName -Label "current owner service_name"
    Assert-Equal -Actual $Owner.executable_sha256 -Expected $Transaction.identity.executable_sha256 -Label "current owner SHA-256"
    Assert-Equal -Actual $Owner.generation -Expected $Transaction.identity.generation -Label "current owner generation"
    Assert-PathEqual -Actual $Owner.executable_path -Expected $Transaction.installed_executable_path -Label "current owner executable"
    Assert-Equal -Actual $Owner.scm_binary_path -Expected $Transaction.scm_binary_path -Label "current owner SCM binary command"
}

function Assert-TransactionTerminalAbsence {
    param([Parameter(Mandatory = $true)]$Transaction)

    Assert-ExactTerminalAbsence -InstalledPath $Transaction.installed_executable_path -LastProcessId 0
    $intent = Read-BoundedJson -Path $IntentRecordPath
    Assert-Equal -Actual $intent.schema_version -Expected 1 -Label "terminal intent schema_version"
    Assert-Equal -Actual $intent.record_kind -Expected "slipstream.windows_service_intent" -Label "terminal intent record_kind"
    Assert-Equal -Actual $intent.desired -Expected "absent" -Label "terminal intent desired"
    Assert-Equal -Actual $intent.crash_restart_attempts -Expected 0 -Label "terminal intent crash budget"
    if ($null -eq $intent.identity) {
        throw "Terminal absence is not bound to the prepared service identity."
    }
    Assert-Equal -Actual $intent.identity.service_name -Expected $Transaction.identity.service_name -Label "terminal intent service_name"
    Assert-Equal -Actual $intent.identity.executable_sha256 -Expected $Transaction.identity.executable_sha256 -Label "terminal intent SHA-256"
    Assert-Equal -Actual $intent.identity.generation -Expected $Transaction.identity.generation -Label "terminal intent generation"
}

function Invoke-ExactRollback {
    param([Parameter(Mandatory = $true)]$Transaction)

    if (-not (Test-Path -LiteralPath $OwnerRecordPath)) {
        Assert-TransactionTerminalAbsence -Transaction $Transaction
        return
    }
    $owner = Read-InstalledIdentity
    Assert-TransactionIdentity -Transaction $Transaction -Owner $owner
    Assert-Equal -Actual (Get-Sha256 -Path $owner.executable_path) -Expected $Transaction.identity.executable_sha256 -Label "rollback host SHA-256"
    $service = Get-ExactService
    $lastProcessId = [uint32]0
    if ($null -ne $service) {
        Assert-Equal -Actual $service.StartMode -Expected "Auto" -Label "rollback SCM start mode"
        Assert-Equal -Actual $service.PathName -Expected $owner.scm_binary_path -Label "rollback SCM binary command"
        $lastProcessId = [uint32]$service.ProcessId
    }
    Invoke-Management -HostPath $owner.executable_path -Arguments @("manage", "uninstall") -ExpectedCommand "uninstall" | Out-Null
    Assert-ExactTerminalAbsence -InstalledPath $owner.executable_path -LastProcessId $lastProcessId
}

function Write-Result {
    param(
        [Parameter(Mandatory = $true)]$Transaction,
        [Parameter(Mandatory = $true)][string]$Outcome,
        [Parameter(Mandatory = $true)][string]$CurrentBootIdentity,
        [uint32]$PostBootProcessId = 0,
        [string]$PostBootProcessCreatedAt = "",
        [string]$Failure = ""
    )

    $result = [ordered]@{
        schema_version = 1
        result = $ResultName
        outcome = $Outcome
        transaction_id = $Transaction.transaction_id
        identity = $Transaction.identity
        before_boot_identity = $Transaction.before_boot_identity
        after_boot_identity = $CurrentBootIdentity
        before_process_id = $Transaction.before_process_id
        after_process_id = $PostBootProcessId
        after_process_created_at = $PostBootProcessCreatedAt
        network_settings_sha256 = $Transaction.network_settings.sha256
        independent_sentinel_sha256 = $Transaction.independent_sentinel.sha256
        exact_uninstall_verified = $true
        failure = $Failure
        completed_at = [DateTime]::UtcNow.ToString("o")
    }
    Write-AtomicJson -Path $ResultPath -Value $result
}

function Invoke-Prepare {
    if ([string]::IsNullOrWhiteSpace($ServiceHost)) {
        throw "prepare requires -ServiceHost with the exact production service executable."
    }
    if (Test-Path -LiteralPath $TransactionPath) {
        throw "A physical reboot qualification transaction is already pending."
    }
    if (Test-Path -LiteralPath $ResultPath) {
        throw "Archive or remove the previous result before starting a new qualification."
    }
    if ($null -ne (Get-ExactService)) {
        throw "The exact Slipstream service must be absent before prepare."
    }
    if ((Test-Path -LiteralPath $OwnerRecordPath) -or
        (Test-Path -LiteralPath $ActiveInstallRecordPath)) {
        throw "Owned active product evidence must be absent before prepare."
    }

    $resolvedHost = (Resolve-Path -LiteralPath $ServiceHost).Path
    $sourceSha256 = Get-Sha256 -Path $resolvedHost
    $beforeBootIdentity = Get-BootIdentity
    $networkSettings = Get-NetworkSettingsSnapshot
    $transactionId = [Guid]::NewGuid().ToString("D")
    [IO.File]::WriteAllText($SentinelPath, $transactionId, $Utf8NoBom)
    $sentinelSha256 = Get-Sha256 -Path $SentinelPath
    $installed = $false
    try {
        $install = Invoke-Management -HostPath $resolvedHost -Arguments @(
            "manage", "install", "--generation", $Generation.ToString()
        ) -ExpectedCommand "install"
        Assert-Equal -Actual $install.lifecycle.state.desired -Expected "running" -Label "install desired state"
        Assert-Equal -Actual $install.lifecycle.state.observed -Expected "running" -Label "install observed state"
        Assert-Equal -Actual $install.lifecycle.state.ownership -Expected "owned" -Label "install ownership"
        $installed = $true

        $owner = Read-InstalledIdentity
        Assert-Equal -Actual $owner.executable_sha256 -Expected $sourceSha256 -Label "source/staged SHA-256"
        Assert-Equal -Actual $owner.generation -Expected $Generation -Label "installed generation"
        $ready = Wait-ExactServiceReady -Owner $owner
        $processCreatedAt = $ready.process.CreationDate.ToUniversalTime().ToString("o")
        $transaction = [ordered]@{
            schema_version = 1
            contract = $ContractName
            phase = "prepared"
            transaction_id = $transactionId
            generation = $Generation
            source = [ordered]@{
                path = $resolvedHost
                sha256 = $sourceSha256
            }
            identity = [ordered]@{
                service_name = $ServiceName
                executable_sha256 = $owner.executable_sha256
                generation = $owner.generation
            }
            installed_executable_path = $owner.executable_path
            scm_binary_path = $owner.scm_binary_path
            before_boot_identity = $beforeBootIdentity
            before_process_id = [uint32]$ready.service.ProcessId
            before_process_created_at = $processCreatedAt
            network_settings = $networkSettings
            independent_sentinel = [ordered]@{
                path = $SentinelPath
                sha256 = $sentinelSha256
            }
            prepared_at = [DateTime]::UtcNow.ToString("o")
        }
        Write-AtomicJson -Path $TransactionPath -Value $transaction
        [ordered]@{
            schema_version = 1
            contract = $ContractName
            phase = "prepared"
            transaction_id = $transactionId
            reboot_required = $true
            automatic_reboot = $false
            next_command = "Run the same script with -Phase resume after a real Windows restart."
        } | ConvertTo-Json -Depth 4
    } catch {
        if ($installed -and -not (Test-Path -LiteralPath $TransactionPath)) {
            try {
                $owner = Read-InstalledIdentity
                Invoke-Management -HostPath $owner.executable_path -Arguments @(
                    "manage", "uninstall"
                ) -ExpectedCommand "uninstall" | Out-Null
            } catch {
                Write-Warning "Prepare failed and exact rollback also failed: $($_.Exception.Message)"
            }
        }
        if (-not (Test-Path -LiteralPath $TransactionPath) -and (Test-Path -LiteralPath $SentinelPath)) {
            Remove-Item -LiteralPath $SentinelPath -Force
        }
        throw
    }
}

function Invoke-Resume {
    if (-not (Test-Path -LiteralPath $TransactionPath -PathType Leaf)) {
        throw "No prepared physical reboot qualification transaction exists."
    }
    $transaction = Read-BoundedJson -Path $TransactionPath
    $currentBootIdentity = Get-BootIdentity
    $postBootProcessId = [uint32]0
    $postBootProcessCreatedAt = ""
    try {
        Assert-TransactionIdentity -Transaction $transaction -Owner (Read-InstalledIdentity)
        if ($currentBootIdentity -eq $transaction.before_boot_identity) {
            throw "The Windows boot identity did not change; a physical restart has not been proven."
        }
        Assert-Equal -Actual (Get-Sha256 -Path $transaction.independent_sentinel.path) -Expected $transaction.independent_sentinel.sha256 -Label "independent sentinel SHA-256"
        $currentNetworkSettings = Get-NetworkSettingsSnapshot
        Assert-Equal -Actual $currentNetworkSettings.sha256 -Expected $transaction.network_settings.sha256 -Label "read-only DNS/proxy/PAC snapshot"

        $owner = Read-InstalledIdentity
        Assert-TransactionIdentity -Transaction $transaction -Owner $owner
        $ready = Wait-ExactServiceReady -Owner $owner
        $postBootProcessId = [uint32]$ready.service.ProcessId
        $postBootProcessCreatedAt = $ready.process.CreationDate.ToUniversalTime().ToString("o")
        $bootTime = [DateTime]::Parse($currentBootIdentity).ToUniversalTime()
        $processTime = [DateTime]::Parse($postBootProcessCreatedAt).ToUniversalTime()
        if ($processTime -lt $bootTime -or
            $processTime -gt [DateTime]::UtcNow.AddSeconds(5)) {
            throw "The service process was not created in the current Windows boot."
        }

        Invoke-Management -HostPath $owner.executable_path -Arguments @(
            "manage", "uninstall"
        ) -ExpectedCommand "uninstall" | Out-Null
        Assert-ExactTerminalAbsence -InstalledPath $owner.executable_path -LastProcessId $postBootProcessId
        Assert-Equal -Actual (Get-Sha256 -Path $transaction.independent_sentinel.path) -Expected $transaction.independent_sentinel.sha256 -Label "post-uninstall sentinel SHA-256"
        Write-Result -Transaction $transaction -Outcome "passed" -CurrentBootIdentity $currentBootIdentity -PostBootProcessId $postBootProcessId -PostBootProcessCreatedAt $postBootProcessCreatedAt
        Remove-Item -LiteralPath $TransactionPath -Force
        Remove-Item -LiteralPath $SentinelPath -Force
        Get-Content -LiteralPath $ResultPath -Raw
    } catch {
        $failure = $_.Exception.Message
        try {
            Invoke-ExactRollback -Transaction $transaction
            Write-Result -Transaction $transaction -Outcome "failed_rolled_back" -CurrentBootIdentity $currentBootIdentity -PostBootProcessId $postBootProcessId -PostBootProcessCreatedAt $postBootProcessCreatedAt -Failure $failure
            Remove-Item -LiteralPath $TransactionPath -Force
            if (Test-Path -LiteralPath $SentinelPath) {
                Remove-Item -LiteralPath $SentinelPath -Force
            }
        } catch {
            throw "Physical reboot qualification failed: $failure. Exact rollback also failed: $($_.Exception.Message)"
        }
        throw "Physical reboot qualification failed and was rolled back exactly: $failure"
    }
}

function Invoke-Cleanup {
    if (-not (Test-Path -LiteralPath $TransactionPath -PathType Leaf)) {
        if ($null -eq (Get-ExactService) -and
            -not (Test-Path -LiteralPath $OwnerRecordPath) -and
            -not (Test-Path -LiteralPath $ActiveInstallRecordPath)) {
            [ordered]@{
                schema_version = 1
                contract = $ContractName
                phase = "clean"
                exact_product_absence = $true
            } | ConvertTo-Json
            return
        }
        throw "Cleanup refuses product mutation without the protected transaction record."
    }
    $transaction = Read-BoundedJson -Path $TransactionPath
    $currentBootIdentity = Get-BootIdentity
    Invoke-ExactRollback -Transaction $transaction
    Write-Result -Transaction $transaction -Outcome "cleanup_only" -CurrentBootIdentity $currentBootIdentity
    Remove-Item -LiteralPath $TransactionPath -Force
    if (Test-Path -LiteralPath $SentinelPath) {
        Remove-Item -LiteralPath $SentinelPath -Force
    }
    Get-Content -LiteralPath $ResultPath -Raw
}

Assert-WindowsAdministrator
Protect-StateRoot

switch ($Phase) {
    "prepare" { Invoke-Prepare }
    "resume" { Invoke-Resume }
    "cleanup" { Invoke-Cleanup }
}
