#Requires -Version 5.1
#Requires -Module ActiveDirectory
#Requires -Module ImportExcel

<#
.SYNOPSIS
  Module de réponse à l'incident CVE-2025-59287 (WSUS).
  Contient les fonctions pour scanner, appliquer/retirer le workaround, et exporter les rapports.
#>

#region Private Helper Functions & ScriptBlocks

# Fonctions de log internes
function Write-Info($msg) { Write-Host "[INFO] $msg" -ForegroundColor Cyan }
function Write-Warn($msg) { Write-Warning $msg }
function Write-Err($msg) { Write-Error $msg }

# --- Constantes du module ---
# Utilisation de $script: pour isoler les variables au scope du module
$script:RulePrefix = 'BLOCK-CVE-2025-59287-WSUS-Port-'
$script:PortsToBlock = 8530, 8531
$script:RequiredKBs = @(
    'KB5070884', # Server 2022
    'KB5070883', # Server 2019
    'KB5070882', # Server 2016
    'KB5070886', # Server 2012 R2
    'KB5070887', # Server 2012
    'KB5070892', # 2022 Hotpatch
    'KB5070893'  # 2025 Hotpatch
)


# --- Scriptblocks distants ---

# Scriptblock côté cible : détection WSUS + état patch + workaround
$script:RemoteProbe = {
  param($RequiredKBs, $RulePrefix, $PortsToBlock)

  # Assure la disponibilité de Get-WindowsFeature
  try { Import-Module ServerManager -ErrorAction SilentlyContinue } catch {}

  # Fonction interne pour tester l'installation de WSUS (multi-critères)
  function Test-WSUSInstalled {
    # 1) Rôle/feature
    $wsusFeature = $null
    try {
      $wsusFeature = Get-WindowsFeature -Name 'UpdateServices*' -ErrorAction SilentlyContinue
    } catch {}
    $featureInstalled = ($wsusFeature | Where-Object Installed).Count -gt 0

    # 2) Service
    $svcInstalled = $false
    try {
      $svc = Get-Service -Name 'WSUSService' -ErrorAction SilentlyContinue
      $svcInstalled = $null -ne $svc
    } catch {}

    # 3) Registre
    $regInstalled = $false
    try {
      $regInstalled = Test-Path 'HKLM:\SOFTWARE\Microsoft\Update Services\Server\Setup'
    } catch {}

    return ($featureInstalled -or $svcInstalled -or $regInstalled)
  }

  # Fonction interne pour lister les KBs installés (multi-critères)
  function Get-InstalledKBs {
    $kbs = @()
    try {
      $kbs += (Get-CimInstance -ClassName Win32_QuickFixEngineering -ErrorAction SilentlyContinue | Select-Object -ExpandProperty HotFixID)
    } catch {}
    try {
      $dism = & dism.exe /online /Get-Packages 2>$null
      if ($LASTEXITCODE -eq 0 -and $dism) {
        $kbMatches = ($dism | Select-String -Pattern 'KB(\d+)' -AllMatches).Matches.Value |
          ForEach-Object { ($_ -replace '.*(KB\d+).*', '$1') }
        $kbs += $kbMatches
      }
    } catch {}
    $kbs | Sort-Object -Unique
  }

  # Fonction interne pour vérifier l'état du workaround
  function Get-WorkaroundState {
    param([string]$RulePrefix, [int[]]$PortsToBlock)
    $present = @()
    foreach ($p in $PortsToBlock) {
      $n = "$RulePrefix$p"
      $r = Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue
      if ($r) { $present += $p }
    }
    return $present
  }

  # --- Exécution du ScriptBlock ---
  $os = (Get-CimInstance Win32_OperatingSystem).Caption
  $isWSUS = Test-WSUSInstalled
  $installed = Get-InstalledKBs
  $found = @($RequiredKBs | Where-Object { $_ -in $installed })
  $workaroundPorts = Get-WorkaroundState -RulePrefix $RulePrefix -PortsToBlock $PortsToBlock

  [PSCustomObject]@{
    ComputerName    = $env:COMPUTERNAME
    OS              = $os
    IsWSUS          = [bool]$isWSUS
    InstalledKBs    = ($installed -join ',')
    FoundOOBKBs     = ($found -join ',')
    IsPatched       = ($found.Count -gt 0)
    WorkaroundPorts = ($workaroundPorts -join ',')
    WorkaroundAction = $null # Initialisation pour un schéma stable
    Timestamp       = (Get-Date).ToString('s')
    Reachable       = $true
    Error           = $null
  }
} # Fin $script:RemoteProbe

# Scriptblock pour APPLIQUER le workaround
$script:RemoteApplyWorkaround = {
  param($RulePrefix, $PortsToBlock)
  $results = @()
  foreach ($p in $PortsToBlock) {
    $name = "$RulePrefix$p"
    $existing = Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
    if (-not $existing) {
      New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Block -Protocol TCP -LocalPort $p -Enabled True | Out-Null
      $results += "created:$p"
    } else {
      $results += "exists:$p"
    }
  }
  # Retourne un objet structuré
  [PSCustomObject]@{
      ComputerName = $env:COMPUTERNAME
      Action = ($results -join ',')
  }
}

# Scriptblock pour SUPPRIMER le workaround
$script:RemoteRemoveWorkaround = {
  param($RulePrefix, $PortsToBlock)
  $results = @()
  foreach ($p in $PortsToBlock) {
    $name = "$RulePrefix$p"
    $existing = Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
    if ($existing) {
      Remove-NetFirewallRule -DisplayName $name
      $results += "removed:$p"
    } else {
      $results += "absent:$p"
    }
  }
  # Retourne un objet structuré
  [PSCustomObject]@{
      ComputerName = $env:COMPUTERNAME
      Action = ($results -join ',')
  }
}

#endregion

#region Exported Functions

function Get-WSUSCveStatus {
<#
.SYNOPSIS
  Scanne les serveurs pour détecter le rôle WSUS et l'état du patch CVE-2025-59287.
.PARAMETER FromAD
  Découvre automatiquement les serveurs Windows depuis l'Active Directory.
.PARAMETER ComputerName
  Liste de noms d'ordinateurs à scanner.
.PARAMETER Credential
  Crédentials alternatifs pour l'exécution distante.
.PARAMETER ThrottleLimit
  Nombre de machines à scanner en parallèle.
.PARAMETER OperationTimeoutSec
  Timeout en secondes pour chaque connexion distante.
.PARAMETER UsePS7Parallel
  Utilise ForEach-Object -Parallel (PS7+) pour le pré-test Test-WSMan.
.EXAMPLE
  Get-WSUSCveStatus -FromAD -UsePS7Parallel
.EXAMPLE
  'srv1','srv2' | Get-WSUSCveStatus -ThrottleLimit 10
#>
  [CmdletBinding(DefaultParameterSetName = 'List')]
  param(
    [Parameter(ParameterSetName = 'AD', Mandatory = $true)]
    [switch]$FromAD,

    [Parameter(ParameterSetName = 'List', Mandatory = $true, ValueFromPipeline = $true)]
    [string[]]$ComputerName,

    [pscredential]$Credential,
    
    [int]$ThrottleLimit = 32,
    [int]$OperationTimeoutSec = 120,
    [switch]$UsePS7Parallel
  )

  begin {
    $Report = [System.Collections.Generic.List[object]]::new()
    $targets = [System.Collections.Generic.List[string]]::new()
    
    if ($PSCmdlet.ParameterSetName -eq 'AD') {
      try {
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
          Write-Warn "Module ActiveDirectory non trouvé."
          Write-Warn "Sur un client Win10/11, installez via : Add-WindowsCapability -Online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'"
          Write-Warn "Sur un serveur, installez via : Install-WindowsFeature RSAT-AD-PowerShell"
          throw "Module ActiveDirectory requis."
        }
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-Info "Découverte des serveurs Windows via AD…"
        (Get-ADComputer -LDAPFilter '(operatingSystem=Windows Server*)' -Properties Name).Name | Sort-Object -Unique | ForEach-Object { $targets.Add($_) }
        if ($targets.Count -eq 0) { throw "Aucun serveur trouvé dans l’AD." }
      } catch {
        Write-Err $_.Exception.Message
        throw
      }
    }
  }

  process {
    # Accepte les cibles depuis le pipeline
    if ($PSCmdlet.ParameterSetName -eq 'List') {
        $ComputerName | ForEach-Object { $targets.Add($_) }
    }
    
    # Le bloc process est utilisé pour collecter les cibles du pipeline.
    # L'exécution réelle se fait dans le bloc 'end' pour s'assurer que toutes les cibles sont collectées.
  }

  end {
    $finalTargets = $targets | Where-Object { $_ -and $_.Trim() } | Sort-Object -Unique
    if (-not $finalTargets) { throw "Aucun hôte à traiter." }

    Write-Info "Cibles: $($finalTargets.Count) hôte(s)."
    
    # Paramètres pour Invoke-Command, incluant le timeout
    $invokeParams = @{
      ThrottleLimit = $ThrottleLimit
      ErrorAction   = 'SilentlyContinue'
      SessionOption = (New-PSSessionOption -OperationTimeout ($OperationTimeoutSec * 1000)) # Conversion sec -> ms
    }
    if ($Credential) { $invokeParams.Credential = $Credential }


    # =================================================================
    # PHASE 1/2 : Pré-test WinRM (Test-WSMan)
    # =================================================================
    Write-Info "Phase 1/2 : Pré-test WinRM (Test-WSMan) des $($finalTargets.Count) cibles..."
    $reachableTargets, $unreachableTargets = @(), @()

    if ($UsePS7Parallel -and $PSVersionTable.PSVersion.Major -ge 7) {
      Write-Info "Utilisation de ForEach-Object -Parallel pour Test-WSMan (Throttle: $ThrottleLimit)..."
      $testResults = $finalTargets | ForEach-Object -Parallel {
        [PSCustomObject]@{
          ComputerName = $_
          Reachable    = (Test-WSMan -ComputerName $_ -ErrorAction SilentlyContinue)
        }
      } -ThrottleLimit $ThrottleLimit
      
      $reachableTargets = $testResults | Where-Object { $_.Reachable } | Select-Object -ExpandProperty ComputerName
      $unreachableTargets = $testResults | Where-Object { -not $_.Reachable } | Select-Object -ExpandProperty ComputerName
    }
    else {
      Write-Info "Utilisation d'une boucle foreach séquentielle pour Test-WSMan (PS5.1 mode)..."
      foreach ($c in $finalTargets) {
        if (Test-WSMan -ComputerName $c -ErrorAction SilentlyContinue) { $reachableTargets += $c } else { $unreachableTargets += $c }
      }
    }

    # Ajouter les injoignables au rapport immédiatement
    $unreachableTargets | ForEach-Object {
      $Report.Add([PSCustomObject]@{
          ComputerName    = $_
          OS              = $null
          IsWSUS          = $false
          InstalledKBs    = $null
          FoundOOBKBs     = $null
          IsPatched       = $false
          WorkaroundPorts = $null
          WorkaroundAction = $null
          Timestamp       = (Get-Date).ToString('s')
          Reachable       = $false
          Error           = "Test-WSMan a échoué (WinRM injoignable)."
      })
    }

    # =================================================================
    # PHASE 2/2 : LECTURE (Probe sur les cibles joignables en parallèle)
    # =================================================================
    if (-not $reachableTargets) {
        Write-Info "Aucune cible joignable via Test-WSMan. Arrêt de la phase de scan."
    } else {
      Write-Info "Phase 2/2 : Scan des $(@($reachableTargets).Count) cibles joignables (ThrottleLimit=$ThrottleLimit, Timeout=$OperationTimeoutSec sec)..."
      
      # Utilisation de $script:RemoteProbe pour accéder à la variable de scope module
      $probeResults = Invoke-Command -ComputerName $reachableTargets `
          -ScriptBlock $script:RemoteProbe `
          -ArgumentList @($script:RequiredKBs, $script:RulePrefix, $script:PortsToBlock) @invokeParams

      # Ajouter les résultats de la sonde au rapport
      $probeResults | ForEach-Object { $Report.Add($_) }

      # Gérer les hôtes qui ont réussi Test-WSMan mais échoué Invoke-Command (ex: timeout, erreur d'exécution)
      $hostsScannés = $probeResults.PSComputerName
      $hostsEchoues = $reachableTargets | Where-Object { $_ -notin $hostsScannés }

      foreach ($c in $hostsEchoues) {
          $Report.Add([PSCustomObject]@{
              ComputerName    = $c
              OS              = $null
              IsWSUS          = $false
              InstalledKBs    = $null
              FoundOOBKBs     = $null
              IsPatched       = $false
              WorkaroundPorts = $null
              WorkaroundAction = $null
              Timestamp       = (Get-Date).ToString('s')
              Reachable       = $false
              Error           = "Test-WSMan OK, mais Invoke-Command a échoué (erreur d'exécution ou timeout de $OperationTimeoutSec sec dépassé)."
          })
      }
    }
    
    # Matérialiser, trier et typer la sortie
    $final = [System.Collections.Generic.List[object]]::new()
    $Report.ToArray() | Sort-Object ComputerName | ForEach-Object { $final.Add($_) } | Out-Null
    
    $final | ForEach-Object { $_.PSTypeNames.Insert(0, 'WSUS.CVE59287.Result') | Out-Null }
    
    # Retourne les objets à la console/pipeline
    Write-Output $final
  }
}


function Set-WSUSCveWorkaround {
<#
.SYNOPSIS
  Applique le workaround (règles pare-feu) sur les serveurs cibles.
.DESCRIPTION
  Prend en entrée (pipeline ou paramètre) des objets de scan ou des noms d'ordinateurs
  et applique les règles de pare-feu entrantes pour bloquer les ports 8530 et 8531.
.PARAMETER InputObject
  Objets de résultat provenant de Get-WSUSCveStatus.
.PARAMETER ComputerName
  Liste de noms d'ordinateurs où appliquer le workaround.
.PARAMETER PassThru
  Retourne les objets mis à jour après l'action.
.EXAMPLE
  Get-WSUSCveStatus -FromAD | Where-Object { $_.IsWSUS -and -not $_.IsPatched } | Set-WSUSCveWorkaround -PassThru
.EXAMPLE
  Set-WSUSCveWorkaround -ComputerName 'srv-wsus-01'
#>
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'InputObject')]
    [object[]]$InputObject,
    
    [Parameter(Mandatory = $true, ParameterSetName = 'ComputerName')]
    [string[]]$ComputerName,
    
    [pscredential]$Credential,
    [int]$ThrottleLimit = 32,
    [int]$OperationTimeoutSec = 120,

    [switch]$PassThru
  )
  
  begin {
      $targets = [System.Collections.Generic.List[object]]::new()
      
      # Paramètres pour Invoke-Command, incluant le timeout
      $invokeParams = @{
        ThrottleLimit = $ThrottleLimit
        ErrorAction   = 'SilentlyContinue'
        SessionOption = (New-PSSessionOption -OperationTimeout ($OperationTimeoutSec * 1000))
      }
      if ($Credential) { $invokeParams.Credential = $Credential }
  }
  
  process {
    if ($PSCmdlet.ParameterSetName -eq 'InputObject') {
        $InputObject | ForEach-Object { $targets.Add($_) }
    } else {
        # Si on reçoit des strings, on les convertit en objets simples pour les traiter
        $ComputerName | ForEach-Object { $targets.Add([PSCustomObject]@{ ComputerName = $_ }) }
    }
  }
  
  end {
    if ($targets.Count -eq 0) { return }
    
    $targetNames = $targets.ComputerName | Sort-Object -Unique
    Write-Info "Application du workaround sur $($targetNames.Count) hôte(s)..."
    Write-Warn "RAPPEL : Le blocage 8530/8531 rend WSUS indisponible pour les clients. Planifiez le patch puis utilisez Remove-WSUSCveWorkaround."

    $applyActions = Invoke-Command -ComputerName $targetNames `
        -ScriptBlock $script:RemoteApplyWorkaround `
        -ArgumentList @($script:RulePrefix, $script:PortsToBlock) @invokeParams
        
    # Mettre à jour les objets
    if ($PassThru -or $PSCmdlet.ParameterSetName -eq 'InputObject') {
        foreach($host in $targets){
            $actionOutput = $applyActions | Where-Object { $_.ComputerName -eq $host.ComputerName }
            if($actionOutput){
                $host.WorkaroundAction = $actionOutput.Action
            }
        }
        if ($PassThru) { Write-Output $targets }
    }
  }
}


function Remove-WSUSCveWorkaround {
<#
.SYNOPSIS
  Supprime le workaround (règles pare-feu) des serveurs cibles.
.EXAMPLE
  Get-WSUSCveStatus -FromAD | Where-Object { $_.WorkaroundPorts } | Remove-WSUSCveWorkaround -PassThru
.EXAMPLE
  Remove-WSUSCveWorkaround -ComputerName 'srv-wsus-01'
#>
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'InputObject')]
    [object[]]$InputObject,
    
    [Parameter(Mandatory = $true, ParameterSetName = 'ComputerName')]
    [string[]]$ComputerName,
    
    [pscredential]$Credential,
    [int]$ThrottleLimit = 32,
    [int]$OperationTimeoutSec = 120,

    [switch]$PassThru
  )
  
  begin {
      $targets = [System.Collections.Generic.List[object]]::new()
      
      $invokeParams = @{
        ThrottleLimit = $ThrottleLimit
        ErrorAction   = 'SilentlyContinue'
        SessionOption = (New-PSSessionOption -OperationTimeout ($OperationTimeoutSec * 1000))
      }
      if ($Credential) { $invokeParams.Credential = $Credential }
  }
  
  process {
    if ($PSCmdlet.ParameterSetName -eq 'InputObject') {
        $InputObject | ForEach-Object { $targets.Add($_) }
    } else {
        $ComputerName | ForEach-Object { $targets.Add([PSCustomObject]@{ ComputerName = $_ }) }
    }
  }
  
  end {
    if ($targets.Count -eq 0) { return }
    
    $targetNames = $targets.ComputerName | Sort-Object -Unique
    Write-Info "Vérification/Suppression du workaround sur $($targetNames.Count) hôte(s)..."

    $removeActions = Invoke-Command -ComputerName $targetNames `
        -ScriptBlock $script:RemoteRemoveWorkaround `
        -ArgumentList @($script:RulePrefix, $script:PortsToBlock) @invokeParams
        
    # Mettre à jour les objets
    if ($PassThru -or $PSCmdlet.ParameterSetName -eq 'InputObject') {
        foreach($host in $targets){
            $actionOutput = $removeActions | Where-Object { $_.ComputerName -eq $host.ComputerName }
            if($actionOutput){
                $host.WorkaroundAction = $actionOutput.Action
            }
        }
        if ($PassThru) { Write-Output $targets }
    }
  }
}


function Export-WSUSCveReport {
<#
.SYNOPSIS
  Exporte les résultats du scan dans différents formats (CSV, JSON, XLSX).
.PARAMETER InputObject
  Objets de résultat provenant de Get-WSUSCveStatus (via pipeline).
.PARAMETER ExportPath
  Chemin du dossier où sauvegarder les rapports. Le nom de fichier sera généré automatiquement.
.PARAMETER NoTranscript
  Désactive le démarrage automatique du transcript.
.EXAMPLE
  Get-WSUSCveStatus -FromAD | Export-WSUSCveReport -ExportPath 'C:\Temp\WSUS_Resp'
#>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
    [object[]]$InputObject,

    [Parameter(Mandatory = $true)]
    [string]$ExportPath,
    
    [switch]$NoTranscript
  )
  
  begin {
      $allResults = [System.Collections.Generic.List[object]]::new()
      # Création du dossier et démarrage du transcript
      New-Item -ItemType Directory -Path $ExportPath -ErrorAction SilentlyContinue | Out-Null
      if (-not $NoTranscript) {
          $Transcript = Join-Path $ExportPath "Transcript_$(Get-Date -Format yyyyMMdd_HHmmss).log"
          try { Start-Transcript -Path $Transcript -ErrorAction Stop } catch { Write-Warning "Impossible de démarrer le transcript à '$Transcript'. $($_.Exception.Message)" }
      }
  }
  
  process {
      $InputObject | ForEach-Object { $allResults.Add($_) }
  }
  
  end {
      $final = $allResults | Sort-Object ComputerName
      if ($final.Count -eq 0) {
          Write-Warn "Aucune donnée reçue. Aucun rapport ne sera généré."
          if (-not $NoTranscript) { try { Stop-Transcript } catch {} }
          return
      }

      $baseName = "WSUS_CVE59287_Report_$(Get-Date -Format yyyyMMdd_HHmmss)"
      
      # --- Exports ---
      $csv = Join-Path $ExportPath "$baseName.csv"
      $json = Join-Path $ExportPath "$baseName.json"
      $xlsx = Join-Path $ExportPath "$baseName.xlsx"

      try {
        $final | Export-Csv $csv -NoTypeInformation -Encoding UTF8
      } catch { Write-Error "Échec export CSV: $($_.Exception.Message)" }
      
      try {
        $final | ConvertTo-Json -Depth 4 | Out-File $json -Encoding UTF8
      } catch { Write-Error "Échec export JSON: $($_.Exception.Message)" }

      $vuln = $final | Where-Object { $_.IsWSUS -and -not $_.IsPatched }
      $vulnPath = Join-Path $ExportPath "Vulnerable_Hosts.txt"
      try {
        $vuln.ComputerName | Out-File $vulnPath -Encoding ascii
      } catch { Write-Error "Échec export TXT: $($_.Exception.Message)" }


      # --- EXPORT EXCEL (XLSX) ---
      try {
        Import-Module ImportExcel -ErrorAction SilentlyContinue
        
        if (Get-Command -Name Export-Excel -ErrorAction SilentlyContinue) {
          Write-Info "Création du rapport Excel : $xlsx"
          $SelectProperties = @(
              'ComputerName', 'Reachable', 'Error', 'OS', 'IsWSUS', 'IsPatched',
              'FoundOOBKBs', 'WorkaroundPorts', 'WorkaroundAction', 'Timestamp', 'InstalledKBs'
          )
          
          $final | Select-Object -Property $SelectProperties | Export-Excel -Path $xlsx `
              -WorksheetName 'Scan_CVE_WSUS' `
              -AutoSize `
              -AutoFilter `
              -BoldTopRow `
              -TableStyle Medium6 `
              -FreezeTopRow
          
          Write-Host "Rapport Excel généré : $xlsx" -ForegroundColor Cyan
                
        } else {
          Write-Warning "Module 'ImportExcel' non trouvé ou impossible à charger. Le rapport XLSX ne sera pas généré."
          Write-Warning "Installez-le avec : Install-Module ImportExcel"
        }
      } catch {
        Write-Error "Échec de la création du rapport Excel '$xlsx' : $($_.Exception.Message)"
      }
      
      # --- Résumé Console ---
      Write-Host ""
      Write-Host ("-" * 60)
      Write-Host "==== RÉSUMÉ DU SCAN ====" -ForegroundColor Yellow
      Write-Host ("-" * 60)
      Write-Host ("Total hôtes: {0}" -f $final.Count)
      Write-Host ("Hôtes injoignables: {0}" -f (($final | Where-Object { -not $_.Reachable }).Count)) -ForegroundColor Gray
      Write-Host ("WSUS détectés: {0}" -f (($final | Where-Object IsWSUS).Count))
      Write-Host ("WSUS PATCHÉS: {0}" -f (($final | Where-Object { $_.IsWSUS -and $_.IsPatched }).Count)) -ForegroundColor Green
      
      if ($vuln.Count -gt 0) {
        Write-Host ("WSUS VULNÉRABLES: {0}" -f $vuln.Count) -ForegroundColor White -BackgroundColor DarkRed
      } else {
        Write-Host ("WSUS VULNÉRABLES: {0}" -f $vuln.Count) -ForegroundColor Green
      }

      Write-Host ("-" * 60)
      Write-Host "Rapports sauvegardés dans :" -ForegroundColor Cyan
      Write-Host $ExportPath
      Write-Host ("-" * 60)
      
      if (-not $NoTranscript) { try { Stop-Transcript } catch {} }
  }
}

#endregion

# Exporter les fonctions publiques
Export-ModuleMember -Function 'Get-WSUSCveStatus', 'Set-WSUSCveWorkaround', 'Remove-WSUSCveWorkaround', 'Export-WSUSCveReport'

