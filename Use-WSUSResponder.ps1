<#
.SYNOPSIS
  Exemple d'utilisation du module WSUSResponder.
  
.DESCRIPTION
  Ce script montre comment importer le module .psm1 (en supposant qu'il est
  dans le même dossier) et utiliser les fonctions exportées pour
  scanner, rapporter et corriger.

.NOTES
  Assurez-vous que les modules 'ActiveDirectory' et 'ImportExcel' sont installés.
  (Voir les messages d'avertissement du module pour les commandes d'installation si nécessaire).
#>

# --- Vérification des droits Administrateur ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Ce script doit être exécuté en tant qu'administrateur pour importer le module et exécuter les actions distantes."
    Write-Warning "Veuillez relancer la console PowerShell en mode Administrateur."
    # Attendre une touche pour que l'utilisateur puisse lire le message
    if ($Host.Name -eq "ConsoleHost") {
        Read-Host -Prompt "Appuyez sur Entrée pour quitter"
    }
    return
}

# Chemin vers le dossier des rapports
$ReportPath = "C:\Temp\WSUS_CVE_Report_$(Get-Date -Format yyyyMMdd_HHmmss)"
New-Item -ItemType Directory -Path $ReportPath -ErrorAction SilentlyContinue | Out-Null

# Importer le module depuis son chemin (en supposant qu'il est dans le même dossier que ce script)
try {
    # $PSScriptRoot est le dossier contenant ce script
    Import-Module -Name (Join-Path $PSScriptRoot "WSUSResponder.psd1") -Force -ErrorAction Stop
} catch {
    Write-Error "Impossible de charger le module WSUSResponder.psd1. Vérifiez le chemin."
    Write-Error $_.Exception.Message
    return
}

Write-Host "Module WSUSResponder importé. Lancement du scan..." -ForegroundColor Green

# -----------------------------------------------------------------
# EXEMPLE 1: Scan AD complet et export des rapports
# -----------------------------------------------------------------
# Les résultats sont passés par pipeline de Get- à Export-
# Le transcript et le résumé console sont gérés par Export-WSUSCveReport
#
Write-Host "--- Lancement du scan AD complet et export ---"
Get-WSUSCveStatus -FromAD -UsePS7Parallel -ErrorAction SilentlyContinue | Export-WSUSCveReport -ExportPath $ReportPath


# -----------------------------------------------------------------
# EXEMPLE 2: Scan, puis application du Workaround sur les vulnérables
# -----------------------------------------------------------------
#
# Write-Host "--- Lancement du scan ET application du workaround ---"
# $scanResults = Get-WSUSCveStatus -FromAD -UsePS7Parallel -ErrorAction SilentlyContinue
#
# $vulnerable = $scanResults | Where-Object { $_.IsWSUS -and -not $_.IsPatched -and $_.Reachable }
#
# if ($vulnerable) {
#    Write-Host "Application du workaround sur $($vulnerable.Count) hôte(s)..." -ForegroundColor Yellow
#    $vulnerable | Set-WSUSCveWorkaround
# } else {
#    Write-Host "Aucun hôte vulnérable trouvé nécessitant le workaround." -ForegroundColor Green
# }
#
# # Exporter le rapport final (avec les WorkaroundActions mises à jour)
# $scanResults | Export-WSUSCveReport -ExportPath $ReportPath


# -----------------------------------------------------------------
# EXEMPLE 3: Retrait du Workaround sur des serveurs spécifiques
# -----------------------------------------------------------------
#
# Write-Host "--- Retrait du workaround ---"
# $serversToClean = 'srv-wsus-01', 'srv-wsus-02'
# Remove-WSUSCveWorkaround -ComputerName $serversToClean


# -----------------------------------------------------------------
# (OPTIONNEL) Signature du module pour la distribution
# -----------------------------------------------------------------
#
# 1. Créer un certificat de signature de code (une seule fois)
# New-SelfSignedCertificate -Type CodeSigning -Subject "CN=IT Operations" -CertStoreLocation Cert:\CurrentUser\My
#
# 2. Signer le module
# $cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1
# if ($cert) {
#    Set-AuthenticodeSignature -FilePath (Join-Path $PSScriptRoot "WSUSResponder.psm1") -Certificate $cert
#    Set-AuthenticodeSignature -FilePath (Join-Path $PSScriptRoot "WSUSResponder.psd1") -Certificate $cert
#    Write-Host "Module signé avec le certificat $($cert.Subject)" -ForegroundColor Cyan
# } else {
#    Write-Warning "Aucun certificat de signature de code trouvé dans Cert:\CurrentUser\My"
# }


Write-Host "Opérations terminées. Rapports disponibles dans $ReportPath"

