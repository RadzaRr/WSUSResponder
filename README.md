# WSUSResponder (v1.0.1)

**Module PowerShell de réponse à l'incident CVE-2025-59287 — WSUS Remote Code Execution (RCE)**

Ce module PowerShell fournit un ensemble d'outils pour la **réponse à l'incident de sécurité CVE-2025-59287**, une vulnérabilité critique d'exécution de code à distance (RCE) affectant **Windows Server Update Services (WSUS)**.

---

## ⚙️ Fonctionnalités principales

- 🔍 **Scanner** l’ensemble d’un parc Active Directory ou une liste de serveurs.
- 🧩 **Identifier** les serveurs WSUS vulnérables.
- 🧱 **Vérifier** la présence des correctifs *Out-of-Band* (OOB).
- 🔒 **Appliquer un contournement** (pare-feu – blocage des ports 8530/8531).
- ♻️ **Supprimer** le contournement après patch.
- 📊 **Exporter** des rapports d’audit complets : CSV, JSON, XLSX, TXT.

---

## 📋 Prérequis

### Sur la machine d’administration
- **PowerShell 5.1+**
- **Module ActiveDirectory**  
  - Windows 10/11 :  
    ```powershell
    Add-WindowsCapability -Online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
    ```
  - Windows Server :  
    ```powershell
    Install-WindowsFeature RSAT-AD-PowerShell
    ```
- **Module ImportExcel**  
  ```powershell
  Install-Module ImportExcel -Scope CurrentUser
Sur les serveurs cibles

PowerShell 5.1+

WinRM activé :

Enable-PSRemoting -Force

📦 Installation du module

Créez un dossier nommé WSUSResponder dans un répertoire de modules PowerShell :

New-Item -ItemType Directory "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\WSUSResponder"


Copiez les fichiers :

WSUSResponder.psm1
WSUSResponder.psd1


dans ce dossier.

Importez le module :

Import-Module WSUSResponder
Get-Command -Module WSUSResponder

🧩 Fonctions Exportées
🔍 Get-WSUSCveStatus

Scanne les cibles et retourne un rapport d’état (WSUS, correctif OOB, contournement).

# Scan via Active Directory
Get-WSUSCveStatus -FromAD [-UsePS7Parallel] [-Credential <pscredential>] [-ThrottleLimit <int>] [-OperationTimeoutSec <int>]

# Scan d’une liste de serveurs
Get-WSUSCveStatus -ComputerName <string[]> [-Credential <pscredential>] [-ThrottleLimit <int>] [-OperationTimeoutSec <int>]

📊 Export-WSUSCveReport

Génère les rapports (CSV, JSON, XLSX, TXT) et un résumé console.

... | Export-WSUSCveReport -ExportPath <string>

🔒 Set-WSUSCveWorkaround

Applique les règles de pare-feu (blocage entrant ports 8530/8531).

# Via pipeline
... | Set-WSUSCveWorkaround [-PassThru]

# Sur une liste de noms
Set-WSUSCveWorkaround -ComputerName <string[]> [-PassThru]

♻️ Remove-WSUSCveWorkaround

Supprime les règles de pare-feu créées précédemment.

... | Remove-WSUSCveWorkaround [-PassThru]
Remove-WSUSCveWorkaround -ComputerName <string[]> [-PassThru]

🧭 Exemples de Workflows

📄 Voir Use-WSUSResponder.ps1 pour les exemples détaillés.

🔹 Workflow 1 : Audit Seul
$ReportPath = "C:\Temp\WSUS_Audit_$(Get-Date -Format yyyyMMdd)"
Get-WSUSCveStatus -FromAD -UsePS7Parallel | Export-WSUSCveReport -ExportPath $ReportPath

🔹 Workflow 2 : Réponse à Incident
$scanResults = Get-WSUSCveStatus -FromAD -UsePS7Parallel
$vulnerable = $scanResults | Where-Object { $_.IsWSUS -and -not $_.IsPatched -and $_.Reachable }
$vulnerable | Set-WSUSCveWorkaround -PassThru | Out-Null
$scanResults | Export-WSUSCveReport -ExportPath "C:\Temp\WSUS_Mitigation"

🔹 Workflow 3 : Rollback (après patch)
$serversPatched = 'srv-wsus-01', 'srv-wsus-02'
Remove-WSUSCveWorkaround -ComputerName $serversPatched

🔏 (Optionnel) Signature du module

Pour exécution sur des systèmes avec AllSigned :

New-SelfSignedCertificate -Type CodeSigning -Subject "CN=IT Ops" -CertStoreLocation Cert:\CurrentUser\My
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1
Set-AuthenticodeSignature -FilePath .\WSUSResponder.psm1 -Certificate $cert
Set-AuthenticodeSignature -FilePath .\WSUSResponder.psd1 -Certificate $cert

🧰 Auteurs et Maintenance

Auteur principal : Rom1 /RZA

Version : 1.0.1

Date : 27/10/2025

Licence : MIT

Tags : WSUS, CVE, Sécurité, PowerShell, Automatisation