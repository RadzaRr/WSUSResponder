# 🧰 WSUSResponder

**Version : 1.0.1**  
**Auteur : RZA / IT Operations**  
**Licence : [MIT](LICENSE)**  

---

## 🎯 Objectif

Le module **WSUSResponder** fournit un ensemble d’outils PowerShell pour **répondre rapidement à la vulnérabilité critique CVE-2025-59287**, une faille d’exécution de code à distance (RCE) affectant **Windows Server Update Services (WSUS)**.

Il permet de :

- 🔍 Scanner un parc Active Directory ou une liste de serveurs ciblés  
- 🧩 Identifier les serveurs WSUS vulnérables  
- 🛡️ Vérifier la présence des correctifs **Out-of-Band (OOB)** publiés par Microsoft  
- 🚧 Appliquer un **workaround pare-feu** (blocage ports 8530/8531)  
- ♻️ Retirer ce workaround une fois les serveurs patchés  
- 📊 Générer des rapports d’audit complets (CSV, JSON, XLSX)

---

## ⚙️ Prérequis

### Modules PowerShell nécessaires
| Module | Rôle | Installation |
|---------|------|--------------|
| **ActiveDirectory** | Découverte automatique des serveurs via AD | `Add-WindowsCapability -Online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'` |
| **ImportExcel** | Génération des rapports Excel (.xlsx) | `Install-Module ImportExcel -Scope CurrentUser` |

### Environnement requis
- PowerShell **5.1+**  
- WinRM activé sur les serveurs cibles (`Enable-PSRemoting`)  
- Droits d’administrateur local sur les hôtes distants  

---

## 📦 Installation

1. Créez un dossier nommé `WSUSResponder` dans l’un de vos répertoires de modules PowerShell :  
   ```powershell
   $Path = "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\WSUSResponder"
   New-Item -ItemType Directory -Path $Path -Force
Copiez les fichiers du module :

WSUSResponder.psm1

WSUSResponder.psd1

Importez le module :

powershell
Copier le code
Import-Module WSUSResponder
Get-Command -Module WSUSResponder
Vérifiez le chargement :

powershell
Copier le code
Get-Module WSUSResponder -ListAvailable
🧩 Fonctions exportées
Fonction	Description
Get-WSUSCveStatus	Scanne les serveurs pour détecter la présence du rôle WSUS et des correctifs OOB.
Set-WSUSCveWorkaround	Applique le contournement (règles pare-feu bloquant les ports 8530/8531).
Remove-WSUSCveWorkaround	Supprime les règles pare-feu créées par le workaround.
Export-WSUSCveReport	Exporte les résultats du scan dans plusieurs formats (CSV, JSON, XLSX, TXT).

🚀 Exemples d’utilisation
🔎 Audit complet du domaine AD
powershell
Copier le code
$ReportPath = "C:\Temp\WSUS_Audit_$(Get-Date -Format yyyyMMdd)"
Get-WSUSCveStatus -FromAD -UsePS7Parallel | Export-WSUSCveReport -ExportPath $ReportPath
🛡️ Scan + Application du Workaround
powershell
Copier le code
$scanResults = Get-WSUSCveStatus -FromAD -UsePS7Parallel
$vulnerable = $scanResults | Where-Object { $_.IsWSUS -and -not $_.IsPatched -and $_.Reachable }
$vulnerable | Set-WSUSCveWorkaround -PassThru
$scanResults | Export-WSUSCveReport -ExportPath "C:\Temp\WSUS_Mitig_$(Get-Date -Format yyyyMMdd)"
🔁 Suppression du Workaround après patching
powershell
Copier le code
Remove-WSUSCveWorkaround -ComputerName 'srv-wsus-01','srv-wsus-02'
📊 Rapports générés
Les rapports sont sauvegardés dans le dossier défini par -ExportPath :

Fichier	Format	Contenu
WSUS_CVE59287_Report.csv	CSV	Résultats complets du scan
WSUS_CVE59287_Report.json	JSON	Export structuré pour API/automatisation
WSUS_CVE59287_Report.xlsx	XLSX	Rapport formaté avec filtres automatiques
Vulnerable_Hosts.txt	TXT	Liste simple des hôtes vulnérables

🧱 Architecture technique
Utilisation de Invoke-Command et WinRM pour exécution distante

Parallélisme natif PS7 (ForEach-Object -Parallel) pour accélérer les pré-tests

Timeout configurable via -OperationTimeoutSec

Workaround idempotent (pas de duplication de règles)

Export multi-format automatisé (CSV, JSON, XLSX via ImportExcel)

🔐 Sécurité et Signature du module
Si votre politique d’exécution est AllSigned, vous pouvez signer le module :

powershell
Copier le code
New-SelfSignedCertificate -Type CodeSigning -Subject "CN=IT Operations" -CertStoreLocation Cert:\CurrentUser\My
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1
Set-AuthenticodeSignature -FilePath "C:\Modules\WSUSResponder\WSUSResponder.psm1" -Certificate $cert
Set-AuthenticodeSignature -FilePath "C:\Modules\WSUSResponder\WSUSResponder.psd1" -Certificate $cert
🧾 Changelog
v1.0.1 – (27/10/2025)
Refactor complet en module PowerShell (.psm1 / .psd1)

Ajout du support parallèle PS7 (-UsePS7Parallel)

Nouveau moteur d’export (CSV, JSON, XLSX)

Correction de la gestion du timeout WinRM

Rollback idempotent des règles pare-feu

🧑‍💻 Auteurs
(RZA) — IT Operations

Contributeurs internes Sécurité Microsoft / DOT_SU_KIOSQUE_CENTER

📜 Licence
Distribué sous licence MIT.
© 2025 RZA / IT Operations – Tous droits réservés.

