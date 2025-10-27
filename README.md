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




