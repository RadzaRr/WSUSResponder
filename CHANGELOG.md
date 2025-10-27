# Historique des versions – WSUSResponder

## 1.0.1 (2025-10-27)
- Ajout du paramètre `-UsePS7Parallel` pour paralléliser le pré-test WinRM.
- Ajout de `-OperationTimeoutSec` pour limiter la durée des opérations distantes.
- Nettoyage complet du code et conversion en module structuré.
- Ajout du script d’exemple `Use-WSUSResponder.ps1`.

## 1.0.0 (2025-10-25)
- Version initiale du script WSUS-CVE-59287-Responder.ps1.
- Détection WSUS, vérification KBs, application du workaround.
- Export CSV/JSON/XLSX.
