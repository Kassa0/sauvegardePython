# 🔐 Scripting & Sauvegarde Sécurisée

> BTS SIO/SISR 2ème année — Module Scripting & Sauvegarde  
> Pipeline de sauvegarde Python conforme **ISO 27001** : chiffrement AES-256, hachage SHA-256, archivage ZIP.

---

## 📁 Structure du projet

```
scripting-sauvegarde/
│
├── tp1_aes256/
│   ├── tp1_chiffrement.py       # Lecture binaire + chiffrement Fernet/AES-256
│   └── README.md
│
├── tp2_sha256/
│   ├── tp2_integrite.py         # Hachage SHA-256 + manifeste JSON ISO 27001
│   └── README.md
│
├── tp3_archivage/
│   ├── tp3_zip.py               # Archivage ZIP récursif + extraction sécurisée
│   └── README.md
│
├── tp4_pipeline/
│   ├── backup_pipeline.py       # Script complet : BackupManager + RestoreManager
│   └── README.md
│
├── tp5_iso27001/
│   ├── tests_iso27001.py        # Framework de tests conformité ISO 27001
│   ├── exercices_avances.py     # Rotation clés, backup incrémental, quarantaine, audit
│   └── README.md
│
├── .gitignore
├── requirements.txt
└── README.md                    ← vous êtes ici
```

---

## ⚙️ Installation

```bash
# 1. Cloner le dépôt
git clone https://github.com/VOTRE_USERNAME/scripting-sauvegarde.git
cd scripting-sauvegarde

# 2. (Optionnel) Créer un environnement virtuel
python -m venv venv
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate           # Windows

# 3. Installer les dépendances
pip install -r requirements.txt
```

---

## 🚀 Utilisation rapide

### Lancer le pipeline complet (TP4)
```bash
python tp4_pipeline/backup_pipeline.py
```

### Lancer les tests ISO 27001 (TP5)
```bash
python tp5_iso27001/tests_iso27001.py
```

### Tester chaque TP individuellement
```bash
python tp1_aes256/tp1_chiffrement.py
python tp2_sha256/tp2_integrite.py
python tp3_archivage/tp3_zip.py
```

---

## 📚 Progression des TPs

| TP | Thème | Modules Python | Durée |
|----|-------|---------------|-------|
| TP1 | Chiffrement AES-256 avec Fernet | `cryptography` | 90 min |
| TP2 | Hachage SHA-256 & manifeste ISO 27001 | `hashlib`, `json`, `os` | 60 min |
| TP3 | Archivage ZIP récursif | `zipfile`, `os` | 90 min |
| TP4 | Pipeline de sauvegarde complet | tous | 120 min |
| TP5 | Tests conformité ISO 27001 | `threading`, `logging` | 120 min |

---

## 🔒 Concepts clés abordés

- **AES-256** : chiffrement symétrique via `cryptography.fernet`
- **SHA-256** : vérification d'intégrité par empreinte cryptographique
- **Manifeste JSON** : documentation ISO 27001 des sauvegardes
- **Archivage ZIP** : compression `DEFLATE` et parcours récursif `os.walk()`
- **Pipeline complet** : archiver → hacher → vérifier → chiffrer → logger

---

## ⚠️ Règles de sécurité importantes

- Ne **jamais** committer de fichiers `.key` ou `.enc`
- Ne **jamais** coder une clé en dur dans le source
- Toujours utiliser les modes `'rb'` / `'wb'` pour les fichiers binaires
- En production : stocker les clés dans un gestionnaire de secrets (AWS KMS, HashiCorp Vault)

---

## 📋 Norme ISO 27001 — Contrôles implémentés

| Contrôle | Exigence | Implémentation |
|----------|----------|---------------|
| A.10.1.1 | Chiffrement fort | Fernet / AES-256 / IV aléatoire |
| A.12.4.1 | Logging & Audit | AuditLogger append-only |
| A.14.1.1 | Contrôle d'accès | `os.chmod(fichier, 0o600)` |
| A.14.1.2 | Intégrité sauvegardes | SHA-256 + manifeste |
| A.14.1.3 | RTO / RPO | `ThreadPoolExecutor` |
| A.14.3   | Rétention & archivage | Rotation clés 90 jours |
