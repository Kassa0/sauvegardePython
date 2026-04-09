# TP 3 — Archivage ZIP & Intégration
# BTS SIO/SISR — Scripting & Sauvegarde
#
# Objectifs :
#   - Créer des archives ZIP avec compression DEFLATE
#   - Archiver récursivement un dossier complet (os.walk)
#   - Extraire avec validation d'intégrité (testzip)
#   - Intégrer archivage + manifeste + chiffrement en pipeline

import zipfile
import os
import json
from datetime import datetime


# ═══════════════════════════════════════════════════════════════
# PARTIE A — Créer et Explorer des Archives ZIP
# ═══════════════════════════════════════════════════════════════

def creer_archive_simple(nom_archive, fichiers_liste):
    """
    Crée une archive ZIP contenant une liste de fichiers.
    Utilise la compression DEFLATE (sans perte, standard ZIP).

    Args:
        nom_archive (str)     : chemin de l'archive à créer (.zip)
        fichiers_liste (list) : liste des chemins de fichiers à archiver
    """
    with zipfile.ZipFile(nom_archive, 'w', zipfile.ZIP_DEFLATED) as zf:
        for fichier in fichiers_liste:
            zf.write(fichier)
            print(f"  + {fichier}")

    taille = os.path.getsize(nom_archive)
    print(f"  Archive créée : {nom_archive} ({taille} octets)")


def lister_archive(nom_archive):
    """
    Affiche le contenu d'une archive ZIP de manière formatée.

    Args:
        nom_archive (str) : chemin de l'archive à lister
    """
    with zipfile.ZipFile(nom_archive, 'r') as zf:
        print(f"\nContenu de {nom_archive} :")
        zf.printdir()
        return zf.namelist()


# ═══════════════════════════════════════════════════════════════
# PARTIE B — Archivage Récursif d'un Dossier Complet
# ═══════════════════════════════════════════════════════════════
#
# os.walk() descend dans tous les sous-dossiers.
# arcname = chemin RELATIF dans l'archive ≠ chemin absolu sur disque.
# Sans arcname correct, l'archive embarque les chemins absolus (/home/user/...).

EXCLUSIONS_DEFAUT = ['.pyc', '__pycache__', '.git', 'node_modules', '.DS_Store', '.tmp']


def archiver_dossier(dossier_source, nom_archive, exclusions=None):
    """
    Archive récursivement tout un dossier en préservant la structure.

    Args:
        dossier_source (str) : dossier à archiver
        nom_archive (str)    : chemin de l'archive ZIP à créer
        exclusions (list)    : extensions/noms à exclure (défaut : .pyc, __pycache__, etc.)

    Returns:
        tuple : (nombre de fichiers archivés, taille totale originale en octets)
    """
    if exclusions is None:
        exclusions = EXCLUSIONS_DEFAUT

    nb_fichiers   = 0
    octets_source = 0

    with zipfile.ZipFile(nom_archive, 'w', zipfile.ZIP_DEFLATED) as zf:
        # os.walk() retourne (racine, liste_dossiers, liste_fichiers)
        for racine, dossiers, fichiers in os.walk(dossier_source):

            # Filtrer les dossiers exclus (modifie la liste en place pour éviter la descente)
            dossiers[:] = [d for d in dossiers if d not in exclusions]

            for fichier in fichiers:
                # Ignorer les fichiers correspondant aux exclusions
                if any(excl in fichier for excl in exclusions):
                    continue

                chemin_complet = os.path.join(racine, fichier)

                # arcname : chemin RELATIF à dossier_source → structure préservée
                arcname = os.path.relpath(chemin_complet, dossier_source)

                zf.write(chemin_complet, arcname=arcname)

                taille = os.path.getsize(chemin_complet)
                octets_source += taille
                nb_fichiers   += 1

    # Ratio de compression
    taille_archive = os.path.getsize(nom_archive)
    if octets_source > 0:
        ratio = (1 - taille_archive / octets_source) * 100
        print(f"  Archive : {nom_archive}")
        print(f"  Fichiers archivés : {nb_fichiers}")
        print(f"  Taille source  : {octets_source:,} octets")
        print(f"  Taille archive : {taille_archive:,} octets")
        print(f"  Compression    : {ratio:.1f}%")

    return nb_fichiers, octets_source


# ═══════════════════════════════════════════════════════════════
# PARTIE C — Extraction Contrôlée et Sécurisée
# ═══════════════════════════════════════════════════════════════
#
# TOUJOURS valider avec testzip() avant d'extraire.
# testzip() → None si archive saine, sinon nom du 1er fichier corrompu.

def extraire_archive(nom_archive, dossier_destination):
    """
    Extrait une archive ZIP après validation d'intégrité.

    Protection contre :
      - Archives corrompues (testzip)
      - Zip Slip attack (validation des chemins)
      - Fichier ZIP invalide (BadZipFile)

    Args:
        nom_archive (str)          : chemin de l'archive à extraire
        dossier_destination (str)  : dossier de destination

    Returns:
        bool : True si extraction réussie, False sinon
    """
    try:
        os.makedirs(dossier_destination, exist_ok=True)

        with zipfile.ZipFile(nom_archive, 'r') as zf:

            # Étape 1 : Vérifier l'intégrité de l'archive
            fichier_corrompu = zf.testzip()
            if fichier_corrompu is not None:
                print(f"  ERREUR : Archive corrompue ! Premier fichier invalide : {fichier_corrompu}")
                return False

            # Étape 2 : Protection Zip Slip (chemin traversal attack)
            destination_abs = os.path.abspath(dossier_destination)
            for membre in zf.namelist():
                chemin_cible = os.path.abspath(os.path.join(dossier_destination, membre))
                if not chemin_cible.startswith(destination_abs):
                    print(f"  ERREUR : Chemin suspect détecté (Zip Slip) : {membre}")
                    return False

            # Étape 3 : Extraction
            zf.extractall(dossier_destination)

            nb = len(zf.namelist())
            print(f"  ✓ Extraction réussie : {nb} fichier(s) → {dossier_destination}")
            return True

    except zipfile.BadZipFile:
        print(f"  ERREUR : {nom_archive} n'est pas une archive ZIP valide")
        return False
    except Exception as e:
        print(f"  ERREUR inattendue lors de l'extraction : {e}")
        return False


# ═══════════════════════════════════════════════════════════════
# PARTIE D — Pipeline Complet Jour 2
# ═══════════════════════════════════════════════════════════════
#
# Combine les trois TPs : ZIP → manifeste → chiffrement Fernet

def pipeline_sauvegarde_jour2(dossier_source, nom_backup, cle=None):
    """
    Pipeline complet de sauvegarde :
      1. Archivage ZIP du dossier source
      2. Calcul du hash SHA-256 de l'archive
      3. Génération du manifeste JSON
      4. Chiffrement de l'archive avec Fernet

    Args:
        dossier_source (str) : dossier à sauvegarder
        nom_backup (str)     : préfixe du nom des fichiers générés
        cle (bytes)          : clé Fernet (générée si None)

    Returns:
        bytes : la clé Fernet utilisée
    """
    from cryptography.fernet import Fernet
    import hashlib

    # Importer la fonction de hash du TP2
    def _hash(chemin):
        hasher = hashlib.sha256()
        with open(chemin, 'rb') as f:
            for bloc in iter(lambda: f.read(4096), b''):
                hasher.update(bloc)
        return hasher.hexdigest()

    if cle is None:
        cle = Fernet.generate_key()

    archive_name   = f"{nom_backup}.zip"
    manifeste_name = f"{nom_backup}.manifest"
    chiffre_name   = f"{nom_backup}.zip.enc"

    # Étape 1 : Créer l'archive ZIP
    print("\n[1] Création de l'archive ZIP...")
    nb, _ = archiver_dossier(dossier_source, archive_name)

    # Étape 2 : Calculer le hash de l'archive
    print("\n[2] Calcul du hash SHA-256 de l'archive...")
    hash_archive = _hash(archive_name)
    print(f"    SHA-256 : {hash_archive[:20]}...")

    # Étape 3 : Générer le manifeste JSON
    print("\n[3] Génération du manifeste...")
    manifeste = {
        "timestamp":    datetime.now().isoformat(),
        "backup_name":  nom_backup,
        "archive":      archive_name,
        "hash_archive": hash_archive,
        "taille_bytes": os.path.getsize(archive_name),
        "nb_fichiers":  nb
    }
    with open(manifeste_name, 'w', encoding='utf-8') as f:
        json.dump(manifeste, f, indent=2)
    print(f"    Manifeste : {manifeste_name}")

    # Étape 4 : Chiffrer l'archive
    print("\n[4] Chiffrement de l'archive...")
    with open(archive_name, 'rb') as f:
        contenu = f.read()
    ciphertext = Fernet(cle).encrypt(contenu)
    with open(chiffre_name, 'wb') as f:
        f.write(ciphertext)

    print(f"\n{'=' * 50}")
    print("✓ Sauvegarde créée avec succès !")
    print(f"  Archive   : {archive_name}")
    print(f"  Manifeste : {manifeste_name}")
    print(f"  Chiffré   : {chiffre_name}")
    print(f"  Clé       : {cle.decode()[:20]}...")
    print(f"{'=' * 50}")

    return cle


# ═══════════════════════════════════════════════════════════════
# Tests
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import shutil

    print("=" * 55)
    print("TP 3 — Archivage ZIP & Intégration")
    print("=" * 55)

    # Créer un dossier de test avec structure hiérarchique
    os.makedirs('projet_test/src', exist_ok=True)
    os.makedirs('projet_test/docs', exist_ok=True)
    os.makedirs('projet_test/src/__pycache__', exist_ok=True)  # Doit être exclu

    for nom, contenu in [
        ('projet_test/src/main.py',       'print("Hello")\n' * 20),
        ('projet_test/src/utils.py',      'def helper(): pass\n' * 15),
        ('projet_test/docs/readme.txt',   'Documentation du projet\n' * 10),
        ('projet_test/config.json',       '{"version": "1.0"}\n'),
        ('projet_test/src/__pycache__/main.pyc', 'bytecode'),  # Doit être exclu
    ]:
        with open(nom, 'w') as f:
            f.write(contenu)

    # --- Test A : Archive simple ---
    print("\n[Test A] Archive simple")
    creer_archive_simple('test_simple.zip', ['projet_test/config.json'])
    lister_archive('test_simple.zip')

    # --- Test B : Archive récursive ---
    print("\n[Test B] Archive récursive")
    archiver_dossier('projet_test', 'test_recursif.zip')

    # --- Test C : Extraction sécurisée ---
    print("\n[Test C] Extraction sécurisée")
    extraire_archive('test_recursif.zip', 'projet_restaure')

    # --- Test D : Pipeline complet ---
    print("\n[Test D] Pipeline complet")
    cle = pipeline_sauvegarde_jour2('projet_test', 'backup_test')

    # Nettoyage
    for item in ['projet_test', 'projet_restaure', 'test_simple.zip',
                 'test_recursif.zip', 'backup_test.zip',
                 'backup_test.manifest', 'backup_test.zip.enc']:
        if os.path.isdir(item):
            shutil.rmtree(item)
        elif os.path.exists(item):
            os.remove(item)

    print("\n✓ TP 3 COMPLET")
