# TP 2 — Hash SHA-256 & Vérification d'Intégrité
# BTS SIO/SISR — Scripting & Sauvegarde
#
# Objectifs :
#   - Calculer des empreintes SHA-256 par blocs (économie mémoire)
#   - Comparer des fichiers via leur hash
#   - Créer et vérifier un manifeste JSON (norme ISO 27001)
#   - Détecter les fichiers corrompus ou modifiés

import hashlib
import json
import os
from datetime import datetime


# ═══════════════════════════════════════════════════════════════
# PARTIE B — Implémenter SHA-256 en Python
# ═══════════════════════════════════════════════════════════════

def calculer_hash_fichier(chemin):
    """
    Calcule l'empreinte SHA-256 d'un fichier par blocs de 4 Ko.

    Lecture par blocs = consommation mémoire CONSTANTE, quelle que
    soit la taille du fichier (1 Mo ou 10 Go → même empreinte RAM).

    Args:
        chemin (str) : chemin vers le fichier à hacher

    Returns:
        str : empreinte SHA-256 en hexadécimal (64 caractères)
    """
    hasher = hashlib.sha256()

    with open(chemin, 'rb') as f:
        # iter(callable, sentinel) : appelle f.read(4096) jusqu'à obtenir b''
        for bloc in iter(lambda: f.read(4096), b''):
            hasher.update(bloc)  # Alimente le hasher bloc par bloc

    return hasher.hexdigest()  # Retourne 64 caractères hexadécimaux


def fichiers_identiques(chemin1, chemin2):
    """
    Vérifie si deux fichiers sont identiques via leur hash SHA-256.
    Si les hashs sont égaux, le contenu l'est aussi (probabilité de
    collision SHA-256 négligeable en pratique).

    Args:
        chemin1 (str) : premier fichier
        chemin2 (str) : second fichier

    Returns:
        bool : True si identiques, False sinon
    """
    hash1 = calculer_hash_fichier(chemin1)
    hash2 = calculer_hash_fichier(chemin2)
    return hash1 == hash2


# ═══════════════════════════════════════════════════════════════
# PARTIE C — Manifeste de Sauvegarde ISO 27001
# ═══════════════════════════════════════════════════════════════
#
# Le manifeste est un fichier JSON stocké EN CLAIR, séparé des
# données chiffrées. Il documente chaque fichier sauvegardé avec :
#   - son chemin relatif
#   - son hash SHA-256
#   - sa taille en octets
#   - un horodatage ISO 8601
#
# Règle ISO 27001 : stocker le manifeste HORS du dossier source.

def creer_manifeste(dossier_source, fichiers_liste, chemin_manifeste="backup.manifest"):
    """
    Crée un manifeste JSON documentant l'état de chaque fichier.

    Args:
        dossier_source (str)    : dossier contenant les fichiers
        fichiers_liste (list)   : liste des noms de fichiers à documenter
        chemin_manifeste (str)  : chemin du fichier manifeste à créer

    Returns:
        dict : le manifeste créé
    """
    manifeste = {
        "timestamp": datetime.now().isoformat(),  # ISO 8601
        "total_fichiers": len(fichiers_liste),
        "fichiers": []
    }

    total_octets = 0

    for fichier in fichiers_liste:
        chemin_complet = os.path.join(dossier_source, fichier)

        hash_val = calculer_hash_fichier(chemin_complet)
        taille   = os.path.getsize(chemin_complet)

        manifeste["fichiers"].append({
            "chemin": fichier,
            "hash":   hash_val,
            "taille": taille
        })

        total_octets += taille

    manifeste["total_octets"] = total_octets

    # Sérialiser en JSON lisible (indent=2)
    with open(chemin_manifeste, 'w', encoding='utf-8') as f:
        json.dump(manifeste, f, indent=2)

    return manifeste


def verifier_manifeste(dossier, manifeste_path):
    """
    Relit le manifeste et recalcule le hash de chaque fichier.
    Tout écart signale une corruption ou une modification.

    Args:
        dossier (str)        : dossier contenant les fichiers à vérifier
        manifeste_path (str) : chemin vers le fichier manifeste

    Returns:
        list[dict] : résultats par fichier avec clés 'fichier', 'valide',
                     'hash_calcule', 'hash_attendu'
    """
    with open(manifeste_path, 'r', encoding='utf-8') as f:
        manifeste = json.load(f)

    resultats = []

    for fichier_info in manifeste["fichiers"]:
        chemin = os.path.join(dossier, fichier_info['chemin'])

        hash_calcule = calculer_hash_fichier(chemin)
        hash_attendu = fichier_info['hash']

        resultats.append({
            "fichier":      fichier_info['chemin'],
            "valide":       hash_calcule == hash_attendu,
            "hash_calcule": hash_calcule,
            "hash_attendu": hash_attendu
        })

    return resultats


def rapport_verif_complet(dossier, manifeste_path):
    """
    Génère un rapport formaté de vérification d'intégrité.

    Args:
        dossier (str)        : dossier source à vérifier
        manifeste_path (str) : chemin du manifeste de référence

    Returns:
        bool : True si tous les fichiers sont intègres, False sinon
    """
    resultats = verifier_manifeste(dossier, manifeste_path)

    total    = len(resultats)
    valides  = sum(1 for r in resultats if r['valide'])  # Expression génératrice
    corrompus = total - valides

    print(f"\n{'=' * 60}")
    print("RAPPORT DE VÉRIFICATION D'INTÉGRITÉ")
    print(f"{'=' * 60}")
    print(f"Manifeste     : {manifeste_path}")
    print(f"Fichiers vérifiés : {total}")
    print(f"  ✓ Intègres  : {valides}")
    print(f"  ✗ Corrompus : {corrompus}")

    if corrompus > 0:
        print("\nFichiers problématiques :")
        for r in resultats:
            if not r['valide']:
                print(f"  - {r['fichier']}")
                print(f"    Attendu  : {r['hash_attendu'][:20]}...")
                print(f"    Calculé  : {r['hash_calcule'][:20]}...")

    statut = "✓ OK — Intégrité confirmée" if corrompus == 0 else "✗ ERREURS DÉTECTÉES"
    print(f"\nStatut global : {statut}")
    print("=" * 60)

    return corrompus == 0  # Retour booléen pour intégration CI/CD ou cron


# ═══════════════════════════════════════════════════════════════
# PARTIE D — Workflow complet avec chiffrement (intégration TP1)
# ═══════════════════════════════════════════════════════════════

def workflow_sauvegarde_integre(chemin_source, cle):
    """
    Workflow complet : hash avant chiffrement → chiffrement →
    hash après chiffrement → manifeste.

    Double vérification :
      - hash_original  : intégrité du fichier SOURCE
      - hash_chiffre   : intégrité du fichier CHIFFRÉ (détecte corruption transit)

    Args:
        chemin_source (str) : fichier à sauvegarder
        cle (bytes)         : clé Fernet

    Returns:
        dict : manifeste avec les deux hashes
    """
    from cryptography.fernet import Fernet

    chemin_enc = chemin_source + '.enc'

    # 1. Hash avant chiffrement
    hash_original = calculer_hash_fichier(chemin_source)

    # 2. Chiffrer
    with open(chemin_source, 'rb') as f:
        contenu = f.read()
    ciphertext = Fernet(cle).encrypt(contenu)
    with open(chemin_enc, 'wb') as f:
        f.write(ciphertext)

    # 3. Hash du fichier chiffré
    hash_chiffre = calculer_hash_fichier(chemin_enc)

    # 4. Manifeste avec les deux hashes
    manifeste = {
        "timestamp":      datetime.now().isoformat(),
        "fichier_source": chemin_source,
        "hash_original":  hash_original,
        "fichier_chiffre": chemin_enc,
        "hash_chiffre":   hash_chiffre
    }

    chemin_manifeste = chemin_source + '.manifest'
    with open(chemin_manifeste, 'w', encoding='utf-8') as f:
        json.dump(manifeste, f, indent=2)

    return manifeste


# ═══════════════════════════════════════════════════════════════
# Tests
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 55)
    print("TP 2 — Hash SHA-256 & Vérification d'Intégrité")
    print("=" * 55)

    # Créer un dossier de test temporaire
    os.makedirs('test_data', exist_ok=True)

    # Créer des fichiers de test
    fichiers_test = ['fichier1.txt', 'fichier2.txt', 'fichier3.txt']
    for i, nom in enumerate(fichiers_test, 1):
        with open(f'test_data/{nom}', 'w', encoding='utf-8') as f:
            f.write(f'Contenu du fichier {i}\n' * (i * 5))

    print("\n[1] Calcul de hash SHA-256")
    for nom in fichiers_test:
        h = calculer_hash_fichier(f'test_data/{nom}')
        print(f"    {nom} → {h[:20]}...")

    print("\n[2] Comparaison de fichiers")
    import shutil
    shutil.copy('test_data/fichier1.txt', 'test_data/fichier1_copie.txt')
    identiques = fichiers_identiques('test_data/fichier1.txt', 'test_data/fichier1_copie.txt')
    print(f"    fichier1 == copie    : {'✓ Identiques' if identiques else '✗ Différents'}")
    differents = fichiers_identiques('test_data/fichier1.txt', 'test_data/fichier2.txt')
    print(f"    fichier1 == fichier2 : {'✓ Identiques' if differents else '✓ Différents (attendu)'}")

    print("\n[3] Création du manifeste")
    creer_manifeste('test_data', fichiers_test, 'test_data/backup.manifest')
    print("    ✓ backup.manifest créé")

    print("\n[4] Vérification du manifeste (avant corruption)")
    rapport_verif_complet('test_data', 'test_data/backup.manifest')

    print("\n[5] Simulation de corruption d'un fichier")
    with open('test_data/fichier2.txt', 'a', encoding='utf-8') as f:
        f.write('\nFICHIER CORROMPU !')
    rapport_verif_complet('test_data', 'test_data/backup.manifest')

    # Nettoyage
    shutil.rmtree('test_data')

    print("\n✓ TP 2 COMPLET")
