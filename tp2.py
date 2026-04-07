from datetime import datetime
import json
import hashlib
import os
# B1


def calculer_hash_fichier(chemin):
    hasher = hashlib.sha256()
    # ??? module ?

    with open(chemin, 'rb') as f:
        # ??? mode binaire ?
        for bloc in iter(
            lambda: f.read(4096), b''
        ):
            hasher.update(bloc)
            # ??? méthode ?

    return hasher.hexdigest()
    # ??? retourner en hex ?

# B2


def fichiers_identiques(chemin1, chemin2):
    """Vérifie si deux fichiers
    sont identiques"""
    hash1 = calculer_hash_fichier(chemin1)
    # ??? fonction précédente ?
    hash2 = calculer_hash_fichier(
        chemin2
    )

    if hash1 == hash2:
        # ??? comparer hash1 et hash2 ?
        return True
    return False


# C1


def creer_manifeste(dossier_source, fichiers_liste):
    manifeste = {
        # ??? ISO format ?
        "timestamp": str(datetime.now().isoformat()),
        # ??? len(fichiers_liste) ?
        "total_fichiers": len(fichiers_liste),
        "fichiers": []
    }
    total_octets = 0
    for fichier in fichiers_liste:
        chemin_complet = f"{dossier_source}/{fichier}"
        hash_val = calculer_hash_fichier(
            chemin_complet)        # ??? fonction B1 ?
        taille = os.path.getsize(chemin_complet)      # ??? os.path.getsize ?
        manifeste["fichiers"].append({
            "chemin": fichier, "hash": hash_val, "taille": taille
        })
        total_octets += taille
    manifeste["total_octets"] = total_octets
    with open("backup.manifest", "w") as f:
        json.dump(manifeste, f, indent=2)         # ??? json.dump ?

# C2


def verifier_manifeste(dossier, manifeste_path):
    with open(manifeste_path, 'r') as f:
        manifeste = json.load(f)
    resultats = []
    for fichier_info in manifeste["fichiers"]:
        chemin = f"{dossier}/{fichier_info['chemin']}"
        hash_calcule = calculer_hash_fichier(
            chemin)             # ??? fonction B1 ?
        hash_attendu = fichier_info['hash']
        # ??? comparer les deux hash ?
        est_valide = hash_calcule == hash_attendu
        resultats.append({"fichier": fichier_info['chemin'],
                          "valide": est_valide})
    return resultats


for item in verifier_manifeste('/data', 'backup.manifest'):
    statut = "✓ OK" if item['valide'] else "✗ CORROMPU"
    print(f"{item['fichier']}: {statut}")
