# TP 1 — Bases Python & Chiffrement AES-256
# BTS SIO/SISR — Scripting & Sauvegarde
#
# Objectifs :
#   - Lire et écrire des fichiers en mode binaire
#   - Comprendre et utiliser AES-256 via Fernet
#   - Chiffrer et déchiffrer des messages et fichiers

from cryptography.fernet import Fernet
import os


# ═══════════════════════════════════════════════════════════════
# PARTIE A — Lecture et Écriture de Fichiers Binaires
# ═══════════════════════════════════════════════════════════════

def lire_fichier_binaire(chemin):
    """
    Lit un fichier en mode binaire (rb).
    Le mode 'rb' est obligatoire pour tout fichier impliqué
    dans des opérations cryptographiques.
    """
    with open(chemin, 'rb') as f:
        contenu = f.read()
    return contenu


def obtenir_taille_fichier(chemin):
    """
    Retourne la taille d'un fichier en octets.
    os.path.getsize() est plus efficace que de lire tout le fichier.
    """
    return os.path.getsize(chemin)


# ═══════════════════════════════════════════════════════════════
# PARTIE B — Chiffrement et Déchiffrement avec Fernet (AES-256)
# ═══════════════════════════════════════════════════════════════
#
# Fernet = AES-128-CBC + HMAC-SHA256
# Il gère automatiquement : la clé, l'IV, le padding et la signature.
# La clé doit être générée UNE seule fois et stockée en lieu sûr.

def chiffrer_message(message, cle):
    """
    Chiffre une chaîne de caractères avec Fernet.
    La chaîne doit être convertie en bytes avant chiffrement.

    Args:
        message (str) : le texte à chiffrer
        cle (bytes)   : clé Fernet (générée avec Fernet.generate_key())

    Returns:
        bytes : le message chiffré (token Fernet)
    """
    chiffre = Fernet(cle)                        # Créer l'objet Fernet
    message_bytes = message.encode('utf-8')      # str → bytes (obligatoire)
    ciphertext = chiffre.encrypt(message_bytes)  # Chiffrer
    return ciphertext


def dechiffrer_message(ciphertext, cle):
    """
    Déchiffre un token Fernet vers une chaîne de caractères.
    Lève InvalidToken si la clé est incorrecte ou le token altéré.

    Args:
        ciphertext (bytes) : le token Fernet chiffré
        cle (bytes)        : la même clé utilisée pour chiffrer

    Returns:
        str : le message déchiffré
    """
    chiffre = Fernet(cle)
    plaintext = chiffre.decrypt(ciphertext)  # Déchiffrer → bytes
    return plaintext.decode('utf-8')         # bytes → str


def chiffrer_fichier(chemin_entree, chemin_sortie, cle):
    """
    Lit un fichier, le chiffre avec Fernet et sauvegarde le résultat.
    Contrairement à chiffrer_message(), le contenu est déjà en bytes
    (mode 'rb'), donc on n'appelle PAS .encode().

    Args:
        chemin_entree (str) : chemin du fichier source
        chemin_sortie (str) : chemin du fichier chiffré à créer
        cle (bytes)         : clé Fernet
    """
    # Étape 1 : Lire le fichier source en binaire
    contenu = lire_fichier_binaire(chemin_entree)

    # Étape 2 : Chiffrer (contenu est déjà des bytes, pas besoin de .encode())
    chiffre = Fernet(cle)
    ciphertext = chiffre.encrypt(contenu)

    # Étape 3 : Écrire le fichier chiffré en mode binaire
    with open(chemin_sortie, 'wb') as f:
        f.write(ciphertext)


def dechiffrer_fichier(chemin_entree, chemin_sortie, cle):
    """
    Déchiffre un fichier chiffré par Fernet et sauvegarde le résultat.

    Args:
        chemin_entree (str) : chemin du fichier chiffré (.enc)
        chemin_sortie (str) : chemin du fichier restauré
        cle (bytes)         : clé Fernet
    """
    # Lire le fichier chiffré
    ciphertext = lire_fichier_binaire(chemin_entree)

    # Déchiffrer
    chiffre = Fernet(cle)
    plaintext = chiffre.decrypt(ciphertext)

    # Écrire le fichier déchiffré
    with open(chemin_sortie, 'wb') as f:
        f.write(plaintext)


# ═══════════════════════════════════════════════════════════════
# PARTIE C — Tests et Validation
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 55)
    print("TP 1 — Chiffrement AES-256 avec Fernet")
    print("=" * 55)

    # --- Génération de la clé ---
    # IMPORTANT : en production, stocker cette clé en lieu sûr !
    # Ne jamais la coder en dur dans le source.
    cle = Fernet.generate_key()
    print(f"\n[1] Clé générée : {cle[:20]}...  ({len(cle)} octets)")

    # --- Test chiffrement de message ---
    print("\n[2] Test chiffrement de message")
    message_original = "Données sensibles — BTS SIO"
    chiffre_msg = chiffrer_message(message_original, cle)
    dechiffre_msg = dechiffrer_message(chiffre_msg, cle)
    assert dechiffre_msg == message_original, "ERREUR : déchiffrement incorrect !"
    print(f"    Original  : {message_original}")
    print(f"    Chiffré   : {chiffre_msg[:30]}...")
    print(f"    Déchiffré : {dechiffre_msg}")
    print("    ✓ Chiffrement message OK")

    # --- Test chiffrement de fichier ---
    print("\n[3] Test chiffrement de fichier")

    # Créer un fichier de test
    with open('test.txt', 'w', encoding='utf-8') as f:
        f.write('Données sensibles pour sauvegarde\n' * 10)

    # Chiffrer
    chiffrer_fichier('test.txt', 'test.txt.enc', cle)

    # Comparer les tailles
    taille_orig = obtenir_taille_fichier('test.txt')
    taille_enc  = obtenir_taille_fichier('test.txt.enc')
    print(f"    Taille original : {taille_orig} octets")
    print(f"    Taille chiffré  : {taille_enc} octets")
    print(f"    Overhead        : +{taille_enc - taille_orig} octets (IV + HMAC)")

    # Déchiffrer et vérifier
    dechiffrer_fichier('test.txt.enc', 'test_restaure.txt', cle)
    contenu_orig = lire_fichier_binaire('test.txt')
    contenu_rest = lire_fichier_binaire('test_restaure.txt')
    assert contenu_orig == contenu_rest, "ERREUR : fichier restauré différent !"
    print("    ✓ Chiffrement fichier OK")

    # Nettoyage des fichiers temporaires
    for f in ['test.txt', 'test.txt.enc', 'test_restaure.txt']:
        if os.path.exists(f):
            os.remove(f)

    print("\n" + "=" * 55)
    print("✓ TP 1 COMPLET — Tous les tests passent")
    print("=" * 55)
