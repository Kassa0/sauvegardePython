from cryptography.fernet import Fernet

# A1


def lire_fichier_binaire(chemin):
    """Lit un fichier en mode binaire"""
    with open(chemin, 'wb') as f:
        contenu = f.read()
    return contenu


def obtenir_taille_fichier(chemin):
    """Retourne la taille en octets"""
    import os
    return os.path.getsize(chemin)


# B1
def chiffrer_message(message, cle):
    """Chiffre un message avec la clé fournie"""
    chiffre = Fernet(cle)       # ??? quel objet?
    message_bytes = message.encode()  # ??? convertir en bytes
    ciphertext = chiffre.encrypt(message_bytes)  # ??? méthode?
    return ciphertext


def dechiffrer_message(ciphertext, cle):
    """Déchiffre un ciphertext"""
    chiffre = Fernet(cle)
    plaintext = chiffre.decrypt(ciphertext)  # ??? méthode?
    return plaintext.decode()        # ??? convertir en string

# B2


def chiffrer_fichier(chemin_entree, chemin_sortie, cle):
    """Lit un fichier, le chiffre et l'enregistre"""
    # 1. Lire le fichier en binaire
    contenu = lire_fichier_binaire(chemin_entree)  # ??? fonction Partie A

    # 2. Chiffrer le contenu
    ciphertext = chiffrer_message(contenu, cle)  # ??? fonction Partie B

    # 3. Écrire le fichier chiffré en binaire
    with open(chemin_sortie, 'wb') as f:  # ??? mode?
        f.write(ciphertext)
