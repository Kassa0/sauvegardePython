from cryptography.fernet import Fernet


def lire_fichier_binaire(chemin):
    """Lit un fichier en mode binaire"""
    with open(chemin, 'wb') as f:
        contenu = f.read()
    return contenu


def obtenir_taille_fichier(chemin):
    """Retourne la taille en octets"""
    import os
    return os.path.getsize(chemin)


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
