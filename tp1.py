from cryptography.fernet import Fernet

# A1


def lire_fichier_binaire(chemin):
    """Lit un fichier en mode binaire"""
    with open(chemin, 'rb') as f:
        contenu = f.read()
    return contenu


def obtenir_taille_fichier(chemin):
    """Retourne la taille en octets"""
    import os
    return os.path.getsize(chemin)


# B1
def chiffrer_message(message, cle):
    """Chiffre un message avec la cle fournie"""
    chiffre = Fernet(cle)       # ??? quel objet?
    # message_bytes = message.encode()  # ??? convertir en bytes
    ciphertext = chiffre.encrypt(message)  # ??? methode?
    return ciphertext


def dechiffrer_message(ciphertext, cle):
    """Dechiffre un ciphertext"""
    chiffre = Fernet(cle)
    plaintext = chiffre.decrypt(ciphertext)  # ??? methode?
    return plaintext.decode('utf-8')        # ??? convertir en string

# B2


def chiffrer_fichier(chemin_entree, chemin_sortie, cle):
    """Lit un fichier, le chiffre et l'enregistre"""
    # 1. Lire le fichier en binaire
    contenu = lire_fichier_binaire(chemin_entree)  # ??? fonction Partie A

    # 2. Chiffrer le contenu
    ciphertext = chiffrer_message(contenu, cle)  # ??? fonction Partie B

    # 3. ecrire le fichier chiffre en binaire
    with open(chemin_sortie, 'wb') as f:  # ??? mode?
        f.write(ciphertext)


print("--- DEBUT DE LA VALIDATION ---")

# 01. Creer test.txt
contenu_original = "Message secret de test."
with open('test.txt', 'w', encoding='utf-8') as f:
    f.write(contenu_original)
print("[OK] etape 01 : Fichier 'test.txt' cree.")

# 02. Generer la Cle
cle = Fernet.generate_key()
print(f"[OK] etape 02 : Cle generee : {cle.decode()}")

# 03. Chiffrer le Fichier
chiffrer_fichier('test.txt', 'test.enc', cle)
print("[OK] etape 03 : Fichier 'test.enc' genere (contenu illisible).")

# 04. Dechiffrer et Comparer
dechiffrer_message('test.enc', cle)
with open('test_final.txt', 'r', encoding='utf-8') as f:
    contenu_recupere = f.read()

print(f"Contenu recupere : '{contenu_recupere}'")

# Verification finale
assert contenu_original == contenu_recupere
print("[OK] etape 04 : Le contenu est IDENTIQUE à l'original.")

# 05. Message de succès pour la capture d'ecran
print("\n" + "="*40)
print("  VALIDATION ReUSSIE AVEC SUCCÈS !  ")
print("="*40)
