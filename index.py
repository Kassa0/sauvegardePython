from cryptography.fernet import Fernet
import os


def sauvegarder_cle(cle, nom_fichier):
    # On ouvre en 'wb' (Write Binary) car la clé est un objet bytes
    with open(nom_fichier, 'wb') as fichier_cle:
        fichier_cle.write(cle)

    # On change les permissions : 0o600 = seul le propriétaire peut lire/écrire
    os.chmod(nom_fichier, 0o600)


def charger_cle(nom_fichier):
    # On ouvre en 'rb' (Read Binary)
    with open(nom_fichier, 'rb') as fichier_cle:
        # On lit et on retourne directement le contenu (bytes)
        return fichier_cle.read()


cle = Fernet.generate_key()
sauvegarder_cle(cle, 'backup.key')
cle_chargee = charger_cle('backup.key')
assert cle == cle_chargee
