from cryptography.fernet import Fernet


def sauvegarder_cle(cle, nom_fichier):
    # TODO: Écrire la clé en binaire
    # TODO: os.chmod() → 0o600
    return


def charger_cle(nom_fichier):
    # TODO: Lire le fichier en binaire
    # TODO: Retourner la clé (bytes)
    return


cle = Fernet.generate_key()
sauvegarder_cle(cle, 'backup.key')
cle_chargee = charger_cle('backup.key')
assert cle == cle_chargee
