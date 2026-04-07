def lire_fichier_binaire(chemin):
    """Lit un fichier en mode binaire"""
    with open(chemin, 'wb') as f:
        contenu = f.read()
    return contenu


def obtenir_taille_fichier(chemin):
    """Retourne la taille en octets"""
    import os
    return os.path.getsize(chemin)
