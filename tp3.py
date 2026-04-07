import os
import zipfile


def creer_archive_simple(nom_archive, fichiers_liste):
    """Crée une archive ZIP"""
    with zipfile.ZipFile(nom_archive, 'w',
                         zipfile.ZIP_DEFLATED) as zf:
        # ??? classe zipfile / mode écriture ?
        for fichier in fichiers_liste:
            zf.write(fichier)  # ??? méthode pour ajouter ?


def lister_archive(nom_archive):
    """Affiche la liste des fichiers"""
    with zipfile.ZipFile(nom_archive, 'r') as zf:
        # ??? mode lecture ?
        zf.printdir()  # ??? objet ?


def archiver_dossier(dossier_source, nom_archive, exclusions=None):
    """Archive un dossier complet"""
    if exclusions is None:
        exclusions = ['.pyc', '__pycache__']

    with zipfile.ZipFile(nom_archive, 'w',
                         zipfile.ZIP_DEFLATED) as zf:
        for racine, dossiers, fichiers \
                in os.walk(dossier_source):
            # ??? fonction pour parcourir dossier ?

            for fichier in fichiers:
                if any(excl in fichier
                       for excl in exclusions):
                    # ??? vérifier si exclusion ?
                    continue

                chemin_complet = os.path.join(
                    racine, fichier)
                # ??? construire chemin ?

                arcname = os.path.relpath(
                    chemin_complet, dossier_source)
                # ??? chemin relatif ?

                zf.write(chemin_complet,
                         arcname=arcname)
                # ??? méthode ?


def extraire_archive_sécurisée(nom_archive,
                               dossier_dest):
    with zipfile.ZipFile(nom_archive, 'r') as zf:
        if zf.testzip() is not None:
            # ??? testzip() retourne None si OK ?
            print("ERREUR: Archive corrompue!")
            return False

        zf.extractall(dossier_dest)
        # ??? méthode extraction complète ?

        print(f"Extraction: "
              f"{len(zf.namelist())} fichiers")
        return True
