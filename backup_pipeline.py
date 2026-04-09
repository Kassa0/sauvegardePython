# TP 4 — Pipeline de Sauvegarde Complet
# BTS SIO/SISR — Scripting & Sauvegarde
#
# Ce script assemble les briques des TP 1, 2 et 3 en un pipeline
# de sauvegarde sécurisée conforme ISO 27001.
#
# Architecture :
#   BackupManager  → archiver() → generer_manifeste() → verifier_integrite() → chiffrer()
#   RestoreManager → verifier_manifeste() → dechiffrer() → extraire() → valider_restauration()

import hashlib
import json
import logging
import os
import shutil
import zipfile
from datetime import datetime

from cryptography.fernet import Fernet, InvalidToken


# ═══════════════════════════════════════════════════════════════
# CONFIGURATION DU LOGGING — Traçabilité ISO 27001
# ═══════════════════════════════════════════════════════════════
#
# Double sortie : fichier backup.log + console simultanément.
# Format horodaté ISO 8601 pour conformité ISO 27001 A.12.4.1.

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-8s | %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S',
    handlers=[
        logging.FileHandler('backup.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('backup')


# ═══════════════════════════════════════════════════════════════
# FONCTIONS UTILITAIRES (réutilisées depuis TP1, TP2, TP3)
# ═══════════════════════════════════════════════════════════════

def calculer_hash_fichier(chemin):
    """Calcule SHA-256 d'un fichier par blocs de 4 Ko."""
    hasher = hashlib.sha256()
    with open(chemin, 'rb') as f:
        for bloc in iter(lambda: f.read(4096), b''):
            hasher.update(bloc)
    return hasher.hexdigest()


EXCLUSIONS_DEFAUT = ['.pyc', '__pycache__', '.git', 'node_modules', '.DS_Store', 'backup.log']


# ═══════════════════════════════════════════════════════════════
# CLASSE BACKUPMANAGER — Orchestration de la sauvegarde
# ═══════════════════════════════════════════════════════════════

class BackupManager:
    """
    Orchestre le pipeline de sauvegarde en 4 étapes séquentielles :
      1. archiver()           → crée l'archive ZIP
      2. generer_manifeste()  → calcule les hashes et génère le JSON
      3. verifier_integrite() → valide le hash de l'archive
      4. chiffrer()           → chiffre l'archive avec Fernet

    Chaque étape retourne un booléen. En cas d'échec,
    executer_sauvegarde() s'arrête et logue l'erreur.
    """

    def __init__(self, dossier_source, nom_backup, cle=None, exclusions=None):
        """
        Args:
            dossier_source (str) : dossier à sauvegarder
            nom_backup (str)     : préfixe des fichiers générés
            cle (bytes)          : clé Fernet (générée automatiquement si None)
            exclusions (list)    : fichiers/dossiers à exclure de l'archive
        """
        self.dossier_source = dossier_source
        self.exclusions     = exclusions or EXCLUSIONS_DEFAUT

        # Générer la clé si non fournie
        self.cle = cle if cle else Fernet.generate_key()

        # Noms des fichiers générés (horodatés pour éviter les collisions)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.archive_name   = f"{nom_backup}_{timestamp}.zip"
        self.manifeste_name = f"{self.archive_name}.manifest"
        self.chiffre_name   = f"{self.archive_name}.enc"

        self.manifeste = {}  # Rempli progressivement au fil du pipeline

    # ── Étape 1 : Archivage ZIP ───────────────────────────────

    def archiver(self):
        """
        Crée l'archive ZIP du dossier source.
        Utilise os.walk() pour parcourir récursivement.

        Returns:
            bool : True si succès
        """
        try:
            logger.info(f"[ARCHIVE] Début archivage : {self.dossier_source}")
            nb_fichiers   = 0
            octets_source = 0

            with zipfile.ZipFile(self.archive_name, 'w', zipfile.ZIP_DEFLATED) as zf:
                for racine, dossiers, fichiers in os.walk(self.dossier_source):
                    dossiers[:] = [d for d in dossiers if d not in self.exclusions]

                    for fichier in fichiers:
                        if any(excl in fichier for excl in self.exclusions):
                            continue

                        chemin_complet = os.path.join(racine, fichier)
                        arcname        = os.path.relpath(chemin_complet, self.dossier_source)
                        zf.write(chemin_complet, arcname=arcname)

                        octets_source += os.path.getsize(chemin_complet)
                        nb_fichiers   += 1

            taille_archive = os.path.getsize(self.archive_name)
            logger.info(f"[ARCHIVE] {nb_fichiers} fichiers → {taille_archive:,} octets")

            # Stocker les infos pour le manifeste
            self.manifeste['nb_fichiers']    = nb_fichiers
            self.manifeste['octets_source']  = octets_source
            self.manifeste['taille_archive'] = taille_archive
            return True

        except Exception as e:
            logger.error(f"[ARCHIVE] ERREUR : {e}")
            return False

    # ── Étape 2 : Génération du manifeste ────────────────────

    def generer_manifeste(self):
        """
        Calcule le SHA-256 de l'archive et génère le manifeste JSON.

        Returns:
            bool : True si succès
        """
        try:
            logger.info("[MANIFESTE] Calcul du hash SHA-256...")
            hash_archive = calculer_hash_fichier(self.archive_name)

            self.manifeste.update({
                "timestamp":     datetime.now().isoformat(),
                "backup_name":   self.archive_name.replace('.zip', ''),
                "archive_file":  self.archive_name,
                "hash_archive":  hash_archive,
                "taille_bytes":  os.path.getsize(self.archive_name),
                "cle_base64":    self.cle.decode(),  # ⚠️ EN PROD : stocker dans un HSM !
                "version":       "1.0"
            })

            with open(self.manifeste_name, 'w', encoding='utf-8') as f:
                json.dump(self.manifeste, f, indent=2)

            logger.info(f"[MANIFESTE] Généré : {self.manifeste_name}")
            return True

        except Exception as e:
            logger.error(f"[MANIFESTE] ERREUR : {e}")
            return False

    # ── Étape 3 : Vérification d'intégrité ───────────────────

    def verifier_integrite(self):
        """
        Relit le manifeste et compare le hash recalculé à celui enregistré.
        Garantit que l'archive n'a pas été altérée entre l'étape 1 et l'étape 4.

        Returns:
            bool : True si l'archive est intègre
        """
        try:
            logger.info("[INTÉGRITÉ] Vérification du hash...")
            with open(self.manifeste_name, 'r', encoding='utf-8') as f:
                manifeste = json.load(f)

            hash_attendu = manifeste['hash_archive']
            hash_calcule = calculer_hash_fichier(self.archive_name)

            if hash_calcule != hash_attendu:
                logger.error("[INTÉGRITÉ] Hash INVALIDE — archive altérée !")
                return False

            logger.info("[INTÉGRITÉ] ✓ Hash valide")
            return True

        except Exception as e:
            logger.error(f"[INTÉGRITÉ] ERREUR : {e}")
            return False

    # ── Étape 4 : Chiffrement ─────────────────────────────────

    def chiffrer(self):
        """
        Chiffre l'archive ZIP avec Fernet et met à jour le manifeste
        avec le hash du fichier chiffré.

        Returns:
            bool : True si succès
        """
        try:
            logger.info("[CHIFFRE] Chiffrement Fernet en cours...")
            with open(self.archive_name, 'rb') as f:
                contenu = f.read()

            ciphertext = Fernet(self.cle).encrypt(contenu)

            with open(self.chiffre_name, 'wb') as f:
                f.write(ciphertext)

            # Mettre à jour le manifeste avec le hash du fichier chiffré
            hash_chiffre = calculer_hash_fichier(self.chiffre_name)
            with open(self.manifeste_name, 'r', encoding='utf-8') as f:
                manifeste = json.load(f)

            manifeste['chiffre_file'] = self.chiffre_name
            manifeste['hash_chiffre'] = hash_chiffre

            with open(self.manifeste_name, 'w', encoding='utf-8') as f:
                json.dump(manifeste, f, indent=2)

            logger.info(f"[CHIFFRE] ✓ Archive chiffrée : {self.chiffre_name}")
            return True

        except Exception as e:
            logger.error(f"[CHIFFRE] ERREUR : {e}")
            return False

    # ── Orchestrateur principal ───────────────────────────────

    def executer_sauvegarde(self):
        """
        Exécute le pipeline complet en séquence.
        S'arrête immédiatement à la première erreur.

        Returns:
            bool : True si toutes les étapes ont réussi
        """
        logger.info("=" * 55)
        logger.info("DÉBUT PIPELINE DE SAUVEGARDE")
        logger.info("=" * 55)

        etapes = [
            ("Archivage ZIP",       self.archiver),
            ("Génération manifeste", self.generer_manifeste),
            ("Vérification intégrité", self.verifier_integrite),
            ("Chiffrement Fernet",   self.chiffrer),
        ]

        for nom_etape, fonction in etapes:
            logger.info(f"--- Étape : {nom_etape}")
            if not fonction():
                logger.error(f"ÉCHEC à l'étape : {nom_etape}")
                return False

        logger.info("=" * 55)
        logger.info("✓ SAUVEGARDE TERMINÉE AVEC SUCCÈS")
        logger.info(f"  Archive   : {self.archive_name}")
        logger.info(f"  Manifeste : {self.manifeste_name}")
        logger.info(f"  Chiffré   : {self.chiffre_name}")
        logger.info("=" * 55)
        return True


# ═══════════════════════════════════════════════════════════════
# CLASSE RESTOREMANAGER — Orchestration de la restauration
# ═══════════════════════════════════════════════════════════════

class RestoreManager:
    """
    Restaure une sauvegarde en 4 étapes :
      1. verifier_manifeste()    → hash du .enc comparé au manifeste
      2. dechiffrer()            → Fernet.decrypt() → archive .zip
      3. extraire()              → testzip() + extractall()
      4. valider_restauration()  → vérification post-extraction
    """

    def __init__(self, manifeste_path, cle):
        """
        Args:
            manifeste_path (str) : chemin du fichier .manifest
            cle (bytes or str)   : clé Fernet (bytes ou str base64)
        """
        self.manifeste_path = manifeste_path

        # Normaliser la clé en bytes
        self.cle = cle if isinstance(cle, bytes) else cle.encode()

        # Charger le manifeste
        with open(manifeste_path, 'r', encoding='utf-8') as f:
            self.manifeste = json.load(f)

        self.archive_restauree = None  # Rempli après déchiffrement

    # ── Étape 1 : Vérification du fichier chiffré ─────────────

    def verifier_manifeste(self):
        """
        Compare le hash SHA-256 du fichier .enc avec celui du manifeste.
        Détecte toute altération survenue après le chiffrement.

        Returns:
            bool : True si le fichier chiffré est intègre
        """
        try:
            logger.info("[RESTORE] Vérification intégrité du fichier chiffré...")
            chiffre_file = self.manifeste.get('chiffre_file')

            if not chiffre_file or not os.path.exists(chiffre_file):
                logger.error(f"[RESTORE] Fichier chiffré introuvable : {chiffre_file}")
                return False

            hash_attendu = self.manifeste.get('hash_chiffre')
            hash_calcule = calculer_hash_fichier(chiffre_file)

            if hash_calcule != hash_attendu:
                logger.error("[RESTORE] Hash INVALIDE — fichier chiffré altéré !")
                return False

            logger.info("[RESTORE] ✓ Fichier chiffré intègre")
            self.chiffre_file = chiffre_file
            return True

        except Exception as e:
            logger.error(f"[RESTORE] ERREUR vérification : {e}")
            return False

    # ── Étape 2 : Déchiffrement ────────────────────────────────

    def dechiffrer(self):
        """
        Déchiffre le fichier .enc → archive .zip temporaire.

        Returns:
            bool : True si déchiffrement réussi
        """
        try:
            logger.info("[RESTORE] Déchiffrement Fernet...")
            with open(self.chiffre_file, 'rb') as f:
                ciphertext = f.read()

            plaintext = Fernet(self.cle).decrypt(ciphertext)

            # Restaurer l'archive ZIP originale
            self.archive_restauree = self.manifeste.get('archive_file', 'restaure.zip')
            with open(self.archive_restauree, 'wb') as f:
                f.write(plaintext)

            # Vérifier le hash de l'archive déchiffrée
            hash_attendu = self.manifeste.get('hash_archive')
            hash_calcule = calculer_hash_fichier(self.archive_restauree)

            if hash_calcule != hash_attendu:
                logger.error("[RESTORE] Hash archive ZIP INVALIDE après déchiffrement !")
                return False

            logger.info("[RESTORE] ✓ Archive déchiffrée et vérifiée")
            return True

        except InvalidToken:
            logger.error("[RESTORE] ERREUR : clé incorrecte ou fichier corrompu (InvalidToken)")
            return False
        except Exception as e:
            logger.error(f"[RESTORE] ERREUR déchiffrement : {e}")
            return False

    # ── Étape 3 : Extraction ───────────────────────────────────

    def extraire(self, dossier_destination):
        """
        Extrait l'archive ZIP après validation testzip().

        Args:
            dossier_destination (str) : dossier de restauration

        Returns:
            bool : True si extraction réussie
        """
        try:
            logger.info(f"[RESTORE] Extraction vers {dossier_destination}...")
            os.makedirs(dossier_destination, exist_ok=True)

            with zipfile.ZipFile(self.archive_restauree, 'r') as zf:
                # Vérifier intégrité de l'archive
                fichier_corrompu = zf.testzip()
                if fichier_corrompu is not None:
                    logger.error(f"[RESTORE] Archive corrompue : {fichier_corrompu}")
                    return False

                # Protection Zip Slip
                dest_abs = os.path.abspath(dossier_destination)
                for membre in zf.namelist():
                    cible = os.path.abspath(os.path.join(dossier_destination, membre))
                    if not cible.startswith(dest_abs):
                        logger.error(f"[RESTORE] Zip Slip détecté : {membre}")
                        return False

                zf.extractall(dossier_destination)
                nb = len(zf.namelist())

            logger.info(f"[RESTORE] ✓ {nb} fichier(s) extrait(s)")
            self.dossier_restaure = dossier_destination
            return True

        except zipfile.BadZipFile:
            logger.error("[RESTORE] Archive ZIP invalide ou corrompue")
            return False
        except Exception as e:
            logger.error(f"[RESTORE] ERREUR extraction : {e}")
            return False

    # ── Étape 4 : Validation post-restauration ─────────────────

    def valider_restauration(self):
        """
        Vérifications finales après extraction.

        Returns:
            bool : True si la restauration est valide
        """
        try:
            logger.info("[RESTORE] Validation post-restauration...")

            # Vérifier que le dossier de destination n'est pas vide
            nb_fichiers = sum(
                len(files)
                for _, _, files in os.walk(self.dossier_restaure)
            )

            if nb_fichiers == 0:
                logger.error("[RESTORE] Dossier restauré vide !")
                return False

            logger.info(f"[RESTORE] ✓ {nb_fichiers} fichier(s) présent(s) dans la restauration")
            return True

        except Exception as e:
            logger.error(f"[RESTORE] ERREUR validation : {e}")
            return False

    # ── Orchestrateur principal ───────────────────────────────

    def executer_restauration(self, dossier_destination):
        """
        Exécute le pipeline de restauration complet.

        Args:
            dossier_destination (str) : dossier de restauration

        Returns:
            bool : True si toutes les étapes ont réussi
        """
        logger.info("=" * 55)
        logger.info("DÉBUT PIPELINE DE RESTAURATION")
        logger.info("=" * 55)

        # Les 3 premières étapes ne prennent pas de paramètre
        etapes_sans_param = [
            ("Vérification manifeste", self.verifier_manifeste),
            ("Déchiffrement",          self.dechiffrer),
        ]

        for nom_etape, fonction in etapes_sans_param:
            logger.info(f"--- Étape : {nom_etape}")
            if not fonction():
                logger.error(f"ÉCHEC : {nom_etape}")
                return False

        # Extraction avec paramètre
        logger.info("--- Étape : Extraction ZIP")
        if not self.extraire(dossier_destination):
            logger.error("ÉCHEC : Extraction")
            return False

        # Validation finale
        logger.info("--- Étape : Validation")
        if not self.valider_restauration():
            logger.error("ÉCHEC : Validation")
            return False

        logger.info("=" * 55)
        logger.info("✓ RESTAURATION TERMINÉE AVEC SUCCÈS")
        logger.info(f"  Destination : {dossier_destination}")
        logger.info("=" * 55)
        return True


# ═══════════════════════════════════════════════════════════════
# FONCTION PRINCIPALE — Test bout-en-bout
# ═══════════════════════════════════════════════════════════════

def main():
    """
    Valide le pipeline complet : sauvegarde → restauration.
    Retourne True si tout réussit (exit(0)), False sinon (exit(1)).
    Compatible CI/CD et cron jobs.
    """

    # Créer un dossier source de test
    os.makedirs('source_test/src', exist_ok=True)
    os.makedirs('source_test/docs', exist_ok=True)

    for nom, contenu in [
        ('source_test/src/app.py',      'print("Application")\n' * 15),
        ('source_test/src/config.py',   'DEBUG = True\n' * 5),
        ('source_test/docs/guide.txt',  'Guide utilisateur\n' * 20),
        ('source_test/README.md',       '# Projet test\n'),
    ]:
        with open(nom, 'w', encoding='utf-8') as f:
            f.write(contenu)

    # ── TEST 1 : SAUVEGARDE ────────────────────────────────────
    print("\n" + "=" * 55)
    print("TEST 1 : SAUVEGARDE")
    print("=" * 55)

    backup = BackupManager('source_test', 'mon_backup')

    if not backup.executer_sauvegarde():
        logger.error("Échec de la sauvegarde")
        return False

    cle = backup.cle
    print(f"\nClé générée (à stocker en sécurité) :")
    print(f"  {cle.decode()}")

    # ── TEST 2 : RESTAURATION ──────────────────────────────────
    print("\n" + "=" * 55)
    print("TEST 2 : RESTAURATION")
    print("=" * 55)

    restore = RestoreManager(backup.manifeste_name, cle)

    if not restore.executer_restauration('restauration_test'):
        logger.error("Échec de la restauration")
        return False

    print("\n✓ Pipeline complet validé !")

    # Nettoyage
    for item in ['source_test', 'restauration_test',
                 backup.archive_name, backup.manifeste_name, backup.chiffre_name]:
        if os.path.isdir(item):
            shutil.rmtree(item)
        elif os.path.exists(item):
            os.remove(item)

    return True


if __name__ == "__main__":
    exit(0 if main() else 1)
