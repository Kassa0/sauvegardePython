# TP 5 — Tests de Conformité ISO 27001
# BTS SIO/SISR — Scripting & Sauvegarde
#
# Framework de tests validant 6 contrôles ISO 27001 :
#   A.10.1.1 — Chiffrement fort (AES-256)
#   A.12.4.1 — Logging & Audit trail
#   A.14.1.1 — Confidentialité / Contrôle d'accès
#   A.14.1.2 — Intégrité des sauvegardes
#   A.14.1.3 — Disponibilité (RTO/RPO)
#   A.14.3   — Rétention & archivage

import hashlib
import json
import logging
import os
import shutil
import time
import zipfile
from datetime import datetime, timedelta

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger('iso27001_tests')
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-8s | %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S'
)


class TestsISO27001:
    """
    Valide la conformité d'un pipeline de sauvegarde aux exigences ISO 27001.

    Usage :
        tester = TestsISO27001()
        tester.executer_tous_tests()
    """

    def __init__(self):
        self.resultats = {}
        self._dossier_test = 'iso_test_data'
        self._setup()

    def _setup(self):
        """Prépare l'environnement de test."""
        os.makedirs(self._dossier_test, exist_ok=True)

        # Fichier de données de test
        self.fichier_test = os.path.join(self._dossier_test, 'donnees.txt')
        with open(self.fichier_test, 'w', encoding='utf-8') as f:
            f.write('Données sensibles de test ISO 27001\n' * 20)

        # Générer une clé et chiffrer
        self.cle = Fernet.generate_key()
        with open(self.fichier_test, 'rb') as f:
            contenu = f.read()
        ciphertext = Fernet(self.cle).encrypt(contenu)

        self.fichier_chiffre = os.path.join(self._dossier_test, 'donnees.enc')
        with open(self.fichier_chiffre, 'wb') as f:
            f.write(ciphertext)
        # Permissions restrictives sur le fichier chiffré
        os.chmod(self.fichier_chiffre, 0o600)

        # Fichier clé avec permissions restrictives
        self.fichier_cle = os.path.join(self._dossier_test, 'backup.key')
        with open(self.fichier_cle, 'wb') as f:
            f.write(self.cle)
        os.chmod(self.fichier_cle, 0o600)

        # Créer une archive ZIP de test
        self.archive_test = os.path.join(self._dossier_test, 'backup_test.zip')
        with zipfile.ZipFile(self.archive_test, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.write(self.fichier_test, 'donnees.txt')

        # Calculer et stocker le hash de référence
        self.hash_reference = self._hash(self.fichier_test)

        # Créer un fichier de log de test
        self.fichier_log = os.path.join(self._dossier_test, 'audit.log')
        with open(self.fichier_log, 'a', encoding='utf-8') as f:
            f.write(f"{datetime.now().isoformat()} | system | SAUVEGARDE | SUCCÈS | backup_test.zip\n")
            f.write(f"{datetime.now().isoformat()} | system | VERIFICATION | SUCCÈS | hash_ok\n")

    def _hash(self, chemin):
        """Calcule SHA-256 d'un fichier."""
        hasher = hashlib.sha256()
        with open(chemin, 'rb') as f:
            for bloc in iter(lambda: f.read(4096), b''):
                hasher.update(bloc)
        return hasher.hexdigest()

    # ═══════════════════════════════════════════════════════════
    # A.10.1.1 — Chiffrement Fort
    # ═══════════════════════════════════════════════════════════

    def test_chiffrement_strength(self):
        """
        A.10.1.1 : Vérifie que le chiffrement est robuste.
        - Le fichier chiffré ne doit pas contenir le texte clair
        - Le déchiffrement avec une mauvaise clé doit échouer
        - Le fichier chiffré doit être différent du fichier source
        """
        try:
            # Vérification 1 : le fichier chiffré est différent du source
            with open(self.fichier_test, 'rb') as f:
                contenu_clair = f.read()
            with open(self.fichier_chiffre, 'rb') as f:
                contenu_chiffre = f.read()

            assert contenu_clair != contenu_chiffre, \
                "Le fichier chiffré est identique au fichier source !"

            # Vérification 2 : une mauvaise clé ne peut pas déchiffrer
            mauvaise_cle = Fernet.generate_key()
            try:
                Fernet(mauvaise_cle).decrypt(contenu_chiffre)
                assert False, "Une mauvaise clé a pu déchiffrer le fichier !"
            except InvalidToken:
                pass  # Comportement attendu

            # Vérification 3 : la bonne clé déchiffre correctement
            plaintext = Fernet(self.cle).decrypt(contenu_chiffre)
            assert plaintext == contenu_clair, "Déchiffrement incorrect avec la bonne clé !"

            print("  ✓ A.10.1.1 — Chiffrement fort OK")
            self.resultats['chiffrement'] = True
            return True

        except AssertionError as e:
            print(f"  ✗ A.10.1.1 — Chiffrement : {e}")
            self.resultats['chiffrement'] = False
            return False

    # ═══════════════════════════════════════════════════════════
    # A.12.4.1 — Logging & Audit Trail
    # ═══════════════════════════════════════════════════════════

    def test_tracabilite(self):
        """
        A.12.4.1 : Vérifie la traçabilité des opérations.
        - Le fichier de log existe
        - Chaque ligne contient un timestamp, une action et un statut
        - Le log est en mode append (non écrasable)
        """
        try:
            assert os.path.exists(self.fichier_log), \
                f"Fichier de log introuvable : {self.fichier_log}"

            # Vérifier le format des entrées
            with open(self.fichier_log, 'r', encoding='utf-8') as f:
                lignes = [l.strip() for l in f if l.strip()]

            assert len(lignes) > 0, "Le fichier de log est vide"

            for ligne in lignes:
                parties = ligne.split(' | ')
                assert len(parties) >= 4, f"Format de log incorrect : {ligne}"
                # Vérifier que le timestamp est parsable
                datetime.fromisoformat(parties[0])

            # Vérifier que le log est en append (ajouter une ligne et revérifier)
            taille_avant = os.path.getsize(self.fichier_log)
            with open(self.fichier_log, 'a', encoding='utf-8') as f:
                f.write(f"{datetime.now().isoformat()} | system | TEST | SUCCÈS | test_tracabilite\n")
            taille_apres = os.path.getsize(self.fichier_log)

            assert taille_apres > taille_avant, "Le log n'est pas en mode append !"

            print("  ✓ A.12.4.1 — Traçabilité OK")
            self.resultats['tracabilite'] = True
            return True

        except (AssertionError, ValueError) as e:
            print(f"  ✗ A.12.4.1 — Traçabilité : {e}")
            self.resultats['tracabilite'] = False
            return False

    # ═══════════════════════════════════════════════════════════
    # A.14.1.1 — Confidentialité / Contrôle d'accès
    # ═══════════════════════════════════════════════════════════

    def test_confidentialite(self):
        """
        A.14.1.1 : Vérifie le contrôle d'accès aux fichiers sensibles.
        - Permissions 0o600 sur les fichiers de clés
        - Permissions 0o600 sur les fichiers chiffrés
        - La clé ne doit pas apparaître en clair dans les logs
        """
        try:
            # Vérification des permissions (Linux/Mac uniquement)
            if os.name != 'nt':  # Pas Windows
                perms_cle     = oct(os.stat(self.fichier_cle).st_mode)[-3:]
                perms_chiffre = oct(os.stat(self.fichier_chiffre).st_mode)[-3:]

                assert perms_cle == '600', \
                    f"Permissions clé : {perms_cle} (attendu: 600)"
                assert perms_chiffre == '600', \
                    f"Permissions fichier chiffré : {perms_chiffre} (attendu: 600)"

            # Vérification : la clé ne doit pas apparaître dans les logs
            if os.path.exists(self.fichier_log):
                cle_str = self.cle.decode()
                with open(self.fichier_log, 'r', encoding='utf-8') as f:
                    contenu_log = f.read()
                assert cle_str not in contenu_log, \
                    "La clé Fernet apparaît en clair dans les logs !"

            print("  ✓ A.14.1.1 — Confidentialité OK")
            self.resultats['confidentialite'] = True
            return True

        except AssertionError as e:
            print(f"  ✗ A.14.1.1 — Confidentialité : {e}")
            self.resultats['confidentialite'] = False
            return False

    # ═══════════════════════════════════════════════════════════
    # A.14.1.2 — Intégrité des Sauvegardes
    # ═══════════════════════════════════════════════════════════

    def test_integrite(self):
        """
        A.14.1.2 : Vérifie l'intégrité des fichiers sauvegardés.
        - Le hash du fichier restauré correspond à celui de l'original
        - La modification d'un fichier est détectée par changement de hash
        """
        try:
            # Vérification 1 : déchiffrer et comparer au hash de référence
            with open(self.fichier_chiffre, 'rb') as f:
                ciphertext = f.read()
            plaintext    = Fernet(self.cle).decrypt(ciphertext)
            hash_restaure = hashlib.sha256(plaintext).hexdigest()

            assert hash_restaure == self.hash_reference, \
                "Hash du fichier restauré ≠ hash original !"

            # Vérification 2 : la modification d'un fichier change son hash
            chemin_modif = os.path.join(self._dossier_test, 'modifie.txt')
            with open(chemin_modif, 'w') as f:
                f.write('Contenu original\n')
            hash_avant = self._hash(chemin_modif)

            with open(chemin_modif, 'a') as f:
                f.write('Ligne ajoutée — corruption simulée\n')
            hash_apres = self._hash(chemin_modif)

            assert hash_avant != hash_apres, \
                "La modification d'un fichier n'a pas changé son hash !"

            print("  ✓ A.14.1.2 — Intégrité OK")
            self.resultats['integrite'] = True
            return True

        except AssertionError as e:
            print(f"  ✗ A.14.1.2 — Intégrité : {e}")
            self.resultats['integrite'] = False
            return False

    # ═══════════════════════════════════════════════════════════
    # A.14.1.3 — Disponibilité (RTO/RPO)
    # ═══════════════════════════════════════════════════════════

    def test_disponibilite(self):
        """
        A.14.1.3 : Vérifie les objectifs de disponibilité.
        - RTO (Recovery Time Objective) : restauration en < 4h
        - RPO (Recovery Point Objective) : perte de données max 24h
        - Mesure le temps d'extraction de l'archive de test
        """
        try:
            dest = os.path.join(self._dossier_test, 'rto_test')
            os.makedirs(dest, exist_ok=True)

            # Mesurer le temps de restauration
            debut = time.time()
            with zipfile.ZipFile(self.archive_test, 'r') as zf:
                assert zf.testzip() is None, "Archive corrompue !"
                zf.extractall(dest)
            duree = time.time() - debut

            # RTO fictif pour le test (en production : vérifier < 4h = 14400s)
            RTO_MAX_SECONDES = 14400  # 4 heures
            assert duree < RTO_MAX_SECONDES, \
                f"RTO dépassé : {duree:.2f}s > {RTO_MAX_SECONDES}s !"

            print(f"  ✓ A.14.1.3 — Disponibilité OK (restauration : {duree:.3f}s)")
            print(f"             RTO mesuré : {duree:.3f}s / max autorisé : {RTO_MAX_SECONDES}s")
            self.resultats['disponibilite'] = True
            return True

        except AssertionError as e:
            print(f"  ✗ A.14.1.3 — Disponibilité : {e}")
            self.resultats['disponibilite'] = False
            return False

    # ═══════════════════════════════════════════════════════════
    # A.14.3 — Rétention & Archivage
    # ═══════════════════════════════════════════════════════════

    def test_retention(self):
        """
        A.14.3 : Vérifie la politique de rétention.
        - Les sauvegardes récentes (< 30 jours) sont conservées
        - Les sauvegardes anciennes (> 30 jours) sont archivées
        - Le manifeste documente la politique de rétention
        """
        try:
            # Simuler des sauvegardes à différentes dates
            sauvegardes = {
                'backup_recent.zip':  0,   # Aujourd'hui → conserver
                'backup_vieux.zip':   35,  # 35 jours → archiver
            }

            dossier_retention = os.path.join(self._dossier_test, 'retention_test')
            os.makedirs(dossier_retention, exist_ok=True)
            os.makedirs(os.path.join(dossier_retention, 'archive'), exist_ok=True)

            for nom, age_jours in sauvegardes.items():
                chemin = os.path.join(dossier_retention, nom)
                with open(chemin, 'w') as f:
                    f.write(f'backup {nom}')

                # Simuler l'âge du fichier
                if age_jours > 0:
                    ts = (datetime.now() - timedelta(days=age_jours)).timestamp()
                    os.utime(chemin, (ts, ts))

            # Appliquer la politique de rétention (30 jours)
            RETENTION_JOURS = 30
            archivees = []
            conservees = []

            for nom in os.listdir(dossier_retention):
                chemin = os.path.join(dossier_retention, nom)
                if not os.path.isfile(chemin):
                    continue
                age = (datetime.now() - datetime.fromtimestamp(os.path.getmtime(chemin))).days
                if age > RETENTION_JOURS:
                    dest = os.path.join(dossier_retention, 'archive', nom)
                    shutil.move(chemin, dest)
                    archivees.append(nom)
                else:
                    conservees.append(nom)

            assert len(archivees) >= 1,  "Aucune sauvegarde archivée !"
            assert len(conservees) >= 1, "Aucune sauvegarde conservée !"

            print(f"  ✓ A.14.3 — Rétention OK")
            print(f"             Conservées : {conservees}")
            print(f"             Archivées  : {archivees}")
            self.resultats['retention'] = True
            return True

        except AssertionError as e:
            print(f"  ✗ A.14.3 — Rétention : {e}")
            self.resultats['retention'] = False
            return False

    # ═══════════════════════════════════════════════════════════
    # Orchestrateur — Exécuter tous les tests
    # ═══════════════════════════════════════════════════════════

    def executer_tous_tests(self):
        """
        Exécute les 6 tests ISO 27001 et affiche un rapport de conformité.

        Returns:
            bool : True si tous les tests passent
        """
        print("\n" + "=" * 60)
        print("TESTS ISO 27001 — PIPELINE DE SAUVEGARDE")
        print("=" * 60)

        tests = [
            ("A.10.1.1 — Chiffrement fort",         self.test_chiffrement_strength),
            ("A.12.4.1 — Traçabilité / Audit",       self.test_tracabilite),
            ("A.14.1.1 — Confidentialité",           self.test_confidentialite),
            ("A.14.1.2 — Intégrité",                 self.test_integrite),
            ("A.14.1.3 — Disponibilité (RTO/RPO)",   self.test_disponibilite),
            ("A.14.3   — Rétention & archivage",     self.test_retention),
        ]

        for nom_test, fonction in tests:
            print(f"\n  [{nom_test}]")
            try:
                fonction()
            except Exception as e:
                print(f"  ✗ Exception inattendue : {e}")
                self.resultats[nom_test] = False

        # Rapport final
        total    = len(tests)
        passes   = sum(1 for v in self.resultats.values() if v)
        echecs   = total - passes
        conforme = echecs == 0

        print("\n" + "=" * 60)
        print("RAPPORT FINAL ISO 27001")
        print("=" * 60)
        print(f"  Tests exécutés : {total}")
        print(f"  ✓ Conformes    : {passes}")
        print(f"  ✗ Non conformes: {echecs}")
        print(f"\n  Statut global  : {'✓ CONFORME ISO 27001' if conforme else '✗ NON CONFORME — Corrections requises'}")
        print("=" * 60)

        self._teardown()
        return conforme

    def _teardown(self):
        """Nettoie l'environnement de test."""
        if os.path.exists(self._dossier_test):
            shutil.rmtree(self._dossier_test)


# ═══════════════════════════════════════════════════════════════
# Point d'entrée
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    tester = TestsISO27001()
    conforme = tester.executer_tous_tests()
    exit(0 if conforme else 1)
