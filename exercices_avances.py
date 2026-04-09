# TP 5 — Exercices Avancés Jour 2
# BTS SIO/SISR — Scripting & Sauvegarde
#
# Exercices avancés :
#   2.1 — Rotation de clés mensuelle (ISO 27001 A.14.3)
#   2.2 — Manifeste incrémental avec dépendances
#   2.3 — Scanner de fichiers suspects + quarantaine
#   2.4 — Restauration parallèle avec ThreadPoolExecutor
#   2.5 — Audit Trail complet (ISO 27001 A.12.4.1)

import hashlib
import json
import logging
import os
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from cryptography.fernet import Fernet

logger = logging.getLogger('tp5')
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-8s | %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S'
)


# ── Utilitaire ────────────────────────────────────────────────

def _calculer_hash(chemin):
    """SHA-256 par blocs de 4 Ko."""
    hasher = hashlib.sha256()
    with open(chemin, 'rb') as f:
        for bloc in iter(lambda: f.read(4096), b''):
            hasher.update(bloc)
    return hasher.hexdigest()


# ═══════════════════════════════════════════════════════════════
# EXERCICE 2.1 — Rotation de Clés Mensuelle
# ═══════════════════════════════════════════════════════════════
#
# ISO 27001 A.14.3 : rotation et archivage des clés de sauvegarde.
# - Nouvelle clé chaque mois → stockée dans cles/
# - Permissions 0o600 (lecture/écriture propriétaire uniquement)
# - Archivage des clés de plus de 90 jours
# - Suivi via rotation.json

def creer_cle_mensuelle(annee, mois):
    """
    Génère une clé Fernet mensuelle et l'enregistre sur disque.

    Args:
        annee (int) : année (ex: 2024)
        mois  (int) : mois (1-12)

    Returns:
        bytes : la clé Fernet générée
    """
    os.makedirs('cles', exist_ok=True)

    # Générer la clé
    cle = Fernet.generate_key()
    nom_fichier = f'cles/backup_{annee}_{mois:02d}.key'

    # Écrire la clé avec permissions restrictives
    with open(nom_fichier, 'wb') as f:
        f.write(cle)
    os.chmod(nom_fichier, 0o600)  # rw------- (propriétaire uniquement)

    # Mettre à jour rotation.json
    rotation_file = 'cles/rotation.json'
    if os.path.exists(rotation_file):
        with open(rotation_file, 'r') as f:
            rotation = json.load(f)
    else:
        rotation = {"cles_actives": [], "cles_archivees": []}

    rotation['cles_actives'].append(nom_fichier)
    rotation['derniere_rotation'] = datetime.now().isoformat()

    with open(rotation_file, 'w') as f:
        json.dump(rotation, f, indent=2)

    logger.info(f"[CLÉ] Créée : {nom_fichier}")
    return cle


def archiver_cle_ancienne(nom_cle):
    """
    Archive une clé si elle a plus de 90 jours (ISO 27001 A.14.3).

    Args:
        nom_cle (str) : nom du fichier clé (ex: 'backup_2024_01.key')
    """
    os.makedirs('cles/archive', exist_ok=True)
    chemin = f'cles/{nom_cle}'

    if not os.path.exists(chemin):
        logger.warning(f"[CLÉ] Fichier introuvable : {chemin}")
        return

    # Calculer l'âge du fichier
    mtime    = os.path.getmtime(chemin)
    age_jours = (datetime.now() - datetime.fromtimestamp(mtime)).days

    if age_jours > 90:
        chemin_archive = f'cles/archive/{nom_cle}'
        shutil.move(chemin, chemin_archive)

        # Mettre à jour rotation.json
        with open('cles/rotation.json', 'r') as f:
            rotation = json.load(f)

        if chemin in rotation['cles_actives']:
            rotation['cles_actives'].remove(chemin)
        rotation['cles_archivees'].append(chemin_archive)

        with open('cles/rotation.json', 'w') as f:
            json.dump(rotation, f, indent=2)

        logger.info(f"[CLÉ] Archivée ({age_jours}j) : {nom_cle}")
    else:
        logger.info(f"[CLÉ] Clé récente ({age_jours}j), pas d'archivage")


def charger_cle_active():
    """
    Charge la clé active la plus récente depuis rotation.json.

    Returns:
        bytes : la clé Fernet active

    Raises:
        ValueError : si aucune clé active n'est disponible
    """
    with open('cles/rotation.json', 'r') as f:
        rotation = json.load(f)

    if not rotation['cles_actives']:
        raise ValueError("Aucune clé active disponible !")

    # cles_actives[-1] = la plus récente
    chemin = rotation['cles_actives'][-1]
    with open(chemin, 'rb') as f:
        return f.read()


# ═══════════════════════════════════════════════════════════════
# EXERCICE 2.2 — Manifeste Incrémental avec Dépendances
# ═══════════════════════════════════════════════════════════════
#
# Dans un backup incrémental, chaque archive dépend de la précédente.
# Le manifeste trace ces dépendances pour garantir une restauration
# complète et vérifiable.

def generer_manifeste_incremental(archive_nom, archive_precedente=None):
    """
    Génère un manifeste pour un backup full ou incrémental.

    Args:
        archive_nom        (str)        : nom de l'archive courante
        archive_precedente (str | None) : archive parente (None = full backup)

    Returns:
        dict : le manifeste généré
    """
    hash_archive = _calculer_hash(archive_nom)

    manifeste = {
        "timestamp":    datetime.now().isoformat(),
        "archive_file": archive_nom,
        "backup_type":  "incremental" if archive_precedente else "full",
        "hash_archive": hash_archive,
        "taille_bytes": os.path.getsize(archive_nom),
        "depends_on":   archive_precedente,
        "fichiers": {
            "modifies":   [],
            "ajoutes":    [],
            "supprimes":  []
        }
    }

    manifeste_path = f"{archive_nom}.manifest"
    with open(manifeste_path, 'w', encoding='utf-8') as f:
        json.dump(manifeste, f, indent=2)

    logger.info(f"[MANIFESTE] Type={manifeste['backup_type']} → {manifeste_path}")
    return manifeste


def valider_chaine_restauration(manifeste_path, dossier_archives):
    """
    Remonte récursivement la chaîne de dépendances pour valider
    que toutes les archives nécessaires sont présentes et intègres.

    Args:
        manifeste_path  (str) : manifeste du backup à restaurer
        dossier_archives (str) : dossier contenant les archives et manifestes

    Returns:
        bool : True si la chaîne est complète et valide
    """
    with open(manifeste_path, 'r') as f:
        manifeste = json.load(f)

    archives_requises = [manifeste['archive_file']]
    archive_courante  = manifeste.get('depends_on')

    # Remonter la chaîne de dépendances
    while archive_courante:
        archives_requises.append(archive_courante)
        man_prec = os.path.join(dossier_archives, f"{archive_courante}.manifest")

        if not os.path.exists(man_prec):
            logger.error(f"[CHAÎNE] Dépendance manquante : {archive_courante}")
            return False

        with open(man_prec, 'r') as f:
            man_temp = json.load(f)
        archive_courante = man_temp.get('depends_on')

    logger.info(f"[CHAÎNE] ✓ Chaîne valide : {len(archives_requises)} archive(s)")
    return True


# ═══════════════════════════════════════════════════════════════
# EXERCICE 2.3 — Scanner de Fichiers Suspects + Quarantaine
# ═══════════════════════════════════════════════════════════════
#
# Avant toute sauvegarde, scanner les fichiers pour détecter :
#   - Taille excessive (> taille_max_mb)
#   - Extensions dangereuses (.exe, .bat, .sh, .dll...)
# Les suspects sont déplacés en quarantaine, JAMAIS archivés.

EXTENSIONS_DANGEREUSES_DEFAUT = ['.exe', '.bat', '.sh', '.dll', '.sys', '.vbs', '.ps1']


def scanner_fichiers_suspects(dossier, taille_max_mb=100, extensions_dangereuses=None):
    """
    Scanner le dossier et isoler les fichiers suspects en quarantaine.

    Args:
        dossier (str)                       : dossier à analyser
        taille_max_mb (int)                 : seuil de taille en Mo
        extensions_dangereuses (list | None): extensions à bloquer

    Returns:
        list[dict] : liste des fichiers suspects (nom, raison, chemin)
    """
    if extensions_dangereuses is None:
        extensions_dangereuses = EXTENSIONS_DANGEREUSES_DEFAUT

    os.makedirs('quarantine', exist_ok=True)
    suspects = []

    for root, _, files in os.walk(dossier):
        for fichier in files:
            chemin = os.path.join(root, fichier)

            # Vérification 1 : taille excessive
            taille_mo = os.path.getsize(chemin) / (1024 * 1024)
            if taille_mo > taille_max_mb:
                suspects.append({
                    'nom':    fichier,
                    'raison': 'taille_excessive',
                    'valeur': f"{taille_mo:.1f} Mo",
                    'chemin': chemin
                })
                continue

            # Vérification 2 : extension dangereuse
            _, ext = os.path.splitext(fichier)
            if ext.lower() in extensions_dangereuses:
                suspects.append({
                    'nom':    fichier,
                    'raison': 'extension_dangereuse',
                    'valeur': ext,
                    'chemin': chemin
                })

    # Déplacer les suspects en quarantaine
    for suspect in suspects:
        dest = os.path.join('quarantine', suspect['nom'])
        shutil.move(suspect['chemin'], dest)
        suspect['quarantine'] = dest
        logger.warning(f"[QUARANTAINE] Isolé : {suspect['nom']} ({suspect['raison']})")

    # Générer le rapport JSON
    rapport = {
        "timestamp":     datetime.now().isoformat(),
        "dossier_scanne": dossier,
        "nb_suspects":   len(suspects),
        "suspects":      suspects
    }
    with open('rapport_quarantaine.json', 'w', encoding='utf-8') as f:
        json.dump(rapport, f, indent=2)

    if suspects:
        logger.warning(f"[QUARANTAINE] {len(suspects)} fichier(s) isolé(s) — voir rapport_quarantaine.json")
    else:
        logger.info("[QUARANTAINE] ✓ Aucun fichier suspect détecté")

    return suspects


# ═══════════════════════════════════════════════════════════════
# EXERCICE 2.4 — Restauration Parallèle
# ═══════════════════════════════════════════════════════════════
#
# Pour les grandes archives, extraire les fichiers en parallèle
# avec ThreadPoolExecutor accélère significativement la restauration.

def extraire_fichier_unique(args):
    """
    Extrait un seul fichier d'une archive ZIP.
    Conçu pour être appelé par ThreadPoolExecutor.map().

    Args:
        args (tuple) : (archive_path, membre, dossier_destination)

    Returns:
        tuple : (membre, succès:bool)
    """
    archive_path, membre, destination = args
    try:
        with zipfile.ZipFile(archive_path, 'r') as zf:
            zf.extract(membre, destination)
        return membre, True
    except Exception as e:
        logger.error(f"[PARALLÈLE] Erreur extraction {membre} : {e}")
        return membre, False


def restauration_parallele(archive_path, destination, nb_workers=4):
    """
    Extrait une archive ZIP en parallèle pour accélérer la restauration.

    Args:
        archive_path (str) : chemin de l'archive ZIP
        destination  (str) : dossier de destination
        nb_workers   (int) : nombre de threads parallèles (défaut: 4)

    Returns:
        dict : résumé (total, succes, echecs)
    """
    import zipfile

    os.makedirs(destination, exist_ok=True)

    with zipfile.ZipFile(archive_path, 'r') as zf:
        membres = zf.namelist()

    total   = len(membres)
    succes  = 0
    echecs  = 0

    logger.info(f"[PARALLÈLE] {total} fichiers à extraire ({nb_workers} workers)")

    # Préparer les arguments pour chaque worker
    args_liste = [(archive_path, membre, destination) for membre in membres]

    with ThreadPoolExecutor(max_workers=nb_workers) as executor:
        futures = {executor.submit(extraire_fichier_unique, args): args[1]
                   for args in args_liste}

        for i, future in enumerate(as_completed(futures), 1):
            _, ok = future.result()
            if ok:
                succes += 1
            else:
                echecs += 1

            # Barre de progression
            pct     = int((i / total) * 40)
            barre   = '#' * pct + '-' * (40 - pct)
            print(f"\r  [{barre}] {i}/{total} ({i*100//total}%)", end='', flush=True)

    print()  # Nouvelle ligne après la barre
    logger.info(f"[PARALLÈLE] ✓ {succes}/{total} extraits ({echecs} erreurs)")

    return {"total": total, "succes": succes, "echecs": echecs}


# ═══════════════════════════════════════════════════════════════
# EXERCICE 2.5 — Audit Trail ISO 27001
# ═══════════════════════════════════════════════════════════════
#
# ISO 27001 A.12.4.1 : journalisation des événements.
# Format : timestamp | user | action | status | details
# Fichier append-only (jamais écrasé).

class AuditLogger:
    """
    Journalise chaque opération de sauvegarde/restauration.
    Le fichier est ouvert en mode 'a' (append) pour être immuable.

    Format de chaque ligne :
        YYYY-MM-DDTHH:MM:SS | USER | ACTION | STATUS | DETAILS
    """

    def __init__(self, fichier_log='audit_trail.log', utilisateur='system'):
        self.fichier_log  = fichier_log
        self.utilisateur  = utilisateur

    def _ecrire(self, action, statut, details=''):
        """Écrit une ligne horodatée dans le journal."""
        ligne = (
            f"{datetime.now().isoformat()} | "
            f"{self.utilisateur} | "
            f"{action} | "
            f"{statut} | "
            f"{details}\n"
        )
        with open(self.fichier_log, 'a', encoding='utf-8') as f:
            f.write(ligne)

    def log_sauvegarde(self, archive, nb_fichiers, taille_bytes):
        """Journalise une opération de sauvegarde."""
        self._ecrire(
            action='SAUVEGARDE',
            statut='SUCCÈS',
            details=f"archive={archive} fichiers={nb_fichiers} taille={taille_bytes}"
        )

    def log_restauration(self, archive, destination):
        """Journalise une opération de restauration."""
        self._ecrire(
            action='RESTAURATION',
            statut='SUCCÈS',
            details=f"archive={archive} destination={destination}"
        )

    def log_verification_integrite(self, manifeste, resultat):
        """Journalise une vérification d'intégrité."""
        statut = 'SUCCÈS' if resultat else 'ÉCHEC'
        self._ecrire(
            action='VERIFICATION_INTEGRITE',
            statut=statut,
            details=f"manifeste={manifeste}"
        )

    def log_erreur(self, action, message):
        """Journalise une erreur."""
        self._ecrire(action=action, statut='ERREUR', details=message)

    def exporter_rapport(self, debut=None, fin=None, format_sortie='json'):
        """
        Exporte les entrées du journal pour une période donnée.

        Args:
            debut (str | None) : date de début ISO 8601 (None = tout)
            fin   (str | None) : date de fin ISO 8601 (None = tout)
            format_sortie (str): 'json' ou 'csv'

        Returns:
            str : chemin du fichier rapport généré
        """
        entrees = []

        if not os.path.exists(self.fichier_log):
            logger.warning("[AUDIT] Fichier journal introuvable")
            return None

        with open(self.fichier_log, 'r', encoding='utf-8') as f:
            for ligne in f:
                ligne = ligne.strip()
                if not ligne:
                    continue
                parties = ligne.split(' | ')
                if len(parties) >= 4:
                    entree = {
                        'timestamp':  parties[0],
                        'utilisateur': parties[1],
                        'action':     parties[2],
                        'statut':     parties[3],
                        'details':    parties[4] if len(parties) > 4 else ''
                    }
                    # Filtre par période si spécifié
                    if debut and entree['timestamp'] < debut:
                        continue
                    if fin and entree['timestamp'] > fin:
                        continue
                    entrees.append(entree)

        timestamp_rapport = datetime.now().strftime('%Y%m%d_%H%M%S')

        if format_sortie == 'json':
            chemin = f'rapport_audit_{timestamp_rapport}.json'
            with open(chemin, 'w', encoding='utf-8') as f:
                json.dump({
                    "genere_le":     datetime.now().isoformat(),
                    "nb_entrees":    len(entrees),
                    "entrees":       entrees
                }, f, indent=2)

        elif format_sortie == 'csv':
            chemin = f'rapport_audit_{timestamp_rapport}.csv'
            with open(chemin, 'w', encoding='utf-8') as f:
                f.write("timestamp,utilisateur,action,statut,details\n")
                for e in entrees:
                    f.write(f"{e['timestamp']},{e['utilisateur']},{e['action']},{e['statut']},{e['details']}\n")

        logger.info(f"[AUDIT] Rapport exporté : {chemin} ({len(entrees)} entrées)")
        return chemin


# ═══════════════════════════════════════════════════════════════
# Tests
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import zipfile

    print("=" * 55)
    print("TP 5 — Exercices Avancés ISO 27001")
    print("=" * 55)

    # ── Test 2.1 : Rotation de clés ───────────────────────────
    print("\n[2.1] Rotation de clés")
    cle1 = creer_cle_mensuelle(2024, 1)
    cle2 = creer_cle_mensuelle(2024, 2)
    cle_active = charger_cle_active()
    assert cle_active == cle2, "La clé active doit être la plus récente"
    print("    ✓ Rotation de clés OK")

    # ── Test 2.2 : Manifeste incrémental ──────────────────────
    print("\n[2.2] Manifeste incrémental")
    # Créer des archives fictives pour le test
    for nom in ['full_backup.zip', 'incr_backup.zip']:
        with open(nom, 'w') as f:
            f.write('contenu test')

    generer_manifeste_incremental('full_backup.zip')
    generer_manifeste_incremental('incr_backup.zip', archive_precedente='full_backup.zip')
    ok = valider_chaine_restauration('incr_backup.zip.manifest', '.')
    assert ok, "La chaîne doit être valide"
    print("    ✓ Manifeste incrémental OK")

    # ── Test 2.3 : Scanner suspects ───────────────────────────
    print("\n[2.3] Scanner de fichiers suspects")
    os.makedirs('dossier_scan', exist_ok=True)
    with open('dossier_scan/normal.txt', 'w') as f:
        f.write('fichier normal')
    with open('dossier_scan/suspect.exe', 'w') as f:
        f.write('exécutable suspect')

    suspects = scanner_fichiers_suspects('dossier_scan')
    assert len(suspects) == 1, f"Attendu 1 suspect, obtenu {len(suspects)}"
    assert suspects[0]['nom'] == 'suspect.exe'
    print(f"    ✓ {len(suspects)} fichier(s) suspect(s) isolé(s)")

    # ── Test 2.4 : Restauration parallèle ────────────────────
    print("\n[2.4] Restauration parallèle")
    # Créer une archive de test réelle
    with zipfile.ZipFile('test_parallele.zip', 'w') as zf:
        for i in range(10):
            zf.writestr(f'fichier_{i}.txt', f'Contenu {i}\n' * 50)

    res = restauration_parallele('test_parallele.zip', 'restaure_parallele', nb_workers=2)
    assert res['succes'] == 10
    print(f"    ✓ {res['succes']}/{res['total']} fichiers extraits en parallèle")

    # ── Test 2.5 : Audit Trail ────────────────────────────────
    print("\n[2.5] Audit Trail")
    audit = AuditLogger('test_audit.log', utilisateur='etudiant')
    audit.log_sauvegarde('backup.zip', nb_fichiers=5, taille_bytes=10240)
    audit.log_restauration('backup.zip', destination='/restore')
    audit.log_verification_integrite('backup.manifest', resultat=True)
    rapport = audit.exporter_rapport(format_sortie='json')
    assert rapport is not None
    print(f"    ✓ Audit trail OK → {rapport}")

    # Nettoyage
    for item in ['cles', 'quarantine', 'dossier_scan', 'restaure_parallele',
                 'full_backup.zip', 'full_backup.zip.manifest',
                 'incr_backup.zip', 'incr_backup.zip.manifest',
                 'test_parallele.zip', 'test_audit.log',
                 'rapport_quarantaine.json']:
        if os.path.isdir(item):
            shutil.rmtree(item)
        elif os.path.exists(item):
            os.remove(item)
    for f in os.listdir('.'):
        if f.startswith('rapport_audit_'):
            os.remove(f)

    print("\n" + "=" * 55)
    print("✓ TP 5 COMPLET — Tous les exercices avancés passent")
    print("=" * 55)
