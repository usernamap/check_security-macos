#!/usr/bin/env python3
import subprocess
import json
import re
import os
from datetime import datetime


# Fonction pour exécuter des commandes shell
def run_command(cmd):
    return subprocess.run(
        cmd, shell=True, capture_output=True, text=True
    ).stdout.strip()


# Vérifier les connexions réseaux établies (ports suspects)
def check_network_connections():
    print("\n--- Vérification des connexions réseau suspectes ---")
    netstat_output = run_command("lsof -i -P -n | grep ESTABLISHED")
    suspicious_ports = ["1337", "31337", "6667", "12345", "31338"]
    alerts = []

    for line in netstat_output.split("\n"):
        if any(port in line for port in suspicious_ports):
            alerts.append(line)

    if alerts:
        print("⚠️ Ports suspects détectés :")
        print("\n".join(alerts))
        return False
    else:
        print("✅ Aucune connexion suspecte détectée.")
        return True


# Vérifier les utilisateurs connectés
def check_logged_users():
    print("\n--- Vérification des utilisateurs connectés ---")
    users = run_command("who")
    users_list = users.split("\n")

    if len(users_list) > 1:
        print("⚠️ Multiples utilisateurs connectés :")
        print(users)
        return False
    else:
        print("✅ Un seul utilisateur connecté.")
        return True


# Vérification des processus suspects
def check_suspicious_processes():
    print("\n--- Vérification des processus suspects ---")
    ps_output = run_command("ps aux")
    suspicious_patterns = [
        "keylogger",
        "crypto",
        "miner",
        "rootkit",
        "nc -l",
        "netcat",
        "nmap",
    ]
    alerts = []

    for line in ps_output.split("\n"):
        if any(pattern in line.lower() for pattern in suspicious_patterns):
            alerts.append(line)

    if alerts:
        print("⚠️ Processus suspects détectés :")
        print("\n".join(alerts))
        return False
    else:
        print("✅ Aucun processus suspect détecté.")
        return True


# Vérification des tâches planifiées suspectes (crontab)
def check_crontab():
    print("\n--- Vérification des tâches cron suspectes ---")
    cron_output = run_command("crontab -l")
    suspicious_patterns = ["curl ", "wget ", "nc ", "bash -i"]
    alerts = []

    for line in cron_output.split("\n"):
        if any(pattern in line.lower() for pattern in suspicious_patterns):
            alerts.append(line)

    if alerts:
        print("⚠️ Tâches cron suspectes détectées :")
        print("\n".join(alerts))
        return False
    else:
        print("✅ Aucune tâche cron suspecte détectée.")
        return True


# Vérification des fichiers récents suspects modifiés dans les dossiers sensibles
def check_recent_files():
    print(
        "\n--- Vérification des fichiers modifiés récemment dans les dossiers sensibles ---"
    )
    dirs = ["/Library/LaunchAgents", "/Library/LaunchDaemons", "~/Library/LaunchAgents"]
    suspicious_files = []

    for dir_path in dirs:
        dir_path = os.path.expanduser(dir_path)
        if os.path.exists(dir_path):
            for root, dirs, files in os.walk(dir_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    mod_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                    if (datetime.now() - mod_time).days < 7:
                        suspicious_files.append(f"{file_path} modifié le {mod_time}")

    if suspicious_files:
        print("⚠️ Fichiers suspects modifiés récemment détectés :")
        print("\n".join(suspicious_files))
        return False
    else:
        print("✅ Aucun fichier récent suspect détecté.")
        return True


# Vérification des binaires systèmes modifiés récemment
def check_binary_modifications():
    print("\n--- Vérification des binaires système modifiés récemment ---")
    dirs = ["/usr/bin", "/usr/local/bin"]
    alerts = []

    for path in dirs:
        if os.path.exists(path):
            for root, dirs, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        mod_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                        if (datetime.now() - mod_time).days < 14:
                            alerts.append(f"{file_path} modifié le {mod_time}")
                    except Exception:
                        continue

    if alerts:
        print("⚠️ Binaires système modifiés récemment :")
        print("\n".join(alerts))
        return False
    else:
        print("✅ Aucun binaire système modifié récemment.")
        return True


# Vérification des permissions système sensibles (TCC.db)
def check_privacy_permissions():
    print("\n--- Vérification des applications avec accès complet au disque ---")
    tcc_db_path = os.path.expanduser(
        "~/Library/Application Support/com.apple.TCC/TCC.db"
    )
    if not os.path.exists(tcc_db_path):
        print("⚠️ TCC.db non trouvé, accès complet au disque non vérifiable.")
        return True

    try:
        output = run_command(
            f"sqlite3 '{tcc_db_path}' \"SELECT client, service FROM access WHERE service='SystemPolicyAllFiles';\""
        )
        if output:
            print("⚠️ Applications avec accès complet au disque :")
            print(output)
            return False
        else:
            print("✅ Aucune application non autorisée avec accès complet au disque.")
            return True
    except Exception as e:
        print(f"Erreur lors de l'accès à TCC.db : {e}")
        return True


# Vérification des extensions système installées
def check_system_extensions():
    print("\n--- Vérification des extensions système installées ---")
    output = run_command("systemextensionsctl list")
    print(output or "Aucune extension système listée.")
    return True


# Analyse des logs système pour comportements anormaux
def check_system_logs():
    print("\n--- Analyse des logs système (recherches de commandes suspectes) ---")
    keywords = [
        "launchctl",
        "curl",
        "wget",
        "bash -i",
        "reverse shell",
        "base64",
        "python -m http.server",
    ]
    command = "log show --predicate 'eventMessage CONTAINS \"{}\"' --info --last 7d"
    found = False
    for keyword in keywords:
        result = run_command(command.format(keyword))
        if result:
            print(f"⚠️ Détection de l'activité suspecte liée à : {keyword}")
            print(result[:1000])  # tronquer pour éviter surcharge
            found = True
    if not found:
        print("✅ Aucun log suspect détecté.")
    return not found


# Résultat final (Bilan)
def final_assessment():
    print("\n\n=== Bilan final de sécurité ===")
    checks = [
        check_network_connections(),
        check_logged_users(),
        check_suspicious_processes(),
        check_crontab(),
        check_recent_files(),
        check_binary_modifications(),
        check_privacy_permissions(),
        check_system_extensions(),
        check_system_logs(),
    ]

    if all(checks):
        print("\n✅ Votre système ne présente aucun signe évident de compromission.")
    else:
        print(
            "\n⚠️ Des signes suspects ont été détectés ! Approfondissez immédiatement les vérifications ou consultez un expert en cybersécurité."
        )


# Exécution du diagnostic
if __name__ == "__main__":
    print("🔍 Début du diagnostic de sécurité chirurgical sur votre MacBook Pro 🔍")
    final_assessment()
