# 🚩 Rapport d'Audit : Machine "Active" (Hack The Box)

| Nom | IP | Difficulté | OS |
| :--- | :--- | :--- | :--- |
| **Active** | 10.129.3.175 | Facile | Windows |

## 1. Résumé de l'Audit
L'objectif était d'évaluer la sécurité d'un contrôleur de domaine. L'audit a révélé deux failles critiques de configuration permettant une compromission totale du domaine (Domain Admin).

## 2. Énumération & Reconnaissance avec Nmap
Nous allons commencer par un scan nmap de tous les ports de la machine pour decouvrir les differents services fonctionnant sur la cible.

![Nmap Scan](./images/nmap-scan)

## 3. Accès Initial (Exploitation GPP)
Le partage `Replication` contenait une réplique du dossier `SYSVOL`. Une recherche récursive a permis d'extraire le fichier `Groups.xml`.

![Récupération XML](./images/mgetSMB.png)

Ce fichier contenait un `cpassword`. En exploitant la clé AES statique de Microsoft via `gpp-decrypt`, les identifiants de l'utilisateur `SVC_TGS` ont été compromis.

![Déchiffrement GPP](./images/cleGPP.png)

**Flag Utilisateur :**
![User Flag](./images/initial_access.png)

## 4. Escalade de Privilèges (Kerberoasting)
Une fois authentifié, l'outil `GetADUsers.py` a confirmé que l'utilisateur Administrateur était actif.

![Utilisateurs Actifs](./images/dusers.png)

L'attaque par **Kerberoasting** a été lancée pour extraire le ticket TGS du compte Administrateur, vulnérable car lié à un SPN.

![Extraction TGS](./images/usersActif.png)

Le hash a été cassé hors-ligne avec `Hashcat` en utilisant le dictionnaire `rockyou.txt`.

![Hashcat Crack](./images/mdp_admin.png)

## 5. Post-Exploitation
Un shell interactif a été obtenu via `wmiexec.py` (exécution fileless) pour valider l'accès root.

![Root Flag](./images/root.png)

## 🛡️ Remédiations préconisées
1. Appliquer le correctif **MS14-025** pour interdire le stockage de mots de passe dans les fichiers XML de GPP.
2. Utiliser des **Group Managed Service Accounts (gMSA)** avec des mots de passe complexes (25+ caractères) pour mitiger le Kerberoasting.
