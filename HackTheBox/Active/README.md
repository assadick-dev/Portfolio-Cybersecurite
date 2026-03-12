# 🚩 Rapport d'Audit : Machine "Active" (Hack The Box)

| Nom | IP | Difficulté | OS |
| :--- | :--- | :--- | :--- |
| **Active** | 10.129.3.175 | Facile | Windows |

## 1. Résumé de l'Audit
L'objectif était d'évaluer la sécurité d'un contrôleur de domaine. L'audit a révélé deux failles critiques de configuration permettant une compromission totale du domaine (Domain Admin).

## 2. Énumération & Reconnaissance avec Nmap
Nous allons commencer par un scan nmap de tous les ports de la machine pour decouvrir les differents services fonctionnant sur la cible.

![Nmap Scan](./images/nmap-scan.png)

Nmap shows that the target is an Active Directory domain controller for active.htb. The DNS version (6.1) confirms that the operating system is Windows Server 2008 R2 SP1. I added this domain to my /etc/hosts file to help my tools communicate correctly with the target during the next steps.



## 3. 3. SMB Enumeration
Since port 445 was open, I checked for anonymous access to the SMB shares. 
![Nmap Scan](./images/nxc.png)

Using NetExec (formerly CrackMapExec), I discovered that the Replication share was readable without any credentials.

Let's connect to the Replication share 
![Nmap Scan](./images/smbconnect.png)

The Replication share usually contains Group Policy Objects (GPOs). I searched through the directories and found a file named Groups.xml.

![Nmap Scan](./images/mgetSMB.png)


This file is a "gold mine" because it contains a cpassword — an encrypted password for the SVC_TGS user.

Microsoft used to store passwords this way, and although they are encrypted, the AES key is public knowledge. I used the gpp-decrypt tool to recover the password in cleartext.


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
