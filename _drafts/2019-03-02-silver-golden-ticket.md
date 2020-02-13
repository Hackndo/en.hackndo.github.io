---
title: "Silver & Golden Tickets"
date: 2019-03-02 14:58:17
author: "Pixis"
layout: post
permalink: /kerberos-silver-golden-tickets/
disqus_identifier: 0000-0000-0000-00a6
cover: assets/uploads/2019/02/goldenticket.png
description: "Maintenant que nous avons vu le fonctionnement du protocole Kerberos en environnement Active Directory, nous allons découvrir ensemble les notions de Silver Ticket et Golden Ticket"
tags:
  - "Active Directory"
  - Windows
---

Now that we have seen how [Kerberos](/kerberos) works in Active Directory, we are going to discover together the notions of **Silver Ticket** and **Golden Ticket**. To understand how they work, it is necessary to primary focus on the PAC (*Privilege Attribute Certificate*).

<!--more-->

## PAC

PAC is a kind of extension of Kerberos protocol used by Microsoft for proper rights management in Active Directory. The KDC is the only one to really know everything about everyone. It is therefore necessary for it to transmit this information to the various services so that they can create security tokens adapted to the users who use these services.

> Note : Microsoft uses an existing field in the tickets to store information about the user. This field is "authorization-data". So it's not an extension in the true sense of the word.

There is a lot of information about the user in his PAC, such as his name, ID, group membership, security information, and so on. The following is a summary of a PAC found in a TGT. It has been simplified to make it easier to understand.


```
AuthorizationData item
    ad-type: AD-Win2k-PAC (128)
        Type: Logon Info (1)
            PAC_LOGON_INFO: 01100800cccccccce001000000000000000002006a5c0818...
                Logon Time: Aug 17, 2018 16:25:05.992202600 Romance Daylight Time
                Logoff Time: Infinity (absolute time)
                PWD Last Set: Aug 16, 2018 14:13:10.300710200 Romance Daylight Time
                PWD Can Change: Aug 17, 2018 14:13:10.300710200 Romance Daylight Time
                PWD Must Change: Infinity (absolute time)
                Acct Name: pixis
                Full Name: pixis
                Logon Count: 7
                Bad PW Count: 2
                User RID: 1102
                Group RID: 513
                GROUP_MEMBERSHIP_ARRAY
                    Referent ID: 0x0002001c
                    Max Count: 2
                    GROUP_MEMBERSHIP:
                        Group RID: 1108
                        Attributes: 0x00000007
                            .... .... .... .... .... .... .... .1.. = Enabled: The enabled bit is SET
                            .... .... .... .... .... .... .... ..1. = Enabled By Default: The ENABLED_BY_DEFAULT bit is SET
                            .... .... .... .... .... .... .... ...1 = Mandatory: The MANDATORY bit is SET
                    GROUP_MEMBERSHIP:
                        Group RID: 513
                        Attributes: 0x00000007
                            .... .... .... .... .... .... .... .1.. = Enabled: The enabled bit is SET
                            .... .... .... .... .... .... .... ..1. = Enabled By Default: The ENABLED_BY_DEFAULT bit is SET
                            .... .... .... .... .... .... .... ...1 = Mandatory: The MANDATORY bit is SET
                User Flags: 0x00000020
                User Session Key: 00000000000000000000000000000000
                Server: DC2016
                Domain: HACKNDO
                SID pointer:
                    Domain SID: S-1-5-21-3643611871-2386784019-710848469  (Domain SID)
                User Account Control: 0x00000210
                    .... .... .... ...0 .... .... .... .... = Don't Require PreAuth: This account REQUIRES preauthentication
                    .... .... .... .... 0... .... .... .... = Use DES Key Only: This account does NOT have to use_des_key_only
                    .... .... .... .... .0.. .... .... .... = Not Delegated: This might have been delegated
                    .... .... .... .... ..0. .... .... .... = Trusted For Delegation: This account is NOT trusted_for_delegation
                    .... .... .... .... ...0 .... .... .... = SmartCard Required: This account does NOT require_smartcard to authenticate
                    .... .... .... .... .... 0... .... .... = Encrypted Text Password Allowed: This account does NOT allow encrypted_text_password
                    .... .... .... .... .... .0.. .... .... = Account Auto Locked: This account is NOT auto_locked
                    .... .... .... .... .... ..1. .... .... = Don't Expire Password: This account DOESN'T_EXPIRE_PASSWORDs
                    .... .... .... .... .... ...0 .... .... = Server Trust Account: This account is NOT a server_trust_account
                    .... .... .... .... .... .... 0... .... = Workstation Trust Account: This account is NOT a workstation_trust_account
                    .... .... .... .... .... .... .0.. .... = Interdomain trust Account: This account is NOT an interdomain_trust_account
                    .... .... .... .... .... .... ..0. .... = MNS Logon Account: This account is NOT a mns_logon_account
                    .... .... .... .... .... .... ...1 .... = Normal Account: This account is a NORMAL_ACCOUNT
                    .... .... .... .... .... .... .... 0... = Temp Duplicate Account: This account is NOT a temp_duplicate_account
                    .... .... .... .... .... .... .... .0.. = Password Not Required: This account REQUIRES a password
                    .... .... .... .... .... .... .... ..0. = Home Directory Required: This account does NOT require_home_directory
                    .... .... .... .... .... .... .... ...0 = Account Disabled: This account is NOT disabled
```

This PAC is found in the tickets generated for a user (TGT or TGS) and is encrypted either with the KDC key or with the requested service account's key. Therefore the user has no control over this information, and cannot modify his own rights, groups, etc.

This structure is very important because it allows a user to access (or not access) a service, a resource, to perform certain actions.

[![PAC](/assets/uploads/2019/02/pac.png)](/assets/uploads/2019/02/pac.png)

The PAC can be considered as the user's security badge: He can use it to open doors, but he cannot open doors to which he does not have access.

## Silver Ticket

When a customer needs to use a service, he asks the KDC for a TGS (*Ticket Granting Service*). This process goes through two requests [KRB_TGS_REQ](/kerberos/#krb_tgs_req) and [KRB_TGS_REP](/kerberos/#krb_tgs_rep).

As a reminder, here is what a TGS looks like schematically.

[![TGS](/assets/uploads/2019/02/tgs.png)](/assets/uploads/2019/02/tgs.png)

It is encrypted with the NT hash of the account that is running the service (machine account or user account). Thus, if an attacker manages to extract the password or NT hash of a service account, he can then forge a service ticket (TGS) by choosing the information he wants to put in it in order to access that service, without asking the KDC. It is the attacker who builds this ticket. It is this forged ticket that is called **Silver Ticket**.

Let's take as an example an attacker who finds the NT hash of `DESKTOP-01` machine account, which is called `DESKTOP-01$`. The attacker can create a block of data corresponding to a ticket like the one found in [KRB_TGS_REP](/kerberos/#krb_tgs_rep). He will specify the domain name, the name of the requested service (its [SPN](/service-principal-name-spn) - Service Principal Name), a username (which he can choose arbitrarily), his PAC (which he can also forge). Here is a simplistic example of a ticket that the attacker can create:

* **realm** : adsec.local
* **sname** : cifs\desktop-01.adsec.local
* **enc-part** : *// Encrypted with compromised NT hash*
    * **key** : 0x309DC6FA122BA1C *// Arbitrary session key*
    * **crealm** : adsec.local
    * **cname** : pixisAdmin
    * **authtime** : 2050/01/01 00:00:00 *// Ticket validity date*
    * **authorization-data** : Forged PAC where, say, this user is domain administrator

Once this structure is created, it encrypts the `enc-part` block with the compromised NT hash, then it can create a [KRB_AP_REQ](/kerberos/#krb_ap_req) from scratch. He just has to send this ticket to the targeted service, along with an authenticator that he encrypts with the session key he arbitrarily chose in the TGS. The service will be able to decrypt the TGS, extract the session key, decrypt the authenticator and provide the service to the user since the information forged in the PAC indicates that the user is a Domain Administrator, and this service allows Domain Admins to use it.

Only the PAC is double signed. The first signature uses service account's secret, but the second uses domain controller's secret (krbtgt account's secret). The attacker only knows the service account's secret, so he is not able to forge the secod signature. However, when the service receives this ticket, it usually verifies only the first signature. This is because service accounts with [SeTcbPrivilege](https://docs.microsoft.com/en-us/windows/desktop/secauthz/privilege-constants), accounts that can act as part of the operating system (for example the local `SYSTEM` account), do not verify the Domain Controller's signature. That's very convenient from an attacker's perspective! It also means that even if krbtgt password is changed, Silver Tickets will still work, as long as the service's password doesn't change.

Here is a schematic summarizing the attack:

[![Silver Ticket](/assets/uploads/2019/02/silverticket.png)](/assets/uploads/2019/02/silverticket.png)

En pratique, voici une capture d'écran qui montre la création d'un Silver Ticket avec l'outil [Mimikatz](http://blog.gentilkiwi.com/mimikatz) développé par Benjamin Delpy ([@gentilkiwi](https://twitter.com/gentilkiwi)).

[![CIFS Example](/assets/uploads/2019/02/ST_CIFS.png)](/assets/uploads/2019/02/ST_CIFS.png)

Here's the command line used in Mimikatz:

```
/kerberos::golden /domain:adsec.local /user:random_user /sid:S-1-5-21-1423455951-1752654185-1824483205 /rc4:ceaxxxxxxxxxxxxxxxxxxxxxxxxxxxxx /target:DESKTOP-01.adsec.local /service:cifs /ptt
```

Cela veut dire qu'on crée un ticket pour le domaine `adsec.local` avec un nom d'utilisateur **arbitraire** (`random_user`), et que l'on vise le service `CIFS` de la machine `DESKTOP-01` en fournissant son hash NTLM.

Il est également possible de créer un Silver Ticket sous linux en utilisant [impaket](https://github.com/SecureAuthCorp/impacket), via l'outil `ticketer.py`.

```bash
ticketer.py -nthash ceaxxxxxxxxxxxxxxxxxxxxxxxxxxxxx -domain-sid S-1-5-21-1423455951-1752654185-1824483205 -domain adsec.local -spn CIFS/DESKTOP-01.adsec.local random_user
``` 

Il faut ensuite exporter le chemin du ticket dans une variable d'environnement spéciale `KRB5CCNAME`

```bash
export KRB5CCNAME='/chemin/vers/random_user.ccache'
```

Enfin, tous les outils de la suite `impacket` peuvent être utilisés avec ce ticket, via l'option `-k`

```bash
psexec.py -k DESKTOP-01.adsec.local
```

## Golden Ticket

Nous avons vu qu'avec un **Silver Ticket**, il était possible d'accéder à un service fourni par un compte de domaine si ce compte était compromis. En effet, le service accepte les informations chiffrées avec son propre secret puisqu'en théorie, seul le service et le KDC ont connaissance de ce secret.

C'est un bon début, mais nous pouvons aller plus loin. En construisant un Silver Ticket, l'attaquant s'affranchit du KDC puisqu'en réalité, le vrai PAC de l'utilisateur contenu dans son TGT ne permet pas d'effectuer toutes les actions qu'il souhaite. Pour pouvoir modifier le TGT, ou en forger un nouveau, il faudrait connaitre la clé qui l'a chiffré, c'est à dire celle du KDC. Cette clé, c'est en fait le hash NTLM du compte `krbtgt`. Ce compte est un simple compte, sans droits particuliers (au niveau système ou Active Directory) et même désactivé. Cette faible exposition permet de mieux le protéger.

Si jamais un attaquant parvient à trouver le hash NTLM de ce compte, il est alors en mesure de forger des TGT avec des PAC arbitraires. Et là, c'est un peu le Saint Graal. Il suffit de forger un TGT avec comme information que l'utilisateur de ce ticket fait partie du groupe "Administrateurs du Domaine", et le tour est joué.

Avec un TGT de la sorte entre les mains, l'utilisateur peut demander au KDC n'importe quel TGS pour n'importe quel service. Or ces TGS auront une copie du PAC qu'a forgé l'attaquant, certifiant qu'il est administrateur de domaine.

C'est ce TGT forgé qui est appelé **Golden Ticket**. Le schéma de l'attaque est très similaire à celui du Silver Ticket. Voici une représentation également simplifiée :

[![Golden Ticket](/assets/uploads/2019/02/goldenticket.png)](/assets/uploads/2019/02/goldenticket.png)

En pratique, voici la démonstration de la création d'un **Golden Ticket**. D'abord, nous sommes dans une session qui ne possède pas de ticket en cache, et n'a pas les droits pour accéder à `\\DC-01.adsec.local\c$`.

[![Access denied](/assets/uploads/2019/03/golden_ticket_access_denied.png)](/assets/uploads/2019/03/golden_ticket_access_denied.png)

On génère alors le **Golden Ticket** en utilisant le hash NTLM du compte `krbtgt`

[![GT Generation](/assets/uploads/2019/03/golden_ticket_generated.png)](/assets/uploads/2019/03/golden_ticket_generated.png)

La ligne de commande utilisée dans Mimikatz est la suivante :

```
/kerberos::golden /domain:adsec.local /user:random_user /sid:S-1-5-21-1423455951-1752654185-1824483205 /krbtgt:ceaxxxxxxxxxxxxxxxxxxxxxxxxxxxxx /ptt
```
Cela veut dire qu'on crée un ticket pour le domaine `adsec.local` avec un nom d'utilisateur **arbitraire** (`random_user`), en fournissant le hash NTLM de l'utilisateur `krbtgt`. Cette commande crée un TGT avec une PAC indiquant que nous sommes administrateur du domaine (entre autre), et que nous nous appelons ANYUSER (choisi arbitrairement).

Une fois ce ticket en mémoire, notre session est en mesure de demander un TGS pour n'importe quel [SPN](/service-principal-name-spn), par exemple pour `CIFS\DC-01.adsec.local` permettant de lire le contenu du partage `\\DC-01.adsec.local\$`

[![GT granted](/assets/uploads/2019/03/golden_ticket_access_granted.png)](/assets/uploads/2019/03/golden_ticket_access_granted.png)

Il est également possible de créer un Golden Ticket sous linux en utilisant [impaket](https://github.com/SecureAuthCorp/impacket), via l'outil `ticketer.py`.

```bash
ticketer.py -nthash ceaxxxxxxxxxxxxxxxxxxxxxxxxxxxxx -domain-sid S-1-5-21-1423455951-1752654185-1824483205 -domain adsec.local random_user
``` 

Il faut ensuite exporter le chemin du ticket dans une variable d'environnement spéciale `KRB5CCNAME`

```bash
export KRB5CCNAME='/chemin/vers/random_user.ccache'
```

Enfin, tous les outils de la suite `impacket` peuvent être utilisés avec ce ticket, via l'option `-k`

```bash
secretsdump.py -k DC-01.adsec.local -just-dc-ntlm -just-dc-user krbtgt
```


## Méthodes de chiffrement

Jusqu'ici, nous utilisions les hashs `NT` pour créer les Silver/Golden Tickets. En réalité, cela signifie que nous utilisions la méthode de chiffrement `RC4_HMAC_MD5`, mais ce n'est pas la seule qui existe. En effet, aujourd'hui, plusieurs méthodes de chiffrement sont possibles au sein d'un Active Directory car elles ont évolué avec les versions de Windows. Voici un tableau récapitulatif issu de la [documentation Microsoft](https://docs.microsoft.com/fr-fr/windows/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos)

[![Encryption types](/assets/uploads/2019/03/encryption_types.png)](/assets/uploads/2019/03/encryption_types.png)

Il est possible d'utiliser la méthode de chiffrement souhaitée pour générer le TGT. Il suffira de la préciser dans les futures requêtes avec le contrôleur de domaine (l'information se trouvera dans le champ `EType` associé au TGT). Voici un exemple avec l'utilisation du chiffrement AES256.

[![GT AES](/assets/uploads/2019/03/golden_ticket_access_granted_aes.png)](/assets/uploads/2019/03/golden_ticket_access_granted_aes.png)

Par ailleurs, d'après la présentation [Evading Microsoft ATA for 
Active Directory Domination](https://www.blackhat.com/docs/us-17/thursday/us-17-Mittal-Evading-MicrosoftATA-for-ActiveDirectory-Domination.pdf) de [Nikhil Mittal](https://twitter.com/nikhil_mitt) à la Black Hat, cela permettrait de ne pas être détecté par Microsoft ATA, pour le moment, puisqu'on évite de faire un *downgade* de méthode de chiffrement. En effet, par défaut, la méthode de chiffrement utilisée est la plus forte supportée par le client.


## Conclusion

Cet article permet de clarifier les notions de PAC, Silver Ticket, Golden Ticket, ainsi que les différentes méthodes de chiffrement utilisées dans les échanges. Ces notions sont essentielles pour comprendre les attaques Kerberos dans un Active Directory.

N'hésitez pas à laisser un commentaire ou à me retrouver sur le [serveur Discord](https://discord.gg/9At6SUZ) du blog si vous avez des questions ou des idées !

## Ressources

* [Secrets d’authentification épisode II Kerberos contre-attaque - Aurélien Bordes](https://www.sstic.org/media/SSTIC2014/SSTIC-actes/secrets_dauthentification_pisode_ii__kerberos_cont/SSTIC2014-Article-secrets_dauthentification_pisode_ii__kerberos_contre-attaque-bordes_2.pdf)
* [ADSecurity - Pyrotek3](http://adsecurity.org/)
* [Kerberos Exploration - Rémi Vernier](http://remivernier.com/index.php/2018/07/07/kerberos-exploration/)
* [Sécurité réseau: configurer les types de chiffrement autorisés pour Kerberos - Microsoft](https://docs.microsoft.com/fr-fr/windows/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos)
* [Encryption Type Selection in Kerberos Exchanges - Microsoft](https://blogs.msdn.microsoft.com/openspecification/2010/11/17/encryption-type-selection-in-kerberos-exchanges/)