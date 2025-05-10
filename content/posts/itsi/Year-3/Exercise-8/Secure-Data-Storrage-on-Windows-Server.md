+++
date = '2025-04-11T03:33:09+02:00'
title = 'Secure data storrage on Windows Server'
categories = ["school", "it sec"]
tags = ["windows","it sec","school","blue team"]
+++

> Note: this was converted from LaTeX to Markdown using ChatGPT 4.1. The original PDF can be found [here](https://github.com/Stefanistkuhl/goobering/blob/master/itsi/y3/ex8/Sichere%20Datenspeicherung%20unter%20Windows.pdf) along with the [bibliography](https://github.com/Stefanistkuhl/goobering/blob/master/itsi/y3/ex8/quellen.bib).

---

# Secure data storage on Windows

---

**Laboratory protocol**  
Exercise 8: Secure data storage on Windows  
{{< figure src="/itsi/y3/ex8/images/menAAA.png" title="Figure: Grouplogo" >}}
**Subject:** ITSI  
**Class:** 3AHITN  
**Name:** Stefan Fürst, Justin Tremurici  
**Group Name/Number:** todo/12  
**Supervisor:** SPAC, ZIVK  
**Exercise dates:** 14.02.2025 | 21.02.2025 | 28.02.2025 | 7.02.2025  
**Submission date:** 14.3.2025

---

## Table of Contents

- [Task definition](#task-definition)
- [Summary](#summary)
- [Exercise Execution](#exercise-execution)
- [References](#references)

---

## Task definition

### Task Overview

The goal of this exercise is to set up a secure and structured data storage system on a Windows Server, ensuring proper access control and encryption. The tasks include installing the operating system, configuring users and groups, setting up a folder structure, and securing access with permissions.

First, `Windows Server 2019` or newer must be installed in a virtualized environment, with the `hostname` and user accounts configured according to a naming convention. A structured folder system should be created based on an assigned fictional company, categorizing data logically and including sample files.

User management involves defining necessary accounts, organizing them into `organizational groups`, and enforcing a consistent naming scheme. Permissions must be applied using `NTFS` security settings, restricting access appropriately. `Network shares` need to be configured to allow remote access while maintaining security through controlled sharing settings.

The storage system must be optimized by creating a new `partition`, migrating data, and applying `BitLocker` encryption. All configurations should be verified, and documentation is required throughout the process. `PowerShell` automation is encouraged where applicable.<cite>ChatGPT[^1]</cite>

---

## Summary

This task was fully automated using two `PowerShell` scripts. The first script set up the environment by configuring the necessary system settings and creating a `Scheduled Task` using `New-ScheduledTask` and `Register-ScheduledTask` to execute the second script at predefined intervals. The second script performed all required operations, including creating and managing `users`, `directories`, `files`, and their `permissions`.

To manage users, the script utilized commands such as `New-LocalUser` to create users, `Add-LocalGroupMember` to assign them to groups, and `Set-LocalUser` to modify user settings. The script dynamically generated random user accounts and assigned them to groups based on predefined logic. Organizational groups and security groups were structured to align with the fictional company scenario, BuildSmart BIM, a digital building company specializing in architecture, material lists, and time plans.

For managing directories and files, commands like `New-Item` were used to create directory structures, and `icacls` was used to configure `NTFS permissions` for securing access.

The partitioning of the drive was accomplished using `Resize-Partition` to shrink the primary partition and `New-Partition` to create a new `B:` partition, followed by `Format-Volume` to prepare it for use. The existing directory structure was then migrated using `Move-Item`.

To enable file sharing, `New-SmbShare` was employed to create network shares. Additionally, the script encrypted the partition using `Enable-BitLocker`.

Through this approach, the entire process was streamlined and executed automatically, significantly reducing manual effort while maintaining a structured and secure environment.

---

## Exercise Execution

### Introduction

This entire exercise was automated with a script that can be invoked with a single command. It is designed to be used after setting up a fresh install of a new version of Windows Server. This script will complete the entire exercise automatically.

**Note:** For the script to work, the language of the Windows Server installation must be set to English, since user and group names are localized with no available aliases.<cite>Nico Boehr[^2]</cite>

To run it, simply log into the Administrator account, press **Windows + R** to open the Run dialog, and paste the following command:

```powershell
powershell.exe iwr https://tinyurl.com/mr234bdr | iex
```

This runs `powershell.exe` and uses the abbreviation `iwr`, which stands for `Invoke-WebRequest`. This command makes a web request to the given link, which in this case is https://tinyurl.com/mr234bdr. This URL redirects to the raw file from my GitHub repository, where the first of two PowerShell scripts is downloaded.<cite>Invoke-WebRequest[^3]</cite>

**Important:** Whenever you run a command like this, always open the URL in your web browser first to verify its contents. Check whether the script has any red flags, such as obfuscation or suspicious behavior that it is not intended to perform.

The downloaded script is then piped into `iex`, which is short for `Invoke-Expression`. This executes the output from `stdin`, which, in this case, is the contents of the script.<cite>Abbreviation Table[^4]</cite><cite>Invoke-Expression[^5]</cite>

---

#### Explaining the first script

##### Changing the execution policy

The first line of the `setup.ps1` script is:

```powershell
Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
```

This sets the `ExecutionPolicy` parameter to the `RemoteSigned` policy. The `Scope` parameter specifies the default scope value in this command as `LocalMachine`. The `-Force` parameter is used to suppress all confirmation prompts. So that the second script that is downloaded in this script is allowed to run on this device.<cite>Set-ExecutionPolicy[^6]</cite>

This can be verified by running the following command:

```powershell
Get-ExecutionPolicy -List
```

{{< figure src="/itsi/y3/ex8/images/expolicy.png" title="Figure 1: Listing the execution policies of the local machine" >}}

---

##### Installing BitLocker

`Install-WindowsFeature BitLocker` installs the Windows feature BitLocker, which is used for drive encryption and will be needed later in the exercise. It is included in the setup because its installation requires a reboot.<cite>Install-WindowsFeature[^7]</cite><cite>BitLocker[^8]</cite>

---

##### Changing the Hostname

`Rename-Computer -NewName "fus-win-12" -Force` changes the hostname of the computer to `fus-win-12`. The `-Force` parameter ensures the command runs non-interactively. This requires a reboot as well and is therefore included in the setup script.<cite>rename-computer[^9]</cite>

The change of the hostname can be verified by using the `hostname` command:

{{< figure src="/itsi/y3/ex8/images/hostname.png" title="Figure 2: Verifying the hostname change" >}}

---

##### Downloading the second script

To download the second script, `Invoke-WebRequest` is used again with a `url` and `dest` variable to store the desired URL and destination file.

```powershell
$url = "https://raw.githubusercontent.com/Stefanistkuhl/obsidianschule/refs/heads/main/3.Klasse/itsi/aufgaben/windoof/script.ps1"
$dest = "C:\Users\Administrator\script.ps1"
Invoke-WebRequest -Uri $url -OutFile $dest
```

---

##### Enabling Remote Desktop

For easier management and testing of users, we choose to enable Remote Desktop.

```powershell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```
<cite>Enable-Remote-Desktop[^10]</cite>

---

##### Creating a Scheduled Task

Since a restart is needed for the first part, some form of persistence is required for the second script to execute. For this, Windows Scheduled Tasks are used to execute the second script after a reboot with a set trigger.<cite>New-ScheduledTask[^11]</cite>

```powershell
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-file C:\Users\Administrator\script.ps1"
$Trigger = New-ScheduledTaskTrigger -AtLogon -User "Administrator"
$Settings = New-ScheduledTaskSettingsSet
Register-ScheduledTask -TaskName "after-setup" -Action $Action -Trigger $Trigger -Settings $Settings
Restart-Computer
```

{{< figure src="/itsi/y3/ex8/images/tasksh.png" title="Figure 3: Inspecting the created task in task scheduler" >}}

---

#### The second script

Now that the setup script has finished running, after logging in as the administrator again, the second script will be launched.

##### Creating Users and Adding Them to Groups

In this step, two new users will be created: `fus-admin` and `fus-user`. These serve as the administrator's low-privileged account and privileged account, respectively, in this scenario.

```powershell
$supersurepassword = ConvertTo-SecureString "rafi123_" -AsPlainText
New-LocalUser -Name 'fus-admin' -Password $supersurepassword
New-LocalUser -Name 'fus-user' -Password $supersurepassword
Add-LocalGroupMember -Group "Administrators" -Member fus-admin
Add-LocalGroupMember -Group "Remote Desktop Users" -Member fus-user
```
<cite>ConvertTo-SecureString[^12]</cite><cite>New-LocalUser[^13]</cite><cite>Add-LocalGroupMember[^14]</cite>

{{< figure src="/itsi/y3/ex8/images/fus-admin&&fus-user.png" title="Figure 4: Verifying the functionality of the two users" >}}
{{< figure src="/itsi/y3/ex8/images/fus-net-user.png" title="Figure 5: Printing information about the users" >}}

---

##### Resizing the Disk and Creating a New Partition

```powershell
Resize-Partition -DiskNumber 0 -PartitionNumber 2 -Size (40GB)
New-Partition -DiskNumber 0 -UseMaximumSize -DriveLetter B
Format-Volume -DriveLetter B -FileSystem NTFS -AllocationUnitSize 4096
```
<cite>Resize-Partition[^15]</cite><cite>New-Partition[^16]</cite><cite>Volumes[^17]</cite><cite>Cluster-Size[^18]</cite><cite>Format-Volume[^19]</cite><cite>Cluster-Size-2[^20]</cite>

{{< figure src="/itsi/y3/ex8/images/Get-Partition.png" title="Figure 6: Printing the partition table" >}}

---

##### Creating Directories

```powershell
$baseDir = "B:\CompanyData"
$folders = @(
    "Administration",
    "Finance",
    "HumanResources",
    "IT",
    "Legal",
    "Marketing",
    "Sales"
)

foreach ($folder in $folders) {
    New-Item -Path $baseDir -Name $folder -ItemType Directory
}
```

{{< figure src="/itsi/y3/ex8/images/show spanning-tree.png" title="Figure 7: Printing the directory structure" >}}

---

##### Populating the Directories

```powershell
$sampleFiles = @(
    "Budget.xlsx",
    "EmployeeList.csv",
    "ProjectPlan.pptx",
    "Report.docx"
)

foreach ($file in $sampleFiles) {
    foreach ($folder in $folders) {
        New-Item -Path "$baseDir\$folder" -Name $file -ItemType File
    }
}
```

{{< figure src="/itsi/y3/ex8/images/lsr.png" title="Figure 8: Recursively listing the files" >}}

---

##### Creating Users and Groups

```powershell
$groups = @("Admins", "Users", "Guests")
$users = @("alice", "bob", "charlie")

foreach ($group in $groups) {
    New-LocalGroup -Name $group
}

foreach ($user in $users) {
    $password = ConvertTo-SecureString "P@ssw0rd" -AsPlainText
    New-LocalUser -Name $user -Password $password
    Add-LocalGroupMember -Group "Users" -Member $user
}
```

{{< figure src="/itsi/y3/ex8/images/theVoices.png" title="Figure 9: Diagram of the users, groups and their permissions" >}}

---

##### Verifying the Creation of users and groups

{{< figure src="/itsi/y3/ex8/images/ds2.jpg" title="Figure 10: Showing all the groups" >}}

---

##### Managing NTFS Permissions Using icacls

```powershell
icacls "B:\CompanyData" /grant:r "Administrators:(OI)(CI)F" /T
icacls "B:\CompanyData" /grant:r "Users:(OI)(CI)RX" /T
icacls "B:\CompanyData" /grant:r "Guests:(OI)(CI)R" /T
```

{{< figure src="/itsi/y3/ex8/images/icals.png" title="Figure 11: Viewing the NTFS permissions of a directory" >}}

---

##### Sharing the Directories via SMB

```powershell
New-SmbShare -Name "CompanyData" -Path "B:\CompanyData" -FullAccess "Administrators","Users" -ReadAccess "Guests"
```

{{< figure src="/itsi/y3/ex8/images/Get-SMBShare.png" title="Figure 12: Listing all the active SMB shares" >}}

---

Now, users can only access the files they need via the network share. Since in Section 3.2.10, permissions to the root directory were removed, users do not have access to the entire file structure. In this scenario, this is a central server where each employee either has a local workstation or a thin client and connects to the server remotely.

{{< figure src="/itsi/y3/ex8/images/nettest.jpg" title="Figure 13: Showing the groups that the test user is part of" >}}
{{< figure src="/itsi/y3/ex8/images/nolocacc.jpg" title="Figure 14: Trying to access the directories locally on the drive" >}}
{{< figure src="/itsi/y3/ex8/images/sharesadge.png" title="Figure 15: Trying to access a share that the user has no permission to open" >}}
{{< figure src="/itsi/y3/ex8/images/readOnly.jpg" title="Figure 16: Trying to create a file in a directory where the user only has read permissions" >}}
{{< figure src="/itsi/y3/ex8/images/rw.jpg" title="Figure 17: Creating a file in a directory where the user has read and write permissions" >}}

---

##### Encrypting the Volume using BitLocker

```powershell
Enable-BitLocker -MountPoint "B:" -EncryptionMethod Aes128 -PasswordProtector -Password $supersurepassword
```
<cite>Enable-BitLocker[^21]</cite>

{{< figure src="/itsi/y3/ex8/images/locked.jpg" title="Figure 18: Trying to list the contents of the encrypted volume" >}}
{{< figure src="/itsi/y3/ex8/images/unlock.jpg" title="Figure 19: Trying to list the contents of the encrypted volume after decrypting it" >}}

---

## References

*For a full bibliography, see the [original BibTeX file](https://github.com/Stefanistkuhl/goobering/blob/master/itsi/y3/ex8/quellen.bib).*

[^1]: This task definition was generated using ChatGPT.
[^2]: Nico Boehr. Localized Names of Users and Groups in Windows. [source](https://blog.nicoboehr.de/2014/08/20/localized-names-of-users-and-groups-in-windows)
[^3]: sdwheeler. Invoke-WebRequest (Microsoft.PowerShell.Utility) - PowerShell. [source](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-7.5)
[^4]: Agoston, Zsolt. PowerShell Abbreviation Table | OpenTechTips. [source](https://opentechtips.com/powershell-abbreviation-table)
[^5]: sdwheeler. Invoke-Expression (Microsoft.PowerShell.Utility) - PowerShell. [source](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression?view=powershell-7.5)
[^6]: sdwheeler. Set-ExecutionPolicy (Microsoft.PowerShell.Security) - PowerShell. [source](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-executionpolicy?view=powershell-7.5)
[^7]: JasonGerend. Install-WindowsFeature (ServerManager). [source](https://learn.microsoft.com/en-us/powershell/module/servermanager/install-windowsfeature?view=windowsserver2025-ps)
[^8]: JasonGerend. BitLocker Module. [source](https://learn.microsoft.com/en-us/powershell/module/bitlocker/?view=windowsserver2025-ps)
[^9]: sdwheeler. Rename-Computer (Microsoft.PowerShell.Management) - PowerShell. [source](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/rename-computer?view=powershell-7.5)
[^10]: PowerShell FAQs. How to Enable Remote Desktop Using PowerShell? [source](https://powershellfaqs.com/enable-remote-desktop-using-powershell)
[^11]: JasonGerend. New-ScheduledTask (ScheduledTasks). [source](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtask?view=windowsserver2025-ps)
[^12]: sdwheeler. ConvertTo-SecureString (Microsoft.PowerShell.Security) - PowerShell. [source](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring?view=powershell-7.5)
[^13]: sdwheeler. New-LocalUser (Microsoft.PowerShell.LocalAccounts) - PowerShell. [source](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/new-localuser?view=powershell-5.1)
[^14]: sdwheeler. Add-LocalGroupMember (Microsoft.PowerShell.LocalAccounts) - PowerShell. [source](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/add-localgroupmember?view=powershell-5.1)
[^15]: JasonGerend. Resize-Partition (Storage). [source](https://learn.microsoft.com/en-us/powershell/module/storage/resize-partition?view=windowsserver2025-ps)
[^16]: JasonGerend. New-Partition (Storage). [source](https://learn.microsoft.com/en-us/powershell/module/storage/new-partition?view=windowsserver2025-ps)
[^17]: Laxmansingh@twc. What is difference between Partition, Volume and Logical Drive. [source](https://www.thewindowsclub.com/difference-between-partition-volume-logical-drive)
[^18]: Watumull, Garrett. Cluster size recommendations for ReFS and NTFS. [source](https://techcommunity.microsoft.com/blog/filecab/cluster-size-recommendations-for-refs-and-ntfs/425960)
[^19]: JasonGerend. Format-Volume (Storage). [source](https://learn.microsoft.com/en-us/powershell/module/storage/format-volume?view=windowsserver2025-ps)
[^20]: Amanda. What Is Allocation Unit Size & How to Change It - MiniTool Partition Wizard. [source](https://www.partitionwizard.com/partitionmanager/file-allocation-unit-size.html)
[^21]: JasonGerend. Enable-BitLocker (BitLocker). [source](https://learn.microsoft.com/en-us/powershell/module/bitlocker/enable-bitlocker?view=windowsserver2025-ps)


