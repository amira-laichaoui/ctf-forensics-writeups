# XWorm Lab – CyberDefenders Blue Team Challenge

## Introduction

This writeup documents my analysis of the **XWorm** malware sample from the CyberDefenders Blue Team Challenge.

The objective of the challenge was to investigate the malware's behavior, including its persistence mechanisms, anti-analysis techniques, encryption, Command and Control (C2) communication, propagation mechanisms, and information-stealing capabilities.


### Q1. What is the compile timestamp (UTC) of the sample?

You can either just directly upload the file into an online malware scanner <span style="color:blue;">**(VirusTotal)**</span> . 

Scroll through details section until you find: 
![Compile timestamp](images/Sans%20titre%203_20260201182618.png)

Otherwise, you can just work locally, using **pefile** a Python module that parses Windows Portable Executable (PE) files that lets you read headers, imports, sections, version info, and more without running the malware. We'll use to retrieve the compile timestamp (UTC) from the PE file metadata.

![PE metadata](images/Screenshot%20from%202025-12-11%2017-28-22.png)
![compilation](images/Screenshot%20from%202025-12-11%2018-38-08.png)

**Answer** : 2024-02-25 22:53

### Q2. Which legitimate company does the malware impersonate in an attempt to appear trustworthy?

![impersonated company](images/Screenshot%20from%202026-08-08%2020-46-21.png)


**Answer** : Adobe

### Q3. How many anti-analysis checks does the malware perform to detect/evade sandboxes and debugging environments?

In the behavior tab, scroll down to the : Dynamic analysis Sandbox Detections where you can notice 5 distinct anti-analysis checks performed by this malware : 

![Scheduled task](images/Screenshot%20from%202026-02-03%2018-44-16.png)

**answer** : 5

### Q4. What is the name of the scheduled task created by the malware to achieve execution with elevated privileges?

In Virustotal, navigate to the Behavior tab and scroll down to the **Processes created** section. Here, we observe the following command executed by the malware:

![Additional screenshot](images/Untitled%20design.png)

The malware uses the legitimate Windows utility schtasks.exe to create a scheduled task with the **'/RL HIGHEST'** option indicationg execution with elevated priviledges. The task name is specified by the **'/tn'** parameter, which is set to **WmiPrvSE**.

**answer** : WmiPrvSE

### Q5. What is the filename of the malware binary that is dropped in the AppData directory?
From the previous screenshot, we can observe that the malware creates a scheduled task that executes the binary located at:

C:\Users\RDhJ0CNFevzX\AppData\Roaming\WmiPrvSE.exe

From this path, we can identify that the malware drops its executable into the AppData\Roaming directory with the filename WmiPrvSE.exe.

**Answer:** WmiPrvSE.exe

### Q6. Which cryptographic algorithm does the malware use to encrypt or obfuscate its configuration data?

I consulted public technical documentation on the XWorm malware family. According to the documentation, XWorm uses the Advanced Encryption Standard (AES) to encrypt its configuration and secure its communications, making static analysis and network inspection more difficult.

**Answer:** AES

Reference: [Deep Dive into New XWorm Campaign Utilizing Multiple-Themed Phishing Emails](https://www.fortinet.com/fr/blog/threat-research/deep-dive-into-new-xworm-campaign-utilizing-multiple-themed-phishing-emails)

### Q7. To derive the parameters for its encryption algorithm (such as the key and initialization vector), the malware uses a hardcoded string as input. What is the value of this hardcoded string?

![hardcoded string](images/Screenshot%20from%202026-08-08%2016-20-32.png)

**Answer:** 8xTJ0EKPuiQsJVaT

### Q8. What are the Command and Control (C2) IP addresses obtained after the malware decrypts them?

The CAPE Sandbox report provided the decrypted malware configuration. In the configuration, the Hosts field contains three IP addresses:

![c2 ips](images/Screenshot%20from%202026-08-08%2016-28-27.png)

The three addresses listed under Hosts correspond to the malware's C2 servers.

**Answer:** 185.117.250.169, 66.175.239.149, 185.117.249.43

### Q9. What port number does the malware use for communication with its Command and Control (C2) server?

![port](images/Screenshot%20from%202026-08-08%2016-33-50.png)

**Answer:** 7000

### Q10. The malware spreads by copying itself to every connected removable device. What is the name of the new copy created on each infected device?

![copy name](images/Screenshot%20from%202026-08-08%2016-44-41.png)

**Answer:** usb.exe

### Q11. To ensure its execution, the malware creates specific types of files. What is the file extension of these created files?

In Virustotal, navigate to the Behavior tab and scroll down to the Files dropped section. We notice several files created by the malware with the extension **'lnk'**. 

![Screenshot from 2026-08-08 21-35-28](<images/Screenshot from 2026-08-08 21-35-28.png>)

**Answer:** lnk

### Q12. What is the name of the DLL the malware uses to detect if it is running in a sandbox environment?

I analyzed the decompiled source code and searched for dll related API calls and references. At line 613, the malware explicitly checks for the presence of SbieDll.dll:

result = ((...("SbieDll.dll").ToInt32() != 0) ? true : false);

![dll](images/Screenshot%20from%202026-08-08%2018-02-29.png)

SbieDll.dll is associated with the Sandboxie sandbox environment according to [the documentation](https://sandboxie-plus.com/sandboxie/injectdll/). This check allows the malware to detect whether it is executing inside Sandboxie and potentially alter its behavior to evade analysis.

**Answer:** SbieDll.dll

### Q13. What is the name of the registry key manipulated by the malware to control the visibility of hidden items in Windows Explorer?

To investigate the registry activity, I searched the decompiled source code for RegistryKey operations:

![regkey](images/Screenshot%20from%202026-08-08%2019-00-46.png)

The relevant code shows that the malware opens the following registry location with write access:

Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced

It then accesses the ShowSuperHidden value and modifies it:

registryKey.GetValue("ShowSuperHidden")
registryKey.SetValue("ShowSuperHidden", 0);

This confirms that the malware manipulates the ShowSuperHidden registry value under the Windows Explorer Advanced settings.

**Answer:** ShowSuperHidden

### Q14. Which API does the malware use to mark its process as critical in order to prevent termination or interference?

I searched online [documentation](https://hackmag.com/malware/windows-critical-process) for commonly used windows native APIs related to critical processes. I found that **RtlSetProcessIsCritical** is a native api function specifically used to mark a process as critical.

![RtlSetProcessIsCritical](images/Screenshot%20from%202026-08-08%2019-59-37.png)

**Answer:** RtlSetProcessIsCritical

### Q15. Which API does the malware use to insert keyboard hooks into running processes in order to monitor or capture user input?

I searched online [documentation](https://dev.to/jaymalli_programmer/keyboard-wizardry-how-to-capture-any-key-press-across-windows-with-c-2c41) for Windows APIs related to keyboard hooks and user input monitoring. I found that **SetWindowsHookEx** is used to establish a hook in the Windows system.

![SetWindowsHookEx](images/Screenshot%20from%202026-08-08%2020-00-36.png)

**Answer:** SetWindowsHookEx

### Q16. Given the malware’s ability to insert keyboard hooks into running processes, what is its primary functionality or objective?

Since the malware is capable of inserting keyboard hooks into running processes, this functionality can be used to monitor and capture user keystrokes. This indicates that the malware implements keylogging functionality, allowing it to record the **user's keyboard input** and potentially capture sensitive information.

**Answer:** Keylogger

## Conclusion

This challenge provided practical experience in analyzing XWorm through behavioral analysis, static analysis, and malware configuration extraction.
