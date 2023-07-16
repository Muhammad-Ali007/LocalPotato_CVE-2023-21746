A local privilege escalation (LPE) vulnerability in Windows was reported to Microsoft on September 9, 2022, by Andrea Pierini (@decoder_it) and Antonio Cocomazzi (@splinter_code). The vulnerability would allow an attacker with a low-privilege account on a host to read/write arbitrary files with SYSTEM privileges. 

While the vulnerability in itself wouldn't directly allow executing commands as SYSTEM, we can combine it with several vectors to achieve this result. Conveniently, on February 13, another privilege escalation PoC was published by BlackArrowSec that abuses the StorSvc service, allowing an attacker to execute code as SYSTEM as long as they can write a DLL file to any directory in the PATH.

The LocalPotato PoC takes advantage of a flaw in a special case of NTLM authentication called NTLM local authentication to trick a privileged process into authenticating a session the attacker starts against the local SMB Server. As a result, the attacker ends up having a connection that grants him access to any shares with the privileges of the tricked process, including special shares like C$ or ADMIN$.

The process followed by the exploit is as follows:
- The attacker will trigger a privileged process to connect to a rogue server under his control. This works similarly to previous Potato exploits, where an unprivileged user can force the Operating System into creating connections that use a privileged user (usually SYSTEM).
- The rogue server will instantiate a Security Context A for the privileged connection but won't send it back immediately. Instead, the attacker will launch a rogue client that simultaneously initiates a connection against the local SMB Server (Windows File Sharing) with its current unprivileged credentials. The client will send the Type1 message to initiate the connection, and the server will reply by sending a Type2 message with the ID for a new Security Context B.
- The attacker will swap the Context IDs from both connections so that the privileged process receives the context of the SMB server connection instead of its own. As a result, the Privileged client will associate its user (SYSTEM) with Security Context B of the SMB connection created by the attacker. As a result, the attacker's client can now access any network share with SYSTEM privileges!

By having a privileged connection to SMB shares, the attacker can read or write files to the target machine in any location. While this won't allow us to run commands directly against the vulnerable machine, we will combine this with a different attack vector to achieve that end.

Note that the vulnerability is in the NTLM protocol rather than the SMB Server, so this same attack vector could be theoretically used against any service that leverages authentication through NTLM. In practice, however, some caveats must be dealt with when selecting the protocol to attack. The PoC uses the SMB Server to avoid some extra protections in place for other protocols against similar attack vectors and even implements a quick bypass to get the exploit to work against the SMB Server.
Original exploit author's post - (https://decoder.cloud/2023/02/13/localpotato-when-swapping-the-context-leads-you-to-system/)

So far, we have used LocalPotato to write arbitrary files to the target machine. To get a privileged shell, we still need to figure out how to use the arbitrary write to run a command.

Recently, another privilege escalation vector was found, where an attacker could hijack a missing DLL to run arbitrary commands with SYSTEM privileges. The only problem with this vector was that an attacker would need to write a DLL into the system's PATH to trigger it. By default, Windows PATH will only include directories that only privileged accounts can write. While it might be possible to find machines where the installation of specific applications has altered the PATH variable and made the machine vulnerable, the attack vector only applies to particular scenarios. Combining this attack with LocalPotato allows us to overcome this restriction and have a fully working privilege escalation exploit.


StorSvc and DLL Hijacking
As discovered by BlackArrowSec (https://github.com/blackarrowsec/redteam-research/tree/26e6fc0c0d30d364758fa11c2922064a9a7fd309/LPE via StorSvc), an attacker can send an RPC call to the "SvcRebootToFlashingMode" method provided by the "StorSvc" service, which in turn will end up triggering an attempt to load a missing DLL called "SprintCSP.dll".
If you are not familiar with RPC, think of it as an API that exposes functions so that they can be used remotely. In this case, the StorSvc service exposes the SvcRebootToFlashingMode method, which anyone with access to the machine can call.
Since StorSvc runs with SYSTEM privileges, creating SprintCSP.dll somewhere in the PATH will get it loaded whenever a call to SvcRebootToFlashingMode is made.


Compiling the Exploit
Exploit link - (https://github.com/decoder-it/LocalPotato)
To make use of this exploit, you will first need to compile both of the provided files:
- SprintCSP.dll: This is the missing DLL we are going to hijack. We will need to change the command to run a reverse shell.
- RpcClient.exe: This program will trigger the RPC call to SvcRebootToFlashingMode. Depending on the Windows version you are targeting, you may need to edit the exploit's code a bit, as different Windows versions use different interface identifiers to expose SvcRebootToFlashingMode.
The projects for both files can be found in the directory "LPE via StorSvc".

Let's start by dealing with "RpcClient.exe". As previously mentioned, we will need to change the exploit depending on the Windows version of the target machine. To do this, we will need to change the first lines of "LPE via StorSvc\RpcClient\RpcClient\storsvc_c.c" so that the correct operating system is chosen. This will set the exploit to use the correct RPC interface identifier. Now that the code has been corrected, let's open a developer's command prompt and build the project by running the following command:
Commands:
C:\LPE via StorSvc\RpcClient> msbuild RpcClient.sln
C:\LPE via StorSvc\RpcClient> move x64\Debug\RpcClient.exe C:\Users\user\Desktop\            (The compiled executable will be found on your desktop.)

Now to compile "SprintCSP.dll", we only need to modify the "DoStuff()" function in "C:\LPE via StorSvc\SprintCSP\SprintCSP\main.c" so that it executes a command that grants us privileged access to the machine. For simplicity, we will make the DLL add our current user to the Administrators group. We can also get a reverse shell from that target to our machine.
We now compile the DLL by running the following command and move the result back to our desktop:
Commands:
C:\LPE via StorSvc\SprintCSP> msbuild SprintCSP.sln
C:\LPE via StorSvc\SprintCSP> move x64\Debug\SprintCSP.dll C:\Users\user\Desktop\ 

We are now ready to launch the exploit. Make sure you have the "LocalPotato.exe" exploit, the "RpcClient.exe" and the "SprintCSP.dll" files.

- Let's start by verifying that our current user is not a part of the Administrators group.
- To successfully exploit "StorSvc", we need to copy "SprintCSP.dll" to any directory in the current PATH. We can verify the PATH by running the following command:
C:\> reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -v Path
- We will be targeting the %SystemRoot%\system32 directory, which expands to "C:\windows\system32". You should be able to use any of the directories, however.
- By using LocalPotato, we can copy SprintCSP.dll into system32 even if we are using an unprivileged user:
C:\Users\user\Desktop> LocalPotato.exe -i SprintCSP.dll -o \Windows\System32\SprintCSP.dll
- With our DLL in place, we can now run "RpcClient.exe" to trigger the call to "SvcRebootToFlashingMode", effectively executing the payload in our DLL.
C:\Users\user\Desktop> RpcClient.exe
- To verify if our exploit worked as expected, we can check if our user is now part of the Administrators group.
C:\> net user user


Detection & Mitigation

Detection
Now that we have understood how thelocalpotato exploit works and how it can be chained with StorSrv service to execute code as SYSTEM, it's time to see how this can be detected within the system and how to prevent such attacks.

YARA rule: As this attack involves an executable running in the command line terminal with arguments, two common ways to detect this activity would be by using the pattern matching tool YARA to detect the file patterns and examining the events generated by the execution of this hack tool localpotato.exe. As the attack uses the hack tool known as localpotato.exe, we can create a YARA rule to detect the presence of this tool within the system using YARA or other detection tools like THOR to scan the host.
(YARA rule is appended in this repositor, this minimal rule looks for common string patterns in the localpotato executable.y).

Sigma rule: SIGMA is a generic signature language that is used to write detection rules based on the patterns found in Event Logs. In order to detect localpotato in the network, it is expected to have centralized logs monitoring enabled in place. The following SIGMA rule is taken from the SIGMA official repository (https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_localpotato.yml).

- Detecting LocalPotato (rule is appended in the repository)
- Detecting Storsvc and SprintCSP.dll Hijacking
We learned that the localpotato vulnerability is combined with Storsvc to hijack SprintCSP.dll and execute as the SYSTEM. The following appended SIGMA rule taken from official GitHub can be used to detect this activity.

We can use these sigma rules to convert into the Detection / Monitoring tool in place and search the Event Logs to hunt for potential attacks.

Mitigation
- Patch updates: The localpotato exploit targets a vulnerability in the Windows operating system. Ensure all systems are updated with the latest security patches to prevent attackers from exploiting this vulnerability. This vulnerability does not affect the patched OS.
- Least Privilege Principle: One way to prevent attackers from exploiting the localpotato exploit is to implement the principle of least privilege. This means limiting user access to only the resources they need to perform their job functions. By doing so, attackers are less likely to gain the elevated privileges required to execute the exploit.
- Monitor for suspicious activity: Use tools like "Splunk" to monitor suspicious activity on your network. Look for signs of a localpotato attack, such as unusual process activity or attempts to execute malicious code.