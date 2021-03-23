# Penetration Testing /Ethical Hacking


 **Engagement**
- It is the act of hacking into a company's netework after obtaining permission. It has 5 stages

1. Planning and Reconnaissance
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
- SOC("Purple Teaming") Attacker is read, defender- Its red team vs blue team- called purple teaming assessments- The cant an mouse game
- Report writing

## Useful softwares
 - KeepNote to take notes
 - Green shot or flame shot

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
ls -la will reveal hidden folders
ls -la /tmp/  for checking the permissions of the file inside the temp folder
`chmod 777 filename.txt` or chmod +x filename.txt giving full read wrtie access
- `cat /etc/passwd
to change password I can type passwd in the terminal
adding a user to sudoers

ifconfig -linux
iwconfig-wireless
ipconfig-windows

- Network commands
ping
arp -a associating the ip addresses with mac addresses
netstat -ano list all the active connections running on the machine- Is the machine talking to someone else and which ports
- route tells were the traffic exit
ifconfig alternative is ip:
- ip a
- ip n
- ipr

- Updating softwares
-apt update && apt updrage
-apt install python3-pip

- install pimp upgrate from cloning a github repository in the 
- cd /opt
- git clone https://github.com/Dewalt-arch/pimpmykali.git
- ./pimpmykali.sh

ig gedit gives an error then use 
`xhost local:` or `xhost +SI:localuser:root` , the later only fixes the issue for a root user

