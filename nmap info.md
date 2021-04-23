## Solution Guide: Nmap and Scanning Review Quiz

### Nmap Flag Solutions

Complete the following on your Kali VM in Hyper-V:

- Write an Nmap command to perform a ping sweep of the range `192.168.0.0` to `192.168.0.254`.
    
    **Hint**: Use `-sn`.
    
- Solution: `nmap -sn 192.168.0.0-254`    

- Read about the `--top-ports` feature: <https://danielmiessler.com/blog/nmap-use-the-top-ports-option-for-both-tcp-and-udp-simultaneously/>.

Use `--top-ports` to scan the top 20 ports of scanme.nmap.org. Save the results as `results.txt` file.

- Solution: `nmap --top-ports 20 scanme.nmap.org -oN results.txt`

Use `--top-ports` to scan the top **100** ports of the IP address `192.168.0.10`. Save the results to an XML file.

- Hint: Use `nmap --help`.

- Solution: `nmap --top-ports 100 192.168.0.10 -oX /tmp/top_ports.xml`


### Quiz Solution

1. Which type of hacker is considered unethical?
    - [ ] White Hat
    - [ ] Grey Hat
    - [x] Black Hat
    - [ ] Blue Hat
    
2. What is the main difference between ethical and malicious hackers?
    - [x] Ethical hackers have written permission
    - [ ] Ethical hackers have verbal permission
    - [ ] Ethical hackers don't use real exploits
    - [ ] Malicious hackers never perform information gathering

3. Which type of testing takes place when pentesters have no knowledge of the target network?
    - [ ] Grey Box
    - [x] Black Box
    - [ ] White Box
    - [ ] Blind test

4. Suppose an attacker alters the contents of two files on the server. Which of the following best describes what was compromised?
    - [ ] Authentication
    - [ ] Confidentiality
    - [x] Integrity
    - [ ] Availability
    
5. Which of the following is _not_ a part of information gathering?
    - [ ] Host Discovery
    - [ ] Finding Physical Addresses
    - [ ] Spidering the Client's Website
    - [x] Exploiting a Database Server

6. A SYN Scan is used in which kind of reconnaissance?
    - [x] Active Reconnaissance
    - [ ] Passive Reconnaissance
    - [ ] Open Source Information Gathering
    - [ ] Internal Reconnaissance

7. An ICMP Type 8 message indicates which of the following?
    - [x] Ping Request
    - [ ] Router Advertisement
    - [ ] Host Unreachable Message
    - [ ] TTL Failure

8. Suppose you run a SYN scan against a target host. Which of the following best describes the state of connections to the target machine after the scan?
    - [x] Half-Open
    - [ ] Fully Open
    - [ ] Full Duplex
    - [ ] Half Duplex

9. Which of the following is a Layer 2 attack?
    - [x] ARP Spoofing
    - [ ] SQL Injection
    - [ ] BGP Hijacking
    - [ ] Ping Sweep
    
10. Which of the following Nmap flags is used for OS fingerprinting?
    - [ ] `-oN`
    - [x] `-A`
    - [ ] `-sS`
    - [ ] `-sU`

11. Identify what the following Nmap command does: `nmap -sn 192.168.12.0/24`
    - [ ] Port-Scan all devices in `192.168.12.0/24`
    - [ ] Perform a UDP scan on `192.168.12.0/24`
    - [ ] Service-Scan `192.168.12.0/24`
    - [x] Perform a Ping Sweep on `192.168.12.0/24`

12. Suppose you run the command `nmap -sS -p 22 192.168.12.7`. If port 22 is open, which TCP flag is set on the response?
    - [ ] ACK
    - [x] SYN
    - [ ] RST
    - [ ] URG

13. Which argument will be used for OS detection in Nmap?
    - [ ] `-G`
    - [ ] `-L`
    - [ ] `-S`
    - [x] `-O`  

14. What will the following nmap command accomplish? `nmap -sS -O -p 123,153 192.168.100.4`
    - [ ] A stealth scan, opening port 123 and 153
    - [x] A stealth scan, determine the operating system, and scanning of ports 123 and 153
    - [ ] A stealth scan checking all open ports excluding ports 123 and 153
      
15. Regarding port enumeration, which port does DNS zone transfer use?
    - [ ] UDP port 161
    - [ ] TCP/UDP port 389
    - [ ] TCP port 137
    - [x] TCP port 53  

16. You are sent to scan a remote host using nmap. Which of the following scan types is the BEST choice to gather the most information while minimizing the chance of detection?
    * [ ] TCP connect scan (-sT)
    * [ ] Xmas scan (-sX)
    * [ ] UDP scan (-sU)
    * [x] SYN scan (-sS)  

17. You are asked to access a server at a particular IP address. The server does not respond to ping requests, what could be the reason(s)? Select all the apply.
    * [x] The host is down 
    * [x] Server configured not to respond to ping 
    * [ ] Firewall blocks TCP
    * [x] Firewall blocks ICMP  

18. Which command would you issue to scan all TCP ports on 192.168.1.1?
    * [ ] nmap -p 0,65535 192.168.1.1
    * [ ] nmap -p 1,65536 192.168.1.1
    * [ ] nmap -p 192.168.1.1
    * [x] nmap -p 0-65535 192.168.1.1  

19. Which of the following nmap arguments are used to perform a Null scan:
    * [ ] -sS
    * [ ] -sP
    * [x] -sN  
    * [ ] -sF

20. Most scan attempts can be detected and flagged by:
    * [ ] Proxy
    * [x] IDS 
    * [ ] Router
    * [ ] Switch

21. Which of these scan types in nmap would make a full TCP connection to the target system?
    * [ ] XMAS scan
    * [x] TCP connect scan 
    * [ ] All of these
    * [ ] SYN stealth scan

22. What does the Nmap `-sU` flag do?
    - [ ] Enable OS Scanning
    - [ ] Enable TCP scanning
    - [x] Enable UDP Scanning
    - [ ] Enable Service Scanning

23. Which of the following is also known as a Zombie scan?
    - [ ] SYN Scan
    - [x] IDLE Scan
    - [ ] UDP Scan
    - [ ] Full-Connect Scan

24. Which of the following commands scans both TCP and UDP port 445?
    - [ ] `nmap -sT -sU -p 445 192.168.12.75`
    - [x] `nmap -p U:445,T:445 192.168.12.75`
    - [ ] `nmap -sU -pU 445 -pT 192.168.12.75 `
    - [ ] `nmap -sS --all-protocols 192.168.12.75 `

25. Suppose you discover the following IP addresses on a target network: `192.168.1.24` and `192.168.1.35`. Both machines have a netmask of `255.255.255.0`. Which of the following is true?
    - [x] The machines are on the same subnet.
    - [ ] The machines are on separate subnets.
    - [ ] The machines are unreachable from one another.
    - [ ] Neither machine is running Windows.

26. Which of the following scan types is used to infer firewall rules?
    - [ ] Full Connect Scan
    - [x] ACK Scan
    - [ ] SYN Scan
    - [ ] IDLE Scan

27. Suppose you dump a Linux machine's `/etc/passwd` file during the information gathering phase. You see the lines `/bin/nologin` and `/bin/false` for many users. What does this mean?
    - [ ] These users don't exist.
    - [ ] These users exist, but aren't stored in the database.
    - [x] These users exist, but can't use an interactive shell.
    - [ ] These users exist, but their accounts have been disabled. 

28. Identify one advantage of an IDLE scan.
    - [ ] They allow an attacker to get information about a target's open ports without actually sending packets.
    - [x] They allow an attacker to scan a target without revealing their IP address.
    - [ ] They are undetectable.
    - [ ] They can find all open ports on a machine, including those that are filtered by a firewall.

29. Which of the following commands runs all of Nmap's SMB scripts against a target?
    - [ ] `nmap --smb-all -sV -p 445 192.168.12.17`
    - [ ] `nmap --script --smb-scripts 192.168.12.17`
    - [x] `nmap --script smb-enum-* -sV -p 445 192.168.12.17`
    - [ ] `nmap --script smb-enum-* 192.168.12.17`

---
&copy; 2020 Trilogy Education Services, a 2U Inc Brand.   All Rights Reserved.
