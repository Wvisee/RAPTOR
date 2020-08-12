# BGP hijack monitoring
 ## Explanation

 In this program, we will analyze all the BGP archives obtained over the internet and we will find potential BGP hijack. The archives are accessed via the Route Views Project of the University of Oregon and the Regional Internet registry RIPE NCC.

 We will filter the prefixes in the BGP updates with the ones containing Tor IP addresses. To discover the potential BGP hijack we will do an origin check first. To make this possible, we will use the IP to ASN mapping tool from team Cymru.

 If it isn't the right AS announcing the prefix, we will look at the frequency of this announcement and the time to live of the potential attack. Indeed, an announcement of a prefix by another AS than the origin AS doesn't always mean that is it a BPG hijack. If the BGP announcement seems suspicious we will write it into a file.

  ## Execution

  The program is written in Python 3. It has only been tested on Ubuntu 18.04. It will need to run Bash as several Bash commands are used in the program.
  Here is the list of all the API used in the program : os, urllib, fileinput, sys, datetime, time, socket. It will also need an internet connection.

  This is how you can execute the program:

  ```console
  $ chmod +x monitoring.py
  $ ./monitoring.py
  ```
