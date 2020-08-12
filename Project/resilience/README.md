# Resilience computation
 ## Explanation

 In this program, we will compute the resilience of Tor relays on BGP hijack. This means the proportion of ASes that will choose the path to the right origin when a malicious AS announce the IP prefix containing the Tor relay.

 We will create a virtual network to represent the internet. We have used networkx. It is an API to create networks. Each node is an AS and each edge is a link between ASes. Finally, each node contains a BGP table with the route that it has learned.

  Each day we will extract the BGP announcement about Tor prefixes find in the BGP archives. We will propagate them inside our virtual network. Now that the network is up-to-date for the day, we will compute the resilience of all Tor relay IP prefixes on BGP hijack as explained in the state of the art of the master thesis in this repository.

  ## Execution

  The program is written in Python 3. It has only been tested on Ubuntu 18.04. It will need to run Bash as several Bash commands are used in the program. Here is the list of all the API used in the program : os, urllib, fileinput, sys, datetime, time, socket, networkx, pickle, errno, copy. It will also need an internet connection.

  This is how you can execute the program:

  ```console
  $ chmod +x resilience.py
  $ ./resilience.py
  ```
