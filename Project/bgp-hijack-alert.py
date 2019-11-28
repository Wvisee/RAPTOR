#!/usr/bin/python3
#import for step 1.
import urllib.request
import os
#import for step 2.
import dns.resolver
import io
from contextlib import redirect_stdout
import json
#import for step 3.
import pybgpstream

############################################################
#1. Take all ip of guard and exit relay => List /24 of these#
############################################################
print("Step 1 Begin")

#download consensuces.html which list file by hours of relay information.
url = 'https://collector.torproject.org/recent/relay-descriptors/consensuses/'
urllib.request.urlretrieve(url, '../Project/consensuces.html')
#find name of last file about relay information.
f= open("consensuces.html","r")
if f.mode == 'r':
    last_line = f.readlines()[-4]
f.close()
last_line = last_line.split('"')[5]
os.remove("consensuces.html")
#download data about current relay running.
url = 'https://collector.torproject.org/recent/relay-descriptors/consensuses/'+last_line
urllib.request.urlretrieve(url, '../Project/ip_relay_data')
#filter file to get all ip prefix of guard/exit relay.
listofprefix = []
reverseprefix = []
with open("ip_relay_data","r") as fin:
    is_in_block=False
    ip=0
    for line in fin:
        tab=line.split(' ')
        if tab[0]=='r':
            ip=tab[6]
            is_in_block=True
        if tab[0]=='s' and is_in_block :
            ok=False
            if "Guard" in tab: ok=True
            if "Exit" in tab: ok=True
            if ok:
                prefix=ip.split('.')
                reverse=prefix[2]+"."+prefix[1]+"."+prefix[0] #necesairy for step 2
                prefix=prefix[0]+"."+prefix[1]+"."+prefix[2]+".0/24"
                if prefix not in listofprefix:
                    listofprefix.append(prefix)
                    reverseprefix.append(reverse)
            is_in_block=False

os.remove("ip_relay_data")

#############################################
#2. Make a Origin Check with Team Cymru tool#
#############################################
print("Step 2 Begin")

prefix_to_AS = {}

for x in reverseprefix:
    output=""
    for rdata in dns.resolver.query(x+'.origin.asn.cymru.com', 'TXT'):
        with io.StringIO() as buf, redirect_stdout(buf):
            print(rdata)
            output = buf.getvalue()
    output=output.split('"')
    output=output[1].split('|') #output[0] = AS that can announce, output[1] = prefix
    AS=str(output[0]).replace(' ', '')
    PREFIX=str(output[1]).replace(' ', '')
    prefix_to_AS[PREFIX] = AS

####################################################
#3. Take a stream of BGP update of prefix of relays#
####################################################

print("Step 3 Begin")

stream = pybgpstream.BGPStream(
    from_time="2008-02-24 18:30:00",until_time="2008-02-24 19:30:00",
    collectors=["route-views.sg", "route-views.eqix"],
    record_type="ribs",
    filter="prefix less "+' '.join(listofprefix)+"" #we filter with the prefix relay
)

for elem in stream:
    # Get the prefix
    pfx = elem.fields["prefix"].replace(' ', '')
    # Get the list of ASes in the AS path
    ases = elem.fields["as-path"].split(" ")
    if len(ases) > 0:
        # Get the origin ASn (rightmost)
        origin = ases[-1].replace(' ', '')
        if pfx in prefix_to_AS:
            good_as=prefix_to_AS[pfx]
            if good_as!=origin:
                print("Prefix ="+pfx+" | Good = "+good_as+" | Real = "+origin)
