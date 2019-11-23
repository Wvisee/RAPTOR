#!/usr/bin/python3
import urllib.request
import os

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
                prefix=prefix[0]+"."+prefix[1]+"."+prefix[2]
                if prefix not in listofprefix:
                    listofprefix.append(prefix)
            is_in_block=False
#Write prefix in file iplist.
with open("iplist", "w+") as f:
    for item in listofprefix:
        f.write("%s\n" % item)
os.remove("ip_relay_data")
