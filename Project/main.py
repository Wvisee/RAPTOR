#!/usr/bin/python3
#import for step 1
import urllib.request
import os
#import for step 2.
from progress.bar import Bar
#import for step 3.
import pybgpstream

############################################################
#1. Take all ip of guard and exit relay => List /24 of these#
############################################################

#download consensuces.html which list file by hours of relay information.
url = 'https://collector.torproject.org/recent/relay-descriptors/consensuses/'
urllib.request.urlretrieve(url, '../Project/tmp/consensuces.html')
#find name of last file about relay information.
f= open("tmp/consensuces.html","r")
if f.mode == 'r':
    last_line = f.readlines()[-4]
f.close()
last_line = last_line.split('"')[5]
os.remove("tmp/consensuces.html")
#download data about current relay running.
url = 'https://collector.torproject.org/recent/relay-descriptors/consensuses/'+last_line
urllib.request.urlretrieve(url, '../Project/tmp/ip_relay_data')
#filter file to get all ip prefix of guard/exit relay.
dict_ip_date = {}
with open("tmp/ip_relay_data","r") as fin:
    is_in_block=False
    ip=0
    for line in fin:
        tab=line.split(' ')
        if tab[0]=='r':
            date=tab[4]
            hour=tab[5]
            ip=tab[6]
            is_in_block=True
        if tab[0]=='s' and is_in_block :
            ok=False
            if "Guard" in tab: ok=True
            if "Exit" in tab: ok=True
            if ok:
                prefix=ip
                #prefix=ip.split('.')
                #prefix=prefix[0]+"."+prefix[1]+"."+prefix[2]+".0/24"
                if prefix not in dict_ip_date:
                    dict_ip_date[prefix]=date
            is_in_block=False
print("There is "+str(len(dict_ip_date))+" Guard and Exit relays")
os.remove("tmp/ip_relay_data")

#############################################
#2. Make a Origin Check with Team Cymru tool#
#############################################
print("Doing the IP-ASN mapping")

prefix_to_AS = {}

bar = Bar('Processing', max=len(dict_ip_date))
for x in dict_ip_date:
    output = os.popen("whois -h whois.cymru.com \" -v "+x+" "+dict_ip_date[x]+" GMT\"").read()
    output = output.split("\n")
    output = output[1].split("|")
    for z in range(len(output)):
        output[z] = output[z].replace(' ','')
    prefix_to_AS[output[2]]=output[0]
    bar.next()
bar.finish()

####################################################
#3. Take a stream of BGP update of prefix of relays#
####################################################

print("Doing an origin check to see BGP hijack")

#get stream of BGP annoncement between 2 moment : from-time to until-time
from_time=last_line
from_time=from_time.split("-")
from_time=str(from_time[0]+"-"+from_time[1]+"-"+from_time[2]+" "+from_time[3]+":"+from_time[4]+":"+from_time[5])
until_time=last_line
until_time=until_time.split("-")
if (int(until_time[3])+1)>=24:
    until_time[3]="00"
else:
    until_time[3]=str(int(until_time[3])+1)
until_time=str(until_time[0]+"-"+until_time[1]+"-"+until_time[2]+" "+until_time[3]+":"+until_time[4]+":"+until_time[5])

stream = pybgpstream.BGPStream(
    from_time=from_time,until_time=until_time,
    collectors=["route-views.sg", "route-views.eqix"],
    record_type="ribs",
    filter="prefix less "+' '.join(list(prefix_to_AS))+"" #we filter with the prefix relay
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
