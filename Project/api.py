#!/usr/bin/python3
import datetime
import stem.descriptor.collector
import os
import pybgpstream

##################################
#1. Get list of IP of Tor relays #
##################################
print("Get IP of tor guard and exit relay")

before = datetime.datetime.utcnow() - datetime.timedelta(hours = 5)
after = datetime.datetime.utcnow() - datetime.timedelta(hours = 4)

dict_ip_date = {}
i = 0
for desc in stem.descriptor.collector.get_consensus(start = before,end=after):
    if ("Guard" in desc.flags) or ("Exit" in desc.flags):
        dict_ip_date[desc.fingerprint] = desc
    i=i+1

print(i)
print(len(dict_ip_date))
#############################################
#2. Make a Origin Check with Team Cymru tool#
#############################################
print("Doing the IP-ASN mapping")

prefix_to_AS = {}

file_ip_date = open("tmp/file_ip_date", 'a')
file_ip_date.write("begin\n")
file_ip_date.write("verbose\n")
for fingerprint,desc in dict_ip_date.items():
    file_ip_date.write(desc.address+" "+str(desc.published)+"\n")
file_ip_date.write("end\n")
file_ip_date.close()

os.system("netcat whois.cymru.com 43 < tmp/file_ip_date | sort -n > tmp/file_team_cymru")

file_ip_date = open("tmp/file_team_cymru", 'r')
for x in file_ip_date:
    if x[0]!='B': #look if different than the first line (info about request)
        output = x.split("|")
        prefix_to_AS[str(output[2]).replace(' ','')]=str(output[0]).replace(' ','')

prefix_to_AS.pop('NA', None) #not always found

os.remove("tmp/file_ip_date")
#os.remove("tmp/file_team_cymru")

####################################################
#3. Take a stream of BGP update of prefix of relays#
####################################################
print("Doing an origin check to see BGP hijack")

prefix_to_AS.pop('NA', None) #not always found

stream = pybgpstream.BGPStream(
    from_time=str(before),until_time=str(after),
    collectors=["route-views2"],
    record_type="ribs",
    filter="prefix less "+str(' '.join(list(prefix_to_AS)))+"" #we filter with the prefix relay
)

bgp_hijack_list={}

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
                t=str(pfx+" : "+origin+" : "+good_as)
                print(t)
                if t in bgp_hijack_list:
                    bgp_hijack_list[t]=bgp_hijack_list[t]+1
                else:
                    bgp_hijack_list[t]=1

for x in bgp_hijack_list:
    print(x+" "+str(bgp_hijack_list[x])+" number of time")
