#!/usr/bin/python3
import pybgpstream
import datetime
import stem.descriptor.collector
import os
from stem.descriptor import DocumentHandler
import networkx as nx
import matplotlib.pyplot as plt
import ipaddress

##################################
#1. Get list of IP of Tor relays #
##################################
print("Begin listing IP of tor guard and exit relay")

before = datetime.datetime.utcnow() - datetime.timedelta(days= 1 ,minutes = 2)
after = datetime.datetime.utcnow() - datetime.timedelta(days= 1 ,minutes = 1)

list_ip = []
for desc in stem.descriptor.collector.get_consensus(start = before,end=after, document_handler = DocumentHandler.DOCUMENT):
    is_in_block=False
    ip=0
    desc = str(desc).split("\n")
    for line in desc:
        tab=line.split(' ')
        if tab[0]=='r':
            ip=tab[6]
            is_in_block=True
        if tab[0]=='s' and is_in_block :
            ok=False
            if "Guard" in tab: ok=True
            if "Exit" in tab: ok=True
            if ok:
                if ip not in list_ip:
                    list_ip.append(ip)
            is_in_block=False

#print(len(list_ip))
for i in range(len(list_ip)):
    list_ip[i] = ipaddress.ip_address(list_ip[i])


##################################
#2. Do a mapping of Internet     #
##################################
print("Begin of Internet Mapping")

G = nx.Graph()
ASN_TO_RIB = {} #dict of dict

def ip_to_binary(ip):
    octet_list_int = ip.split(".")
    octet_list_bin = [format(int(i), '08b') for i in octet_list_int]
    binary = ("").join(octet_list_bin)
    return binary

def prefix_of_tor_relay(prefix):
    if ":" in prefix: #IPV6
        prefix = ipaddress.IPv6Network(prefix)
    else: #IPV4
        prefix = ipaddress.ip_network(prefix)
    for i in list_ip:
        if i in prefix:
            return True
    return False

def link_as_in_graph(ases):
    for i in range(len(ases)-1):
        if G.has_edge(ases[i],ases[i+1])==False:
            G.add_edge(ases[i],ases[i+1])

def add_data_to_db(ases,prefix):
    tmp = ases.copy()
    for i in ases:
        if not ASN_TO_RIB.get(i):
            ASN_TO_RIB[i]={}
        var = ASN_TO_RIB[i]
        if not var.get(prefix):
            var[prefix]=[]
        if tmp not in var[prefix]:
            var[prefix].append(tmp.copy())
        tmp.remove(i)

def delete_data_to_db(prefix):
    for i in ASN_TO_RIB:
        if prefix in i:
            i.remove(prefix)

before = datetime.datetime.utcnow() - datetime.timedelta(days = 1 ,minutes = 2)
after = datetime.datetime.utcnow() - datetime.timedelta(days= 1 ,minutes = 1)

stream = pybgpstream.BGPStream(
    from_time=str(before),until_time=str(after),
    collectors=["route-views2","route-views3","route-views4","route-views6","route-views.eqix","route-views.isc","route-views.kixp","route-views.jinx","route-views.linx","route-views.telxatl","route-views.wide","route-views.sydney","route-views.saopaulo","route-views.nwax","route-views.perth","route-views.sg","route-views.sfmix","route-views.soxrs","route-views.chicago","route-views.napafrica","route-views.flix","route-views.chile","route-views.amsix","rrc01","rrc02","rrc03","rrc04","rrc05","rrc06","rrc07","rrc08","rrc09","rrc10","rrc11","rrc12","rrc13","rrc14","rrc15","rrc16","rrc18","rrc19","rrc20","rrc21","rrc22","rrc23"],
    record_type="updates",
)

for elem in stream:
    if(elem.type=='A'): #annoucement (BGP update)
        ases = elem.fields["as-path"].split(" ")
        prefix = elem.fields["prefix"]
        if len(ases) > 0:
            link_as_in_graph(ases)
            if prefix_of_tor_relay(prefix):
                add_data_to_db(ases,prefix)
    if(elem.type=='W'): #withdraw
        prefix=elem.fields["prefix"]
        if prefix_of_tor_relay(prefix):
            delete_data_to_db(prefix)

print("End of stream")
#print(ASN_TO_RIB)
print(len(G))
#nx.draw(G, with_labels=True)
#plt.show()

##############################################
# 3. Calculate Resilient Score of Tor Relays #
##############################################

#10 as announce and we calculate the score
