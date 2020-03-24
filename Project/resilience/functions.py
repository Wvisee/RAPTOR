#!/usr/bin/python3
from datetime import datetime
from datetime import timedelta
import os
import urllib.request
import fileinput
import sys
from progress.bar import Bar
import networkx as nx
import matplotlib.pyplot as plt
import ipaddress
import pybgpstream
from random import *

############################################################
#   Download + update tar archives consensus of tor relays #
############################################################

#function to replace a string in file by another one.
def replaceAll(file,searchExp,replaceExp):
    for line in fileinput.input(file, inplace=1):
        if searchExp in line:
            line = line.replace(searchExp,replaceExp)
        sys.stdout.write(line)

def update_tor_archive():
    #load the metadata of the consensuses
    dict_metadata = {}
    metadata = open("tor-consensuses-tar/last_changed", 'r')
    for x in metadata:
        x=x.split(" ")
        if len(x)==3:
            nameoffile=x[0]
            dateofchange=str(x[1]+" "+x[2].replace('\n', ''))
            dict_metadata[nameoffile]=dateofchange
    metadata.close()
    #print(dict_metadata)
    #download consensuces.html which list file by hours of relay information.
    url = 'https://collector.torproject.org/archive/relay-descriptors/consensuses/'
    urllib.request.urlretrieve(url, '../tmp/all-concensuses.html')
    #dowload the consensuses that aren't already downloaded
    f= open("../tmp/all-concensuses.html","r")
    for i in f:
        if "consensuses-20" in i:
            #we take the name of the consensus and the date of the last changed
            name = i.split(">")
            name = str(name[2].split("<")[0])
            date = i.split(" ")
            date = str(date[9]+" "+date[10])
            #print(name+" "+date)
            #we look if consensuses are already donwloaded by checking the metadata, if not we download them
            if name not in dict_metadata:
                print("download "+name+" "+date)
                url2 = 'https://collector.torproject.org/archive/relay-descriptors/consensuses/'+name
                urllib.request.urlretrieve(url2, 'tor-consensuses-tar/'+name)
                #update the metadata
                metadata = open("tor-consensuses-tar/last_changed", 'a')
                metadata.write(name+" "+date+"\n")
                metadata.close()
            if name in dict_metadata:
                if dict_metadata[name] != date:
                    print("update "+name+" "+date)
                    url2 = 'https://collector.torproject.org/archive/relay-descriptors/consensuses/'+name
                    urllib.request.urlretrieve(url2, 'tor-consensuses-tar/'+name)
                    #update the metadata
                    replaceAll("tor-consensuses-tar/last_changed",name+" "+dict_metadata[name],name+" "+date)
    f.close()
    os.remove("../tmp/all-concensuses.html")

##############################################################
#  extract tor ip and put all the possible prefix in hashmap #
##############################################################

def extract_tor_ip(path_of_consensuses):
    list_ip = []
    list_ip6 = []
    is_in_block=False
    has_ip6=False
    ip=0
    ip6=0
    for desc in open(path_of_consensuses,"r"):
        tab=desc.split(' ')
        if tab[0]=='r':
            ip=tab[6]
            is_in_block=True
        if tab[0]=='a' and is_in_block:
            has_ip6=True
            ip6 = tab[1]
        if tab[0]=='s' and is_in_block :
            ok=False
            if "Guard" in tab: ok=True
            if "Exit" in tab: ok=True
            if ok:
                if ip not in list_ip:
                    list_ip.append(ip)
                if has_ip6:
                    if ip6 not in list_ip6:
                        list_ip6.append(ip6)
            is_in_block=False
            has_ip6=False
    return list_ip,list_ip6
    #print(len(list_ip))
    #print(len(list_ip6))

def hash_map_all_prefix(list_ip4_ip6):
    hash_map={}
    list_ipv4 = list_ip4_ip6[0]
    list_ipv6 = list_ip4_ip6[1]
    #IPV4
    for i in list_ipv4:
        for number in range(0,9): #0 to 8
            var = i.split(".")
            addr = var[0]+".0.0.0/"+str(number)
            hash_map[addr]=True
        for number in range(9,17): #9 to 16
            var = i.split(".")
            addr = var[0]+"."+var[1]+".0.0/"+str(number)
            hash_map[addr]=True
        for number in range(17,25): #17 to 24
            var = i.split(".")
            addr = var[0]+"."+var[1]+"."+var[2]+".0/"+str(number)
            hash_map[addr]=True
        for number in range(25,33): #25 to 32
            var = str(i)+"/"+str(number)
            hash_map[var]=True
        #print(hash_map)
        return hash_map
    #IPV6
    #for i in list_ipv6:
    #break

##################################
#   Do a mapping of Internet     #
##################################

def ip_to_binary(ip):
    octet_list_int = ip.split(".")
    octet_list_bin = [format(int(i), '08b') for i in octet_list_int]
    binary = ("").join(octet_list_bin)
    return binary

def prefix_of_tor_relay(prefix,hash_map):
    return (prefix in hash_map)

def link_as_in_graph(ases,G):
    for i in range(len(ases)-1):
        if G.has_edge(ases[i],ases[i+1])==False:
            G.add_edge(ases[i],ases[i+1])

def add_data_to_db(ases,prefix,asn_to_rib):
    tmp = ases.copy()
    for i in ases:
        if not asn_to_rib.get(i):
            asn_to_rib[i]={}
        var = asn_to_rib[i]
        if not var.get(prefix):
            var[prefix]=[]
        if tmp not in var[prefix]:
            var[prefix].append(tmp.copy())
        tmp.remove(i)

def add_data_to_db_one_as(ases,prefix,asn_to_rib):
    tmp = ases.copy()
    i=ases[0]
    if not asn_to_rib.get(i):
        asn_to_rib[i]={}
    var = asn_to_rib[i]
    if not var.get(prefix):
        var[prefix]=[]
    if tmp not in var[prefix]:
        var[prefix].append(tmp)

def delete_data_to_db(prefix,asn_to_rib):
    for i in asn_to_rib:
        if prefix in i:
            i.remove(prefix)

def internet_mapping(hash_map,date):
    #print("Begin of Internet Mapping")
    G = nx.Graph()
    ASN_TO_RIB = {} #dict of dict

    var = date.split("-")
    before = datetime(int(var[0]), int(var[1]), int(var[2]), int(var[3]), int(var[4]), int(var[5]))
    after = datetime(int(var[0]), int(var[1]), int(var[2]), int(var[3]), int(var[4]), int(var[5])) + timedelta(hours=1)

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
                link_as_in_graph(ases,G)
                if prefix_of_tor_relay(prefix,hash_map):
                    add_data_to_db(ases,prefix,ASN_TO_RIB)
        if(elem.type=='W'): #withdraw
            prefix=elem.fields["prefix"]
            if prefix_of_tor_relay(prefix,hash_map):
                delete_data_to_db(prefix,ASN_TO_RIB)
    return G,ASN_TO_RIB
    #print("End of stream")
    #print(ASN_TO_RIB)
    #print(len(G))
    #nx.draw(G, with_labels=True)
    #plt.show()

##############################################
#   Calculate Resilient Score of Tor Relays  #
##############################################

def take_10_random_AS(G):
    lenght = len(G) #number of AS
    list_of_as = []
    count = 0
    if lenght >= 10:
        while count<10:
            t = choice(list(G.nodes()))
            if t not in list_of_as:
                count = count + 1
                list_of_as.append(t)
        return list_of_as
    else:
        for AS in G.nodes():
            list_of_as.append(AS)
        return list_of_as

def is_it_best_route(ases,prefix,DB):
    AS_prefix_list = DB[ases[0]]
    path_list = AS_prefix_list[prefix]
    longest=9999999999999999999 #Normaly no path should be bigger than this.
    for i in path_list:
        if len(i) < longest:
            longest=len(i)
    return longest==len(ases)

#bfs
def advertise_prefix(ases,prefix,Graph,DB):
    #advertise_prefix2(ases,prefix,Graph,DB)
    queue = []     #Initialize a queue
    visited = []
    queue.append([ases[0],ases])
    visited.append(ases[0])

    while queue:
        s = queue.pop(0)
        add_data_to_db_one_as(s[1],prefix,DB)
        for neighbour in Graph.neighbors(s[0]):
            if neighbour not in visited:
                x = ases.copy()
                x.insert(0, neighbour)
                visited.append(neighbour)
                queue.append([neighbour,x])
    return DB

'''
def advertise_prefix2(ases,prefix,Graph,DB):
    add_data_to_db_one_as(ases,prefix,DB)
    if is_it_best_route(ases,prefix,DB):
        for i in Graph.neighbors(ases[0]):
            x = ases.copy()
            x.insert(0, i)
            advertise_prefix2(x,prefix,Graph,DB)
'''

def compute_score(Wrong_AS,prefix,DB2,G):
    #iter on all node to get asn
    #go to table and look which route is prefer
    #in 2 var
    hijacked = 0
    for i in G.nodes():
        if DB2.get(i):
            prefix_list = DB2[i]
            if prefix_list.get(prefix):
                path_list = prefix_list[prefix]
                shortest = 4294967296
                for x in path_list:
                    if len(x) < shortest:
                        shortest=len(x)
                list_path_same_length = []
                for x in path_list:
                    if len(x) == shortest:
                        list_path_same_length.append(x)
                is_hijacked = True
                for x in list_path_same_length:
                    if x[len(x)-1] != Wrong_AS:
                        is_hijacked = False
                if is_hijacked:
                    hijacked=hijacked+1
    return hijacked/len(G)


def computation_resilient_score_tor_relay(graph_db):
    Graph=graph_db[0]
    DB =graph_db[1]
    #get all prefix in a list
    list_prefix_in_DB = []
    for AS in DB:
        for prefix in DB[AS]:
            if prefix not in list_prefix_in_DB:
                list_prefix_in_DB.append(prefix)
    #main
    for prefix in list_prefix_in_DB: #iterate on all prefix (we have to calculate the score for each one of them)
        random_AS_10 = take_10_random_AS(Graph) #take 10 random AS => they will hijack the prefix
        score=0
        for AS in random_AS_10:
            DB2 = advertise_prefix([AS],prefix,Graph,DB.copy())
            score = score + compute_score(AS,prefix,DB2,Graph)
        final_score = score/10
        print("prefix : "+str(prefix)+" , score : "+str(final_score))
