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
import subprocess

####################
#  Global Variable #
####################

G = nx.Graph()  #graph of internet
ASN_TO_RIB = {} #dict of dict to store BGP table of ASes

########################
# Management functions #
########################

def clean():
    if len(os.listdir("BGP_Archives")) != 0:
        os.system("rm BGP_Archives/*")
    if len(os.listdir("../tmp")) != 0:
        os.system("rm ../tmp/*")

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

############################################################
#   Return a sorted list of all BGP archives url           #
############################################################

def get_update_bgp_stack_archive():
    x = get_update_bgp_url_RCC()
    #y = get_update_bgp_url_ROUTEVIEW()
    return x

def get_update_bgp_url_RCC():
    #load stack
    load_stack=[]
    f1= open("Data/BGP_url_stack_rcc","r")
    for i in f1:
        load_stack.append(i.rstrip("\n"))
    #get only last line
    f1.close()
    return load_stack
    f1= open("Data/BGP_url_stack_rcc","r")
    #get only last line
    last_line = f1.readlines()[-1]
    f1.close()
    x = last_line.split("/")
    last_date_archive = x[5][8:16]
    last_date_archive_year_month_day = last_date_archive
    last_date_archive_year_month = last_date_archive[0:4]+"."+last_date_archive[4:6]

    #download list of collector
    url = 'https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris/ris-raw-data'
    urllib.request.urlretrieve(url, '../tmp/ripe_ncc_collector.html')

    list_url=[]
    f1= open("../tmp/ripe_ncc_collector.html","r")
    for i in f1:
        if "href=\"http://data.ris.ripe.net/rrc" in i:
            i = i.split("href=\"http://data.ris.ripe.net/rrc")
            z = str(i[1][0])+str(i[1][1])
            url_collector = "http://data.ris.ripe.net/rrc"+z
            urllib.request.urlretrieve(url_collector, '../tmp/ripe_ncc_collector_'+z+'.html')
            f2= open('../tmp/ripe_ncc_collector_'+z+'.html',"r")
            list_of_date=[]
            for l in f2:
                if "href=" in l:
                    var = l.split("href=\"")[1]
                    date = var[0:7]
                    boo = var[0].isdigit()

                    if boo and date>=last_date_archive_year_month:
                        list_of_date.append(date)
            f2.close()
            os.remove('../tmp/ripe_ncc_collector_'+z+'.html')
            list_of_date.sort()
            for date in list_of_date:
                url = 'http://data.ris.ripe.net/rrc'+z+'/'+date+"/"
                urllib.request.urlretrieve(url, '../tmp/ripe_ncc_collector_'+z+'_'+date+'.html')
                f3 = open('../tmp/ripe_ncc_collector_'+z+'_'+date+'.html','r')
                for m in f3:
                    if len(m)==233:
                        if m[84]=="u": #it means that it is an update
                            name_of_archive = m[84:108]
                            name_of_archive2 = name_of_archive[8:16]
                            if name_of_archive2 >= last_date_archive_year_month_day:
                                url = 'http://data.ris.ripe.net/rrc'+z+'/'+date+"/"+name_of_archive
                                list_url.append(url)
                        else:
                            break
                f3.close()
                os.remove('../tmp/ripe_ncc_collector_'+z+'_'+date+'.html')
    f1.close()
    os.remove("../tmp/ripe_ncc_collector.html")

    for i in list_url:
        if i not in load_stack:
            load_stack.append(i)

    load_stack.sort(key = lambda x: x.split("/")[5]) #sort by the name of the archive
    log = open("Data/BGP_url_stack_rcc",'w')
    for i in load_stack:
        log.write(i+"\n")
    log.close()

    return load_stack

#A bug here
def get_update_bgp_url_ROUTEVIEW():

    #load stack
    load_stack=[]
    '''
    f1= open("Data/BGP_url_stack_routeview","r")
    for i in f1:
        load_stack.append(i.rstrip("\n"))
    #get only last line
    f1.close()
    return load_stack
    f1= open("Data/BGP_url_stack_routeview","r")
    #get only last line
    last_line = f1.readlines()[-1]
    f1.close()
    x = last_line.split("/")
    last_date_archive = x[5][8:16]
    last_date_archive_year_month_day = last_date_archive
    last_date_archive_year_month = last_date_archive[0:4]+"."+last_date_archive[4:6]
    '''
    last_date_archive="2007.10"
    last_date_archive_hour="20071027.12"
    #download list of collector
    url = 'http://archive.routeviews.org'
    urllib.request.urlretrieve(url, '../tmp/routeview_collector.html')

    list_url=[]
    f1= open("../tmp/routeview_collector.html","r")
    for i in f1:
        if "<A HREF=\"/" in i:
            i = i.split("\"")
            k = i[1]
            name = i[1].replace("/", "")
            if k == "/ipv6" or k=="/route-views3/bgpdata": #we don't need theses files
                continue
            url_collector = "http://archive.routeviews.org"+k
            urllib.request.urlretrieve(url_collector, '../tmp/routeview_collector'+name+'.html')
            f2= open('../tmp/routeview_collector'+name+'.html',"r")
            list_of_date=[]
            for l in f2:
                if len(l)==211:
                    date = l[80:87]
                    if date>=last_date_archive:
                        list_of_date.append(date)
            f2.close()
            os.remove('../tmp/routeview_collector'+name+'.html')
            list_of_date.sort()
            for date in list_of_date:
                url = "http://archive.routeviews.org"+k+"/"+date+"/UPDATES/"
                urllib.request.urlretrieve(url, '../tmp/routeview_collector'+name+date+'.html')
                f3 = open('../tmp/routeview_collector'+name+date+'.html','r')
                for m in f3:
                    if len(m)==232:
                        name_of_file = m[81:106]
                        url = "http://archive.routeviews.org"+k+"/"+date+"/UPDATES/"+name_of_file
                        list_url.append(url)
                f3.close()
                os.remove('../tmp/routeview_collector'+name+date+'.html')
    f1.close()
    os.remove("../tmp/routeview_collector.html")

    for i in list_url:
        if i not in load_stack:
            load_stack.append(i)

    load_stack.sort(key = lambda x: x.split("/")[6]) #sort by the name of the archive
    log = open("Data/BGP_url_stack_routeview",'w')
    for i in load_stack:
        log.write(i+"\n")
    log.close()

    return load_stack

##############################################################
#  Download bgp archives + delete archives #
##############################################################

def download_bgp_archives(url_stack,date):
    for i in range(len(url_stack)):
        url = url_stack.pop(0)
        date_bgp = url.split(".")
        date_bgp = date_bgp[5]+date_bgp[6][0:2] #ex 2020040700 => 2020 04 07 00(heure)
        date_consensus = date.split("-")
        date_consensus = date_consensus[0]+""+date_consensus[1]+""+date_consensus[2]+""+date_consensus[3]
        if date_bgp<date_consensus:
            continue
        elif date_bgp==date_consensus:
            x = url.split(".")
            urllib.request.urlretrieve(url, 'BGP_Archives/'+x[5]+x[6]+"-"+x[3][4:9]+"."+x[7])
        elif date_bgp>date_consensus:
            url_stack.insert(0,url)
            break

def delete_bgp_archives():
    os.system("rm BGP_Archives/*")

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
    for bgp_archive in os.listdir("BGP_Archives"):
        data = os.popen("bgpdump BGP_Archives/"+bgp_archive).read()
        data = data.split("\n\n") #split in block
        for elem in data:
            elem = elem.split("\n") #split by line
            update = 0
            withdraw = 0
            prefix_list = []
            ases_path = []
            count=0
            for line in elem:
                count=count+1
                if line[0:6]=="ASPATH":
                    ases_path = line.split(" ")
                    ases_path.pop(0)
                    link_as_in_graph(ases_path,G)
                if update or withdraw:
                    prefix_list.append(line[2:len(line)])
                if line[0:9]=="ANNOUNCE":
                    update = 1
                if line[0:9]=="WITHDRAW":
                    withdraw = 1
                if count==len(elem): #end of file
                    for i in prefix_list:
                        if update:
                            if prefix_of_tor_relay(i,hash_map):
                                add_data_to_db(ases_path,i,ASN_TO_RIB)
                        if withdraw:
                            if prefix_of_tor_relay(i,hash_map):
                                delete_data_to_db(i,ASN_TO_RIB)
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

def advertise_prefix2(ases,prefix,Graph,DB):
    add_data_to_db_one_as(ases,prefix,DB)
    if is_it_best_route(ases,prefix,DB):
        for i in Graph.neighbors(ases[0]):
            x = ases.copy()
            x.insert(0, i)
            advertise_prefix2(x,prefix,Graph,DB)

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
    if len(list_prefix_in_DB)==0:
        print("Can't compute score because no BGP announcement about tor relay prefix")
    #main
    for prefix in list_prefix_in_DB: #iterate on all prefix (we have to calculate the score for each one of them)
        random_AS_10 = take_10_random_AS(Graph) #take 10 random AS => they will hijack the prefix
        score=0
        for AS in random_AS_10:
            DB2 = advertise_prefix([AS],prefix,Graph,DB.copy())
            score = score + compute_score(AS,prefix,DB2,Graph)
        final_score = score/10
        print("prefix : "+str(prefix)+" , score : "+str(final_score))
