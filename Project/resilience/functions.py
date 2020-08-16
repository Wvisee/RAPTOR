#!/usr/bin/python3
from datetime import datetime
from datetime import timedelta
import os
import urllib.request
import fileinput
import sys
import networkx as nx
import matplotlib.pyplot as plt
import ipaddress
from random import *
import subprocess
import time
from socket import error as SocketError
import errno
import pickle
import json
import copy
import gc

####################
#  Global Variable #
####################

G = nx.Graph()  #graph of internet
ASN_TO_RIB = {} #dict of dict to store BGP table of ASes
AS_RELATION= {} #dict containing the AS relation

def init_graph():
    global G
    G = nx.Graph()

def init_db():
    global ASN_TO_RIB
    ASN_TO_RIB = {}

def init_dict_relation():
    global AS_RELATION
    AS_RELATION= {}

########################
# Management functions #
########################

def clean():
    if len(os.listdir("rib")) != 0:
        os.system("rm rib/*")
    if len(os.listdir("../tmp")) != 0:
        os.system("rm ../tmp/*")
    if len(os.listdir("tor-consensuses")) != 0:
        os.system("rm -rf tor-consensuses/*")

def init():
    if not os.path.isdir("tor-consensuses-tar"):
        os.system("mkdir tor-consensuses-tar")
    if not os.path.isfile("tor-consensuses-tar/last_changed"):
        os.system("echo \"\" >> tor-consensuses-tar/last_changed")
    if not os.path.isdir("../tmp"):
        os.system("mkdir ../tmp")
    if not os.path.isdir("tor-consensuses"):
        os.system("mkdir tor-consensuses")
    if not os.path.isdir("rib"):
        os.system("mkdir rib")

#from https://stackoverflow.com/questions/36965507/writing-a-dictionary-to-a-text-file
def dic_to_file(exDict,name="db.txt"):
    with open(name, 'w') as file:
        for i in exDict:
            file.write(i+"-\n")
            file.write(json.dumps(exDict[i])) # use `json.loads` to do the reverse
            file.write("\n")

#########################################################
#  small functions that help making the code clearer    #
#########################################################

def download_file(url,path):
    try:
        urllib.request.urlretrieve(url, path)
    except SocketError as e:
        download_file(url,path)

def get_list_of_files_sorted_in_directory(dir):
    list=[]
    for filename in os.listdir(str(dir)):
        list.append(filename)
    list.sort()
    return list

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
    download_file(url,'../tmp/all-concensuses.html')
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
                if name == "consensuses-2007-10.tar.xz": #We don't take the first consensus has we are only interested in first day of the month (here we start the 27)
                    continue
                print("download "+name+" "+date)
                url2 = 'https://collector.torproject.org/archive/relay-descriptors/consensuses/'+name
                download_file(url2,'tor-consensuses-tar/'+name)
                #update the metadata
                metadata = open("tor-consensuses-tar/last_changed", 'a')
                metadata.write(name+" "+date+"\n")
                metadata.close()
            if name in dict_metadata:
                if dict_metadata[name] != date:
                    print("update "+name+" "+date)
                    url2 = 'https://collector.torproject.org/archive/relay-descriptors/consensuses/'+name
                    download_file(url2,'tor-consensuses-tar/'+name)
                    #update the metadata
                    replaceAll("tor-consensuses-tar/last_changed",name+" "+dict_metadata[name],name+" "+date)
    f.close()
    os.remove("../tmp/all-concensuses.html")

############################################################
#   Return a sorted list of all BGP archives url           #
############################################################

def DOWNLOAD_RIB(date):
    print("Download RIB RCC")
    Download_RIB_RCC(date)

def Download_RIB_RCC(date_asked):
    list_url = []
    url = 'https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris/ris-raw-data'
    download_file(url,'../tmp/ripe_ncc_collector.html')
    f1= open("../tmp/ripe_ncc_collector.html","r")
    for i in f1:
        if "href=\"http://data.ris.ripe.net/rrc" in i:
            i = i.split("href=\"http://data.ris.ripe.net/rrc")
            z = str(i[1][0])+str(i[1][1])
            url_collector = "http://data.ris.ripe.net/rrc"+z
            download_file(url_collector,'../tmp/ripe_ncc_collector_'+z+'.html')
            f3= open('../tmp/ripe_ncc_collector_'+z+'.html',"r")
            #we will look at all month >= 2007.10
            for l in f3:
                if len(l)==197:
                    date = l[90:97]
                    if date == date_asked:
                        url_collector = "http://data.ris.ripe.net/rrc"+z+"/"+date+"/"
                        download_file(url_collector,'../tmp/ripe_ncc_collector_'+z+'_'+date+'.html')
                        f2= open('../tmp/ripe_ncc_collector_'+z+'_'+date+'.html',"r")
                        for m in f2:
                            if len(m)==229:
                                if m[84]=="b": #it means that it is an bview rib
                                    name_of_archive = m[84:106]
                                    name_of_archive2 = name_of_archive[6:14]
                                    date_without_point = date.replace('.', '')
                                    if name_of_archive2 == (date_without_point+"01"):
                                        url = "http://data.ris.ripe.net/rrc"+z+"/"+date+"/"+name_of_archive
                                        list_url.append(url)
                                        year = date_without_point[0:4]
                                        month = date_without_point[4:6]
                                        print("download file rcc"+z+" "+year+"/"+month+"/"+name_of_archive)
                                        download_file(url,'rib/'+year+"_"+month+"_"+z+"_"+name_of_archive)
                        f2.close()
            f3.close()
    f1.close()

##############################################################
#           Get archives of relation AS by Caida             #
##############################################################

def get_url_archives_relation_as():
    list=[]
    #download as_relationships.html which list all archives by month os AS relation.
    url = 'http://data.caida.org/datasets/as-relationships/serial-1/'
    download_file(url,'../tmp/as_relationships.html')
    #dowload all archives available
    f= open("../tmp/as_relationships.html","r")
    for i in f:
        if len(i)==135:
            name = i[52:75]
            date = name[0:6]
            if date >= "200711": #beginning of Tor network
                url_of_archive = 'http://data.caida.org/datasets/as-relationships/serial-1/'+name
                list.append(url_of_archive)
    f.close()
    os.remove("../tmp/as_relationships.html")
    list.sort()
    return list

def add_as_relation_archive_to_dict(url_of_as_relation_archive):
    init_dict_relation() #initialize AS_RELATION to empty
    download_file(url_of_as_relation_archive,'../tmp/as_relation_archive.bz2')
    os.system("bzip2 -d ../tmp/as_relation_archive.bz2")
    f = open("../tmp/as_relation_archive","r")
    for i in f:
        if i[0].isdigit():
            i = i.split("|")
            AS1 = i[0]
            AS2 = i[1]
            Relation = int(i[2].rstrip())
            if not AS_RELATION.get(AS1):
                AS_RELATION[AS1]={}
                dict = AS_RELATION[AS1]
                dict[1] = []
                dict[0] = []
                dict[-1] = []
            if not AS_RELATION.get(AS2):
                AS_RELATION[AS2]={}
                dict = AS_RELATION[AS2]
                dict[1] = []
                dict[0] = []
                dict[-1] = []
            dict_as1 = AS_RELATION[AS1]
            dict_as1[Relation].append(AS2)
            dict_as2 = AS_RELATION[AS2]
            dict_as2[-Relation].append(AS1)

def init_as_relation_in_dict(filename,url_relation_as):
    init_dict_relation()
    print("AS RELATION BEFORE = "+str(len(AS_RELATION)))
    #pop first elem of AS-relation and look if if is the good date => launch a function that translate the archives into dic
    month_consensuses = filename[12:19]
    as_relation_url = url_relation_as.pop(0)
    as_relation_month = as_relation_url[57:61]+"-"+as_relation_url[61:63]
    if month_consensuses==as_relation_month:
        print("AS relation date = "+str(as_relation_url))
        add_as_relation_archive_to_dict(as_relation_url)
    else:
        #no data about as relation this month => we will use the one of previous month
        #we reinsert the url at the begin of the stack for the next right month
        url_relation_as.insert(0,as_relation_url)
    print("AS RELATION AFTER = "+str(len(AS_RELATION)))


##############################################################
#  add rib to G and db to Initialize the virtual internet    #
##############################################################

def add_rib_of_collector_to_db(prefix_hash_map):

    init_graph()
    init_db()

    print("G BEFORE = "+str(len(G)))
    print("DB BEFORE = "+str(len(ASN_TO_RIB)))

    print("Graph")
    create_graph()

    print("Extract from BGP archives RIB prefix announced by AS")
    announcement_list,withdraw_list = extract_as_prefix_from_bgp_archives(prefix_hash_map,"rib")

    print("Initialize vitual network with RIBs")
    advertise_all_prefix(announcement_list.copy(),withdraw_list)

    print("G AFTER = "+str(len(G)))
    print("DB AFTER = "+str(len(ASN_TO_RIB)))

    return announcement_list

def create_graph():
    for i in AS_RELATION:
        link = i.split("-")
        link_as_in_graph(link,G)

##############################################################
#  extract tor ip and put all the possible prefix in hashmap #
##############################################################

def extract_tor_ip(path_of_consensuses):
    list_ip = []
    is_in_block=False
    ip=0
    for desc in open(path_of_consensuses,"r"):
        tab=desc.split(' ')
        if tab[0]=='r':
            ip=tab[6]
            is_in_block=True
        if tab[0]=='s' and is_in_block :
            if "Guard" in tab or "Exit" in tab:
                if ip not in list_ip:
                    list_ip.append(ip)
            is_in_block=False
    return list_ip

def hash_map_all_prefix(list_ip4):
    hash_map={}
    #IPV4
    for i in list_ip4:
        for number in range(17,25): #17 to 24
            var = i.split(".")
            addr = var[0]+"."+var[1]+"."+var[2]+".0/"+str(number)
            hash_map[addr]=i
    return hash_map

##################################
#   Do a mapping of Internet     #
##################################

def ip_to_binary(ip):
    octet_list_int = ip.split(".")
    octet_list_bin = [format(int(i), '08b') for i in octet_list_int]
    binary = ("").join(octet_list_bin)
    return binary

def prefix_of_tor_relay(prefix,hash_map):
    return hash_map.get(prefix) #O(1) complexity
    # (prefix in hash_map) O(N) complexity

def link_as_in_graph(ases,G):
    for i in range(len(ases)-1):
        if G.has_edge(ases[i],ases[i+1])==False:
            if ases[i]!=ases[i+1]:#we don't link one as with itself
                G.add_edge(ases[i],ases[i+1])

def add_data_to_db_one_as(ases,prefix,DB):
    AS = ases[0]
    if not DB.get(AS):
        DB[AS]={}
    var = DB[AS]
    if not var.get(prefix):
        var[prefix]=[]
    if ases not in var[prefix]:
        var[prefix].append(ases)

def delete_path_to_db(path,prefix,DB):
    AS = path[0]
    table = DB[AS]
    path_list = table[prefix]
    path_list.remove(path)

def delete_data_to_db(AS,prefix,asn_to_rib):
    for i in asn_to_rib:
        if prefix in i:
            list_path = i.get(prefix)
            for path in list_path:
                if path[len(path)-1]==AS:
                    list_path.remove(path)

def extract_as_prefix_from_bgp_archives(hash_map,dir):
    announcement_list = []
    withdraw_list = []
    count = 0
    for bgp_archive in os.listdir(dir):
        print(count)
        count += 1
        data = os.popen("python Programs/mrt2bgpdump.py "+dir+"/"+bgp_archive).read()
        data = str(data).split("\n")
        for elem in data:
            elem=elem.split("|")
            if elem[0]=='': #empty list
                continue
            #time = elem[1]
            type = elem[2]
            if type!="W":
                as_path = elem[6]
            annoucer = elem[3]
            as_nb = elem[4]
            prefix = elem[5]
            if type=="W":
                if prefix_of_tor_relay(prefix,hash_map):
                    if str(as_nb+"-"+prefix) in announcement_list:
                        announcement_list.remove(str(as_nb+"-"+prefix))
                    elif str(as_nb+"-"+prefix) not in withdraw_list:
                            withdraw_list.append(str(as_nb+"-"+prefix))
            elif type=="A" or type=="B":
                as_path = as_path.split(" ")
                announcer = as_path[len(as_path)-1]
                link_as_in_graph(as_path,G)
                if prefix_of_tor_relay(prefix,hash_map):
                    if str(announcer+"-"+prefix) in withdraw_list:
                        withdraw_list.remove(str(announcer+"-"+prefix))
                        if str(announcer+"-"+prefix) not in announcement_list:
                            announcement_list.append(str(announcer+"-"+prefix))
                    elif str(announcer+"-"+prefix) not in announcement_list:
                        announcement_list.append(str(announcer+"-"+prefix))
    return announcement_list,withdraw_list

def advertise_all_prefix(announcement_list,withdraw_list):
    for i in announcement_list:
        print(i)
        i = i.split("-")
        AS = i[0]
        Prefix = i[1]
        start_time = time.time()
        advertise_prefix_new([AS],Prefix,G,ASN_TO_RIB)
        print(" --- %s seconds ---" % (time.time() - start_time))

##############################################
#   Calculate Resilient Score of Tor Relays  #
##############################################

def take_200_random_AS(G,True_AS):
    lenght = len(G) #number of AS
    list_of_as = []
    count = 0
    if lenght >= 100:
        while count<100:
            t = choice(list(G.nodes()))
            if t not in list_of_as and t not in True_AS:
                count = count + 1
                list_of_as.append(t)
        return list_of_as
    else:
        for AS in G.nodes():
            list_of_as.append(AS)
        return list_of_as

def advertise_prefix_new(ases,prefix,Graph,DB):
    already_announce={}
    queue = []     #Initialize a queue
    queue.append(ases)
    while queue:
        path = queue.pop(0)
        AS = path[0]
        add_data_to_db_one_as(path,prefix,DB)
        if BGP_PROCESS_is_best(path,prefix,DB):
            for neighbour in Graph.neighbors(AS):
                if len(path) > 1 and neighbour==path[1]: #we don't send update to the as that send us the update
                    continue
                if str(AS+"-"+neighbour) in already_announce:
                    continue
                already_announce[str(AS+"-"+neighbour)]=1
                x = path.copy()
                x.insert(0, neighbour)
                queue.append(x)
    return DB

def BGP_PROCESS_is_best(path,prefix,DB):
    i = path[0]
    if DB.get(i):
        prefix_list = DB[i]
        if prefix_list.get(prefix):
            path_list = prefix_list[prefix]
            if len(path_list)==1: # we just add a path to the db, if the len==1 it is the only one so it's TRUE
                return True
            best_relation_path = get_best_relation_path(path_list.copy(),i)
            if len(best_relation_path)==0:
                print("error best_relation_path = 0")
            elif len(best_relation_path)==1:
                if (path not in best_relation_path):
                    delete_path_to_db(path,prefix,DB)
                    return False
                elif (path in best_relation_path):
                    path_list.copy().remove(path)
                    old_path = path_list[0]
                    delete_path_to_db(old_path,prefix,DB)
                    return True
                else:
                    print("error")
            elif len(best_relation_path)==2:
                best_relation_path.remove(path)
                old_path = best_relation_path[0] #we get the other path in the DB
                if len(path)<len(old_path):
                    delete_path_to_db(old_path,prefix,DB)
                    return True
                elif len(path)>len(old_path):
                    delete_path_to_db(path,prefix,DB)
                    return False
                else:
                    delete_path_to_db(old_path,prefix,DB)
                    return True
            else:
                print("error : best_relation_path length is "+str(len(best_relation_path)))

def get_best_relation_path(path_list,AS):
    if AS_RELATION.get(AS):
        x = AS_RELATION[AS]
        customer_list = []
        peer_list = []
        provider_list = []
        not0 = True
        not1 = True
        for i in path_list:
            if len(i)==1:
                return [i]
            neighbor = i[1]
            if neighbor in x[-1]:
                customer_list.append(i)
                not0 = False
                not1 = False
            elif not0 and neighbor in x[0]:
                peer_list.append(i)
                not1 = False
            elif not1 and neighbor in x[1]:
                provider_list.append(i)
        if len(customer_list)>0:
            return customer_list
        if len(peer_list)>0:
            return peer_list
        if len(provider_list)>0:
            return provider_list
        return path_list
    else: #no data about AS relations
        return path_list

def compute_score(Wrong_AS,prefix,DB2,G,True_AS_list):
    #iter on all node to get asn
    #go to table and look which route is prefer
    #in 2 var
    hijacked = 0
    count = 0
    wtf_count= 0
    for i in G.nodes():
        if i not in True_AS_list:
            if DB2.get(i):
                prefix_list = DB2[i]
                if prefix_list.get(prefix):
                    count += 1
                    path_list = prefix_list[prefix]

                    true_path = 0
                    false_path = 0
                    if len(path_list) > 1:
                        print("path_list > 1")
                    path = path_list[0]
                    as_announcing = path[-1]
                    if as_announcing==Wrong_AS:
                        #print("Wrong")
                        false_path += 1
                        score = true_path/(false_path+true_path)
                        hijacked += score
                    elif as_announcing in True_AS_list:
                        #print("True")
                        true_path += 1
                        score = true_path/(false_path+true_path)
                        hijacked += score
                    else:
                        print("error")
                        print("count = "+str(count)+" / wtf_count = "+str(wtf_count))
                        print("as_choosen = "+str(as_announcing)+" / "+"Wrong_AS = "+str(Wrong_AS)+" / "+"True_AS_list = "+str(True_AS_list))
                        #dic_to_file(DB2)
                        exit()
                        wtf_count+=1
    return hijacked/count


def computation_resilient_score_tor_relay(announcement_list,hash_map):
    #get all prefix in a list
    dict_prefix_as_annoucing = {}
    for i in announcement_list:
        x = i.split("-")
        if dict_prefix_as_annoucing.get(x[1]): #if the prefix is announce by 2 AS we store the 2 AS for the prefix in a list
            dict_prefix_as_annoucing[x[1]].append(x[0])
        else:
            dict_prefix_as_annoucing[x[1]] = [x[0]]
    if len(announcement_list)==0:
        result = open("output",'a')
        result.write("Computation not possible\n")
        result.close()
    #main
    store_score = {}

    store_list_random_as = {}
    for prefix in dict_prefix_as_annoucing:
        True_AS = dict_prefix_as_annoucing[prefix]
        random_AS_200 = take_200_random_AS(G,True_AS) #take 10 random AS => they will hijack the prefix
        #print(len(random_AS_200)) #100
        store_list_random_as[prefix] = random_AS_200

    global ASN_TO_RIB
    pickle.dump(ASN_TO_RIB, open("ASN_TO_RIB.p", "wb" ))
    ASN_TO_RIB = 0
    gc.collect()

    for i in range(0,100):
        print("--- Prefix n°"+str(i))
        #DB_hijacked = copy.deepcopy(ASN_TO_RIB)
        DB_hijacked = pickle.load( open("ASN_TO_RIB.p", "rb" ) )
        for prefix in dict_prefix_as_annoucing: #Graph.nodes():
            AS = store_list_random_as[prefix].pop() #list goes down ok
            True_AS = dict_prefix_as_annoucing[prefix]
            if AS in True_AS:
                print("error : AS==True_AS")
            #print(AS)
            #print(True_AS)
            advertise_prefix_new([AS],prefix,G,DB_hijacked)
            score = compute_score(AS,prefix,DB_hijacked,G,True_AS)
            if not store_score.get(str(prefix)):
                #print("error : computation_resilience")
                store_score[str(prefix)] = {}
            as_to_score = store_score[str(prefix)]
            as_to_score[AS] = score
        DB_hijacked = 0
        gc.collect()
    result = open("output",'a')
    for prefix in store_score:
        score = 0
        for AS in store_score[prefix]:
            as_to_score = store_score[str(prefix)]
            score = score + as_to_score[AS]
        final_score = score/100
        result.write(str(dict_prefix_as_annoucing[prefix])+" "+str(hash_map[prefix])+" "+str(str(prefix))+" "+str(final_score)+"\n")
    result.close()

def get_true_as_from_prefix(prefix):
    #print(prefix)
    x = prefix.split("/")
    #print(x)
    x = x[0].split(".")
    #print(x)
    line = os.popen("dig +short "+x[3]+"."+x[2]+"."+x[1]+"."+x[0]+".peer.asn.cymru.com TXT").read()
    if line == "":
        return []
    #print(line)
    line = line.split("\"")
    #print(line)
    line = line[1].split("|")
    #print(line)
    line = line[0].split(" ")
    #print(line)
    while("" in line) :
        line.remove("")
    #print(line)
    return line
