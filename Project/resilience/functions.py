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
from random import *
import subprocess
import time
from socket import error as SocketError
import errno
import pickle

####################
#  Global Variable #
####################

G = nx.Graph()  #graph of internet
ASN_TO_RIB = {} #dict of dict to store BGP table of ASes
AS_RELATION= {}

def init_dict_relation():
    AS_RELATION= {}

########################
# Management functions #
########################

def clean():
    if len(os.listdir("BGP_Archives")) != 0:
        os.system("rm BGP_Archives/*")
    if len(os.listdir("../tmp")) != 0:
        os.system("rm ../tmp/*")

def init():
    if not os.path.isdir("tor-consensuses-tar"):
        os.system("mkdir tor-consensuses-tar")
    if not os.path.isfile("tor-consensuses-tar/last_changed"):
        os.system("echo \"\" >> tor-consensuses-tar/last_changed")
    if not os.path.isdir("../tmp"):
        os.system("mkdir ../tmp")
    if not os.path.isdir("BGP_Archives"):
        os.system("mkdir BGP_Archives")
    if not os.path.isdir("Data"):
        os.system("mkdir Data")
    if not os.path.isfile("Data/BGP_url_stack_rcc"):
        os.system("echo \"\" >> Data/BGP_url_stack_rcc")
    if not os.path.isfile("Data/BGP_url_stack_routeview"):
        os.system("echo \"\" >> Data/BGP_url_stack_routeview")
    if not os.path.isfile("Data/BGP_url_stack_routeview_history_download_archive"):
        os.system("echo \"\" >> Data/BGP_url_stack_routeview_history_download_archive")
    if not os.path.isdir("tor-consensuses"):
        os.system("mkdir tor-consensuses")

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

def get_update_bgp_stack_archive():
    print("Update rcc url stack")
    x = get_update_bgp_url_RCC()
    print("Update routeview url stack")
    y = get_update_bgp_url_ROUTEVIEW()
    return x,y

def get_update_bgp_url_RCC():
    #load stack
    load_stack=[]
    f1= open("Data/BGP_url_stack_rcc","r")
    for i in f1:
        load_stack.append(i.rstrip("\n"))
    #get only last line
    f1.close()
    #return load_stack
    f1= open("Data/BGP_url_stack_rcc","r")
    #get only last line
    last_line = f1.readlines()[-1]
    f1.close()
    if os.path.getsize("Data/BGP_url_stack_rcc")>1:
        x = last_line.split("/")
        last_date_archive = x[5][8:16]
        last_date_archive_year_month_day = last_date_archive
        last_date_archive_year_month = last_date_archive[0:4]+"."+last_date_archive[4:6]
    else:
        last_date_archive = "20071027" #creation of Tor network
        last_date_archive_year_month_day = "20071027"
        last_date_archive_year_month = "2007.10"


    #download list of collector
    url = 'https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris/ris-raw-data'
    download_file(url,'../tmp/ripe_ncc_collector.html')

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
                download_file(url,'../tmp/ripe_ncc_collector_'+z+'_'+date+'.html')
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
        load_stack.append(i)
    load_stack = list(dict.fromkeys(load_stack)) #delete duplicate element

    for i in load_stack:
        if i=="":
            load_stack.remove(i)

    load_stack.sort(key = lambda x: x.split("/")[5]) #sort by the name of the archive
    log = open("Data/BGP_url_stack_rcc",'w')
    for i in load_stack:
        log.write(i+"\n")
    log.close()

    return load_stack

def get_update_bgp_url_ROUTEVIEW():

    #load stack
    load_stack=[]
    f1= open("Data/BGP_url_stack_routeview","r")
    for i in f1:
        load_stack.append(i.rstrip("\n"))
    #get only last line
    f1.close()
    #return load_stack
    dict={}
    if os.path.getsize("Data/BGP_url_stack_routeview_history_download_archive")>1:
        f1= open("Data/BGP_url_stack_routeview_history_download_archive","r")
        #get only last line
        for i in f1:
            i = i.split(" ")
            dict[i[0]]=i[1].replace("\n","")
        f1.close()

    #download list of collector
    url = 'http://archive.routeviews.org'
    download_file(url,'../tmp/routeview_collector.html')

    list_url=[]
    f1= open("../tmp/routeview_collector.html","r")
    for i in f1:
        if "<A HREF=\"/" in i:
            i = i.split("\"")
            k = i[1]
            name = i[1].replace("/", "")
            if k == "/ipv6" or k=="/route-views3/bgpdata" or k=="/route-views6/bgpdata": #we don't need theses files
                continue
            url_collector = "http://archive.routeviews.org"+k
            download_file(url_collector,'../tmp/routeview_collector'+name+'.html')
            f2= open('../tmp/routeview_collector'+name+'.html',"r")
            list_of_date=[]
            for l in f2:
                if len(l)==211:
                    date = l[80:87]
                    if dict.get(k):
                        if date>=dict[k]:
                            list_of_date.append(date)
                        if date>dict[k]:
                            dict[k]=date
                    else:
                        if date>="2007.10": #creation of Tor network
                            list_of_date.append(date)
                        if date>"2007.10":
                            dict[k]=date
            f2.close()
            os.remove('../tmp/routeview_collector'+name+'.html')
            list_of_date.sort()
            for date in list_of_date:
                url = "http://archive.routeviews.org"+k+"/"+date+"/UPDATES/"
                download_file(url,'../tmp/routeview_collector'+name+date+'.html')
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

    #update history_download_archive
    f1= open("Data/BGP_url_stack_routeview_history_download_archive","w")
    #get only last line
    for i in dict:
        f1.write(i+" "+dict[i]+"\n")
    f1.close()

    for i in list_url:
        load_stack.append(i)
    load_stack = list(dict.fromkeys(load_stack)) #delete duplicate element

    for i in load_stack:
        if i=="":
            load_stack.remove(i)

    load_stack.sort(key = lambda x: x.split("/")[-1]) #sort by the name of the archive
    log = open("Data/BGP_url_stack_routeview",'w')
    for i in load_stack:
        log.write(i+"\n")
    log.close()

    return load_stack

##############################################################
#  Download bgp archives + delete archives #
##############################################################

def download_bgp_archives(url_stack,date):
    print("Download rcc archives")
    download_bgp_archives_rcc(url_stack[0],date)
    print("Download routeview archives")
    download_bgp_archives_routeview(url_stack[1],date)

def download_bgp_archives_rcc(url_stack,date):
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
            download_file(url,'BGP_Archives/'+x[5]+x[6]+"-"+x[3][4:9]+"."+x[7])
        elif date_bgp>date_consensus:
            url_stack.insert(0,url)
            break

def download_bgp_archives_routeview(url_stack,date):
    for i in range(len(url_stack)):
        url = url_stack.pop(0)
        date_bgp = url.split("/")
        if date_bgp[3]=="bgpdata": #or date_bgp[3]=="route-views6": #doesn't seems to be real bgp update data
            continue
        date_url = date_bgp[-1]
        date_url = date_url.split(".")
        date_url = date_url[1]+""+date_url[2][0:2] #date_url

        date_consensus = date.split("-")
        date_consensus = date_consensus[0]+""+date_consensus[1]+""+date_consensus[2]+""+date_consensus[3] #date_consensus

        url_before = url.split("/")
        result=""
        for k in range(len(url_before)-1):
            result= result+url_before[k]+"/"
        path = "../tmp/"+str(url_before[3])+"_"+str(url_before[4])+"_"+str(url_before[5])
        if not os.path.isfile(path):
            download_file(result,path)

        if date_url<date_consensus:
            f1=open(path,"r")
            lines = f1.readlines()
            for nb in range(0, len(lines)):
                if len(lines[nb])==232:
                    name_of_file = lines[nb][81:106]
                    if name_of_file==url_before[-1]:
                        if len(lines[nb+1])==232:
                            date_of_file = lines[nb+1][81:106]
                            date_of_file = date_of_file.split(".")
                            date_of_file = date_of_file[1]+""+date_of_file[2][0:2]
                            if date_of_file==date_consensus:
                                download_file(result,'BGP_Archives/'+""+str(url_before[3])+"_"+str(url_before[4])+"_"+str(url_before[5])+"_"+str(url_before[-1]))
            f1.close()
        elif date_url==date_consensus:
            download_file(url,'BGP_Archives/'+""+str(url_before[3])+"_"+str(url_before[4])+"_"+str(url_before[5])+"_"+str(url_before[-1]))
        else:
            break

def delete_bgp_archives():
    os.system("rm BGP_Archives/*")

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
            if date >= "200710": #beginning of Tor network
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
    #pop first elem of AS-relation and look if if is the good date => launch a function that translate the archives into dic
    month_consensuses = filename[12:19]
    as_relation_url = url_relation_as.pop(0)
    as_relation_month = as_relation_url[57:61]+"-"+as_relation_url[61:63]
    if month_consensuses==as_relation_month:
        add_as_relation_archive_to_dict(as_relation_url)
    else:
        #no data about as relation this month => we will use the one of previous month
        #we reinsert the url at the begin of the stack for the next right month
        url_relation_as.insert(0,as_relation_url)

##############################################################
#  add rib to G and db to Initialize the virtual internet    #
##############################################################

def add_rib_of_collector_to_db(hash_map):
    '''
    print("Download")
    download_rib_of_collector_of_tor_begin()
    print("Graph")
    create_graph()
    print("Add to db")
    add_ribs_to_db(hash_map)
    print("save asnrib")
    pickle.dump(ASN_TO_RIB, open( "ASN_TO_RIB.p", "wb" ))
    print("save graph")
    nx.write_gpickle(G, "G.p")
    '''
    global ASN_TO_RIB
    ASN_TO_RIB = pickle.load( open( "ASN_TO_RIB.p", "rb" ) )
    global G
    G = nx.read_gpickle("G.p")

def download_rib_of_collector_of_tor_begin():

    list_metadata = []
    metadata = open("RIB_2007_10_27/history", 'r')
    for x in metadata:
        list_metadata.append(x.rstrip("\n"))
    metadata.close()

    list_url=[]
    #rrc
    url = 'https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris/ris-raw-data'
    download_file(url,'../tmp/ripe_ncc_collector.html')
    f1= open("../tmp/ripe_ncc_collector.html","r")
    for i in f1:
        if "href=\"http://data.ris.ripe.net/rrc" in i:
            i = i.split("href=\"http://data.ris.ripe.net/rrc")
            z = str(i[1][0])+str(i[1][1])

            #look if 2007.10 is in collector
            url_collector = "http://data.ris.ripe.net/rrc"+z
            download_file(url_collector,'../tmp/ripe_ncc_collector_'+z+'.html')
            f3= open('../tmp/ripe_ncc_collector_'+z+'.html',"r")
            var = False
            for l in f3:
                if "2007.10" in l:
                    var = True
            f3.close()
            if not var:
                #print(url_collector)
                continue

            url_collector = "http://data.ris.ripe.net/rrc"+z+"/2007.10/"
            download_file(url_collector,'../tmp/ripe_ncc_collector_'+z+'.html')
            f2= open('../tmp/ripe_ncc_collector_'+z+'.html',"r")
            for m in f2:
                if len(m)==229:
                    if m[84]=="b": #it means that it is an bview rib
                        name_of_archive = m[84:106]
                        name_of_archive2 = name_of_archive[6:14]
                        if name_of_archive2 == "20071027":
                            url = "http://data.ris.ripe.net/rrc"+z+"/2007.10/"+name_of_archive
                            list_url.append(url)
                            break #we only take the last rib table, it is the first one we see in the file
            f2.close()
    f1.close()
    #routeview
    url = 'http://archive.routeviews.org'
    download_file(url,'../tmp/routeview_collector.html')
    f1= open("../tmp/routeview_collector.html","r")
    for i in f1:
        if "<A HREF=\"/" in i:
            i = i.split("\"")
            k = i[1]
            name = i[1].replace("/", "")
            if k == "/ipv6" or k=="/route-views3/bgpdata" or k=="/route-views6/bgpdata": #we don't need theses files
                continue

            #look if 2007.10 is in collector
            url_collector = "http://archive.routeviews.org"+k
            download_file(url_collector,'../tmp/routeview_collector'+name+'.html')
            f3= open('../tmp/routeview_collector'+name+'.html',"r")
            var = False
            for l in f3:
                if "2007.10" in l:
                    var = True
            f3.close()
            if not var:
                continue

            url_collector = "http://archive.routeviews.org"+k+"/2007.10/RIBS/"
            download_file(url_collector,'../tmp/routeview_collector'+name+'.html')
            f2 = open('../tmp/routeview_collector'+name+'.html','r')
            tab = []
            for m in f2:
                if "20071027" in m:
                    tab.append(m)
            f2.close()
            m = tab[-1]
            name_of_file = m[81:102]
            url = "http://archive.routeviews.org"+k+"/2007.10/RIBS/"+name_of_file
            list_url.append(url)
    f1.close()

    for i in list_url:
        if i not in list_metadata:
            z = i.split("/")
            download_file(i,'RIB_2007_10_27/'+z[3])
            list_metadata.append(i)

    os.system("rm RIB_2007_10_27/history")
    metadata = open("RIB_2007_10_27/history", 'w')
    for x in list_metadata:
        metadata.write(x+"\n")
    metadata.close()

def create_graph():
    for i in AS_RELATION:
        link = i.split("-")
        link_as_in_graph(link,G)

def add_ribs_to_db(hash_map):
    for rib_archive in os.listdir("RIB_2007_10_27"):
        print(rib_archive)
        if rib_archive=="history":
            continue
        data = os.popen("python Programs/mrt2bgpdump.py RIB_2007_10_27/"+rib_archive).read()
        data = str(data).split("\n")
        for elem in data:
            elem=elem.split("|")
            if elem[0]=='': #empty list
                continue
            time = elem[1]
            type = elem[2]
            if type=="W": #withdraw
                annoucer = elem[3]
                as_nb = elem[4]
                prefix = elem[5]
            elif type=="A" or type=="B": #annoucement, Table
                annoucer = elem[3]
                as_nb = elem[4]
                prefix = elem[5]
                as_path = elem[6]
            if type=="W":
                if prefix_of_tor_relay(prefix,hash_map):
                    continue
                    #delete_data_to_db(prefix,ASN_TO_RIB)
            elif type=="A" or type=="B":
                as_path = as_path.split(" ")
                link_as_in_graph(as_path,G)
                if prefix_of_tor_relay(prefix,hash_map):
                    advertise_prefix([as_path[len(as_path)-1]],prefix,G,ASN_TO_RIB)


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
    #list_ipv6 = list_ip4_ip6[1]
    #IPV4
    for i in list_ip4:
        '''
        for number in range(0,9): #0 to 8
            var = i.split(".")
            addr = var[0]+".0.0.0/"+str(number)
            hash_map[addr]=True
        for number in range(9,17): #9 to 16
            var = i.split(".")
            addr = var[0]+"."+var[1]+".0.0/"+str(number)
            hash_map[addr]=True
        '''
        for number in range(17,25): #17 to 24
            var = i.split(".")
            addr = var[0]+"."+var[1]+"."+var[2]+".0/"+str(number)
            hash_map[addr]=True
        '''
        for number in range(25,33): #25 to 32
            var = str(i)+"/"+str(number)
            hash_map[var]=True
        #print(hash_map)
        '''
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

def delete_data_to_db(AS,prefix,asn_to_rib):
    for i in asn_to_rib:
        if prefix in i:
            list_path = i.get(prefix)
            for path in list_path:
                if path[len(path)-1]==AS:
                    list_path.remove(path)

def extract_as_prefix_from_bgp_archives(hash_map):

    announcement_list = []
    withdraw_list = []
    count = 0
    for bgp_archive in os.listdir("BGP_Archives"):
        print(count)
        count += 1
        data = os.popen("python Programs/mrt2bgpdump.py BGP_Archives/"+bgp_archive).read()
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
            elif type=="A":
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
    for i in withdraw_list:
        i = i.split("-")
        AS = i[0]
        Prefix = i[1]
        delete_data_to_db(AS,Prefix,ASN_TO_RIB)
    for i in announcement_list:
        print(i)
        i = i.split("-")
        AS = i[0]
        Prefix = i[1]
        start_time = time.time()
        advertise_prefix_new([AS],Prefix,G,ASN_TO_RIB)
        print(" --- %s seconds ---" % (time.time() - start_time))
    return G,ASN_TO_RIB

##############################################
#   Calculate Resilient Score of Tor Relays  #
##############################################

def take_50_random_AS(G,True_AS):
    lenght = len(G) #number of AS
    list_of_as = []
    count = 0
    if lenght >= 10:
        while count<10:
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
    #print("begin "+str(ases)+" "+str(prefix))
    #print("length graph : "+str(len(Graph)))
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
            best_relation_path = get_best_relation_path(path_list,i)
            if (path not in best_relation_path):
                return False
            shortest = 4294967296
            for x in best_relation_path:
                if len(x) < shortest:
                    shortest=len(x)
            if len(path)==shortest:
                return True
            else:
                return False

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
    for i in G.nodes():
        if i not in True_AS_list:
            if DB2.get(i):
                prefix_list = DB2[i]
                if prefix_list.get(prefix):
                    path_list = prefix_list[prefix]
                    best_relation_path = get_best_relation_path(path_list,i)
                    shortest = 4294967296
                    for x in best_relation_path:
                        if len(x) < shortest:
                            shortest=len(x)
                    list_path_same_length = []
                    for x in path_list:
                        if len(x) == shortest:
                            list_path_same_length.append(x)
                    true_path = 0
                    false_path = 0
                    for x in list_path_same_length:
                        if x[len(x)-1] != Wrong_AS:
                            false_path += 1
                        else:
                            true_path += 1
                    score = true_path/(false_path+true_path)
                    hijacked += score
    return (len(G)-hijacked)/len(G)


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
        print("Can't compute score because no IP prefix in BGP tables about tor relay")
    #main
    for prefix in list_prefix_in_DB: #iterate on all prefix (we have to calculate the score for each one of them)
        True_AS_list = get_true_as_from_prefix(prefix)
        random_AS_50 = take_50_random_AS(Graph,True_AS_list) #take 10 random AS => they will hijack the prefix
        score=0
        for AS in random_AS_50: #Graph.nodes():
            start_time = time.time()
            DB2 = advertise_prefix_new([AS],prefix,Graph,DB.copy())
            print(" --- %s seconds ---" % (time.time() - start_time))
            start_time = time.time()
            score = score + compute_score(AS,prefix,DB2,Graph,True_AS_list)
            print(" --- %s seconds score fun ---" % (time.time() - start_time))
        final_score = score/len(G)
        print("prefix : "+str(prefix)+" , score : "+str(final_score))

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
