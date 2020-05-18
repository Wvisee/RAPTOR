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

####################
#   Monitoring     #
####################

def prefix_of_tor_relay(prefix,hash_map):
    return hash_map.get(prefix) #O(1) complexity
    # (prefix in hash_map) O(N) complexity

def get_true_as_from_prefix(prefix,date_of_prefix):
    #print(prefix)
    x = prefix.split("/")
    #print(x)
    x = x[0].split(".")
    #print(x)
    line = os.popen("dig +short "+x[3]+"."+x[2]+"."+x[1]+"."+x[0]+".peer.asn.cymru.com TXT").read()
    if line == "":
        return []
    #print("cympru")
    #print(prefix)
    #print(line)
    line = line.split("\"")
    #print(line)
    line = line[1].split("|")
    date = line[-1].rstrip()
    line = line[0].split(" ")
    #print(line)
    while("" in line) :
        line.remove("")
    #print(line)
    if date<=date_of_prefix:
        return line
    else:
        print("ALERT : "+date_of_prefix+" : "+date)
        return line

def monitoring(hash_map,date):
    wrong_announcement = {}
    all_announcement = {}
    for bgp_archive in os.listdir("BGP_Archives"):
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
                continue
                #if prefix_of_tor_relay(prefix,hash_map):
                    #print(elem)
            elif type=="A":
                as_path = as_path.split(" ")
                announcer = as_path[len(as_path)-1]
                if prefix_of_tor_relay(prefix,hash_map):

                    if not all_announcement.get(prefix):
                        all_announcement[prefix] = 1
                    else:
                        all_announcement[prefix] += 1

                    true_list = get_true_as_from_prefix(prefix,date)
                    if len(true_list)==0: #we don't know the real announcer
                        continue
                    else:
                        if announcer not in true_list: #origin check
                            #print(announcer+" "+prefix+" "+str(true_list))
                            if not wrong_announcement.get(prefix):
                                wrong_announcement[prefix] = {}
                            dict = wrong_announcement[prefix]
                            if announcer not in dict:
                                dict[announcer] = 1
                            else:
                                dict[announcer] += 1
    for prefix in all_announcement:
        nb = all_announcement[prefix]
        if wrong_announcement.get(prefix):
            dict = wrong_announcement[prefix]
        else:
            dict = {}
        for AS in dict:
            if dict[AS]/nb <= 0.0025:
                print("Frequency : "+prefix+" : "+AS+" : "+str(dict[AS])+"/"+str(nb)+" = "+str(dict[AS]/nb))
            elif dict[AS]/nb <= 0.065:
                print("Time : "+prefix+" : "+AS+" : "+str(dict[AS])+"/"+str(nb)+" = "+str(dict[AS]/nb))
