#!/usr/bin/python3
import os
import urllib.request
import fileinput
import sys
from progress.bar import Bar
from functions import *

##########################################################
#0. Clean directories of files from previous computation #
##########################################################
print("Clean directories")
#clean()

#####################################
#1. Update Tor Consensuses Archives #
#####################################
print("Update Tor Archives")
update_tor_archive()

#####################################
#2.   Update the BGP url stack      #
#####################################
print("Get Url of BGP Archives")
url_stack = get_update_bgp_stack_archive()

#####################################
#3.  Get all relation AS archives   #
#####################################
print("Get relations AS Archives")
url_relation_as = get_url_archives_relation_as()

##################################
#4.   Calculate the resilience   #
##################################

tar_list = get_list_of_files_sorted_in_directory("tor-consensuses-tar")

only_at_begin = True #condition used to init once the virtual network

for filename in tar_list: #iterate throught TOR consensuses archives by month
    if filename.endswith(".tar.xz"): #only looking at archives (a file name "last_changed" is used to maintain this list up-to-date)
        os.system("tar -xf tor-consensuses-tar/"+str(filename)+" -C tor-consensuses") #untar archive
        filename= str(filename).split('.')
        filename= filename[0] #get name of archives without the .tar.xz

        init_as_relation_in_dict(filename,url_relation_as) #we init the as relation data

        day_list = get_list_of_files_sorted_in_directory("tor-consensuses/"+str(filename))
        for day in day_list:
            hour_list = get_list_of_files_sorted_in_directory("tor-consensuses/"+str(filename)+"/"+day)

            for hour in hour_list:
                print("Download BGP archives of "+str(hour))
                #download_bgp_archives(url_stack,str(hour))

            print("Extract IP of relays from Tor network from "+str(filename)+"-"+str(day))
            list_day_ipv4 = []
            for hour in hour_list: #extract ip of relay of Tor network
                list_ipv4_hour = extract_tor_ip("tor-consensuses/"+str(filename)+"/"+str(day)+"/"+str(hour))
                for ip in list_ipv4_hour:
                    if ip not in list_day_ipv4: #if ip is not in the list of ip day then we add it
                        list_day_ipv4.append(ip)

            prefix_hash_map=hash_map_all_prefix(list_day_ipv4) #returns all prefix of all ip extracted from /17-/24

            if only_at_begin: #init the virtual network with the BGP tables available on TOR first day
                print("Initialize vitual network with Ribs")
                add_rib_of_collector_to_db(prefix_hash_map)
                only_at_begin = False

            print("Extract from BGP archives prefix announced by AS")
            announcement_list,withdraw_list = extract_as_prefix_from_bgp_archives(prefix_hash_map)

            print("Injection the BGP update in the virtual network")
            internetgraph_routingdb = advertise_all_prefix(announcement_list,withdraw_list)

            print("Computing the resilience of the Tor relays")
            resilient_score_tor_relay = computation_resilient_score_tor_relay(internetgraph_routingdb)
            #break
            #delete_bgp_archives()
            break
        break
        os.system("rm -rf tor-consensuses/"+str(filename))
    break
