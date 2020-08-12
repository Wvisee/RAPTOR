#!/usr/bin/python3
import os
import fileinput
import sys
from functions import *

###############################################################
#0. Init/Clean directories of files from previous computation #
###############################################################

print("Initialization of directories and files")
init()
print("Cleaning of directories")
clean()

#####################################
#1. Update Tor Consensuses Archives #
#####################################
print("Download and update of Tor archives")
update_tor_archive()

#####################################
#2.  Get all relation AS archives   #
#####################################
print("Download of AS relation archives")
url_relation_as = get_url_archives_relation_as()

##################################
#3.   Calculate the resilience   #
##################################

tar_list = get_list_of_files_sorted_in_directory("tor-consensuses-tar")

for filename in tar_list: #iterate throught TOR consensuses archives by month
    if filename.endswith(".tar.xz"): #only looking at archives (a file name "last_changed" is used to maintain this list up-to-date)

        os.system("tar -xf tor-consensuses-tar/"+str(filename)+" -C tor-consensuses") #untar archive
        filename= str(filename).split('.')
        filename= filename[0] #get name of archives without the .tar.xz
        print(filename) # to see where we are during the execution

        date_for_rib = filename.replace("consensuses-","")
        date_for_rib = date_for_rib.replace("-",".")

        init_as_relation_in_dict(filename,url_relation_as) #we init the as relation data
        DOWNLOAD_RIB(date_for_rib)

        hour_list = get_list_of_files_sorted_in_directory("tor-consensuses/"+str(filename)+"/01")

        date = str(filename).split("-")
        date = date[1]+"-"+date[2]+"-01"

        result = open("output",'a')
        result.write(str(date)+"\n")
        result.close()

        print("Extract IP address of relays from Tor network from "+str(filename)+"-01")
        list_day_ipv4 = []
        for hour in hour_list: #extract ip of relay of Tor network
            list_ipv4_hour = extract_tor_ip("tor-consensuses/"+str(filename)+"/01/"+str(hour))
            for ip in list_ipv4_hour:
                if ip not in list_day_ipv4: #if ip is not in the list of ip day then we add it
                    list_day_ipv4.append(ip)

        prefix_hash_map=hash_map_all_prefix(list_day_ipv4) #returns all prefix of all IP address extracted from /17-/24

        announcementlist = add_rib_of_collector_to_db(prefix_hash_map) #announcement list is the list of prefix to announce inside the virtual network

        print("Computing the resilience of Tor relays")
        resilient_score_tor_relay = computation_resilient_score_tor_relay(announcementlist,prefix_hash_map)

        clean()
