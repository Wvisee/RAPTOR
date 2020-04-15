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
clean()

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

##################################
#3.   Calculate the resilience   #
##################################
number_of_tar_file = os.popen("ls -1 tor-consensuses-tar | wc -l").read()

tar_list=[] #sort the tar file in the directory
for filename in os.listdir("tor-consensuses-tar"):
    tar_list.append(filename)
tar_list.sort()

only_at_begin = True
result = open("../tmp/result", 'a')
for filename in tar_list:
    if filename.endswith(".tar.xz"):
        os.system("tar -xf tor-consensuses-tar/"+str(filename)+" -C tor-consensuses")
        filename= str(filename).split('.')
        filename= filename[0]

        day_list=[] #sort the day file in the tar-directory
        for dayname in os.listdir("tor-consensuses/"+str(filename)):
            day_list.append(dayname)
        day_list.sort()

        for day in day_list:

            hour_list=[] #sort the hour file in the day-directory
            for hourname in os.listdir("tor-consensuses/"+str(filename)+"/"+day):
                hour_list.append(hourname)
            hour_list.sort()

            for hour in hour_list:

                print("Dowload BGP archives of "+str(hour))
                download_bgp_archives(url_stack,str(hour))

                print("Computation of relay resilience of "+str(hour))
                list_ip4_ip6=extract_tor_ip("tor-consensuses/"+str(filename)+"/"+str(day)+"/"+str(hour))
                prefix_hash_map=hash_map_all_prefix(list_ip4_ip6)

                if only_at_begin:
                    add_rib_of_collector_to_db(prefix_hash_map)
                    only_at_begin = False

                internetgraph_routingdb= internet_mapping(prefix_hash_map,str(hour))
                #print(len(internetgraph_routingdb[0]))
                #print(internetgraph_routingdb[1])
                #print(prefix_hash_map)
                #break
                resilient_score_tor_relay = computation_resilient_score_tor_relay(internetgraph_routingdb)
                #break
                delete_bgp_archives()

                #break
            #break
        #break
        os.system("rm -rf tor-consensuses/"+str(filename))
    #break
