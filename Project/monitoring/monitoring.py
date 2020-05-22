#!/usr/bin/python3
import os
import urllib.request
import fileinput
import sys
from functions import *

###############################################################
#0. Init/Clean directories of files from previous computation #
###############################################################
print("Init directories and files")
init()
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
#3.   Monitor BGP announcement   #
##################################

tar_list = get_list_of_files_sorted_in_directory("tor-consensuses-tar")

for filename in tar_list: #iterate throught TOR consensuses archives by month
    if filename.endswith(".tar.xz"): #only looking at archives (a file name "last_changed" is used to maintain this list up-to-date)
        os.system("tar -xf tor-consensuses-tar/"+str(filename)+" -C tor-consensuses") #untar archive
        filename= str(filename).split('.')
        filename= filename[0] #get name of archives without the .tar.xz

        day_list = get_list_of_files_sorted_in_directory("tor-consensuses/"+str(filename))
        for day in day_list:
            hour_list = get_list_of_files_sorted_in_directory("tor-consensuses/"+str(filename)+"/"+day)

            for hour in hour_list:
                print("Download BGP archives of "+str(hour))
                download_bgp_archives(url_stack,str(hour))

                #print("Extract IP of relays from Tor network from "+str(filename)+"-"+str(day)+" "+str(hour))
                list_ipv4_hour = extract_tor_ip("tor-consensuses/"+str(filename)+"/"+str(day)+"/"+str(hour))

                prefix_hash_map=hash_map_all_prefix(list_ipv4_hour) #returns all prefix of all ip extracted from /17-/24

                print("Monitoring of BGP announcement")
                date = str(filename).split("-")
                date = date[1]+"-"+date[2]+"-"+str(day)

                result = open("output",'a')
                result.write(str(hour)+"\n")
                result.close()

                monitoring(prefix_hash_map,date)

                #break
                delete_bgp_archives()
                #break
        #break
        os.system("rm -rf tor-consensuses/"+str(filename))
    #break
