#!/usr/bin/python3
import urllib.request
import os
import fileinput
import sys
from progress.bar import Bar
from current_bgp_hijack import *
#function to replace a string in file by another one.
def replaceAll(file,searchExp,replaceExp):
    for line in fileinput.input(file, inplace=1):
        if searchExp in line:
            line = line.replace(searchExp,replaceExp)
        sys.stdout.write(line)

####################################################
#1. Download +- update tar consensus of tor relays #
####################################################

#load the metadata of the consensuses
dict_metadata = {}
metadata = open("tor-consensuses-tar/last_changed", 'r')
for x in metadata:
    x=x.split(" ")
    nameoffile=x[0]
    dateofchange=str(x[1]+" "+x[2].replace('\n', ''))
    dict_metadata[nameoffile]=dateofchange
metadata.close()
#print(dict_metadata)
#download consensuces.html which list file by hours of relay information.
url = 'https://collector.torproject.org/archive/relay-descriptors/consensuses/'
urllib.request.urlretrieve(url, '../Project/tmp/all-concensuses.html')
#dowload the consensuses that aren't already downloaded
f= open("tmp/all-concensuses.html","r")
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
            urllib.request.urlretrieve(url2, '../Project/tor-consensuses-tar/'+name)
            #update the metadata
            metadata = open("tor-consensuses-tar/last_changed", 'a')
            metadata.write(name+" "+date+"\n")
            metadata.close()
        if name in dict_metadata:
            if dict_metadata[name] != date:
                print("update "+name+" "+date)
                url2 = 'https://collector.torproject.org/archive/relay-descriptors/consensuses/'+name
                urllib.request.urlretrieve(url2, '../Project/tor-consensuses-tar/'+name)
                #update the metadata
                replaceAll("tor-consensuses-tar/last_changed",name+" "+dict_metadata[name],name+" "+date)
f.close()
os.remove("tmp/all-concensuses.html")

################################################################
#2. Untar Downloaded concensuses + download recent concensuses #
################################################################

number_of_tar_file = os.popen("ls -1 tor-consensuses-tar | wc -l").read()

tar_list=[] #sort the tar file in the directory
for filename in os.listdir("tor-consensuses-tar"):
    tar_list.append(filename)
tar_list.sort()

bar = Bar('Processing\n', max=int(number_of_tar_file))
result = open("tmp/result", 'a')
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
                print(hour)
                hijack=get_bgp_hijack("tor-consensuses/"+str(filename)+"/"+str(day)+"/"+str(hour))
                for x in hijack:
                    result.write(str(hour)+" : "+x+" : "+str(hijack[x])+"\n")
        bar.next()
        os.system("rm -rf tor-consensuses/"+str(filename))
bar.finish()
