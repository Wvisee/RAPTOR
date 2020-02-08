#!/usr/bin/python3
import urllib.request
import os
import fileinput
import sys
#function to replace a string in file by another one.
def replaceAll(file,searchExp,replaceExp):
    for line in fileinput.input(file, inplace=1):
        if searchExp in line:
            line = line.replace(searchExp,replaceExp)
        sys.stdout.write(line)
#load the metadata of the consensuses
dict_metadata = {}
metadata = open("tor-consensuses/last_changed", 'r')
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
            urllib.request.urlretrieve(url2, '../Project/tor-consensuses/'+name)
            #update the metadata
            metadata = open("tor-consensuses/last_changed", 'a')
            metadata.write(name+" "+date+"\n")
            metadata.close()
        if name in dict_metadata:
            if dict_metadata[name] != date:
                print("update "+name+" "+date)
                url2 = 'https://collector.torproject.org/archive/relay-descriptors/consensuses/'+name
                urllib.request.urlretrieve(url2, '../Project/tor-consensuses/'+name)
                #update the metadata
                replaceAll("tor-consensuses/last_changed",name+" "+dict_metadata[name],name+" "+date)
f.close()
