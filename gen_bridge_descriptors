#!/usr/sbin/env python -tt

import sys
import random
import time
import ipaddr
from datetime import datetime
import binascii


def usage():
    print "syntax: generatedescriptors.py <count>\n"\
          "    count: number of descriptors to generate\n"

def randomIP():
    return randomIP4()

def randomIP4():
    return ipaddr.IPAddress(random.getrandbits(32))

def randomPort():
    return random.randint(1,65535)

def gettimestamp():
    return time.strftime("%Y-%m-%d %H:%M:%S")

def getHexString(size):
    s = ""
    for i in xrange(size):
        s+= random.choice("ABCDEF0123456789") 
    return s

def generateDesc():

    baseDesc = "router Unnamed %s %s 0 %s\n"\
               "opt fingerprint %s\n"\
               "opt @purpose bridge\n"\
               "opt published %s\n"\
               "router-signature\n"
    fp = "DEAD BEEF F00F DEAD BEEF F00F " + \
         getHexString(4) + " " + getHexString(4) + " " + \
         getHexString(4) + " " + getHexString(4)
    ip = randomIP()
    orport = randomPort()
    dirport = randomPort()
    ID = binascii.a2b_hex(fp.replace(" ", ""))
    df =  baseDesc % (ip, orport, dirport, fp, gettimestamp())
    return (df, (ID, ip, orport, dirport))

def generateStatus(info, ID=None, ip=None, orport=None, dirport=None):
    baseStatus = "r %s %s %s %s %s %d %d\n"\
                 "s Running Stable\n"

    if info and len(info) == 4:
        ID = info[0]
        ip = info[1]
        orport = info[2]
        dirport = info[3]
    return "".join(baseStatus % ("namedontmattah", binascii.b2a_base64(ID)[:-2],
           "randomstring", gettimestamp(), ip,
            orport, dirport))

def generateExtraInfo(fp, ip=None):
    baseExtraInfo = "extra-info %s %s\n"\
                    "transport %s %s:%d\n"\
                    "router-signature\n"
    if not ip:
        ip = randomIP()
    return "".join(baseExtraInfo % ("namedontmattah", fp,
                                    random.choice(["obfs2", "obfs3", "obfs2"]),
                                    ip, randomPort()))
if __name__ == "__main__":
    if len(sys.argv) != 2:
        usage()
        sys.exit(0)

    df = ''
    sf = ''
    ei = ''
    count = int(sys.argv[1])
    for i in xrange(count):
        desc, info = generateDesc()
        df += desc

        sf += generateStatus(info)
	ei += generateExtraInfo(binascii.b2a_hex(info[0]))
        
    try:
        f = open("networkstatus-bridges", 'w')
        f.write(sf)
        f.close()
    except:
        print "Failed to open or write to status file"

    try:
        f = open("bridge-descriptors", 'w')
        f.write(df)
        f.close()
    except:
        print "Failed to open or write to descriptor file"

    try:
        f = open("extra-infos", 'w')
        f.write(ei)
        f.close()
    except:
        print "Failed to open or write to extra-info file"
