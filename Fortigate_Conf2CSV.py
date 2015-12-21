#!/usr/bin/python

import sys
import re

if len(sys.argv) != 2:
    print "Usage: "+sys.argv[0]+" configurationFile.txt > output.csv"
    sys.exit(1)

file = sys.argv[1] 

insideConfig=False
insidePolicy=False
sp="    "

parametres = [
	["uuid","UUID"],
	["srcintf","SRCINTF"],
	["dstintf","DSTINTF"],
	["srcaddr","SRCADDR"],
	["dstaddr","DSTADDR"],
	["rtp-nat","RTPNAT"],
	["action","ACTION"],
	["status","STATUS"],
	["schedule","SCHEDULE"],
	["schedule-timeout","SCHEDULETIMEOUT"],
	["service","SERVICE"],
	["utm-status","UTMSTATUS"],
	["logtraffic","LOGTRAFFIC"],
	["logtraffic-start","LOGTRAFFICSTART"],
	["capture-packet","CAPTUREPACKET"],
	["auto-asic-offload","AUTOASIC-OFFLOAD"],
	["wanopt","WANOPT"],
	["webcache","WEBCACHE"],
	["traffic-shaper","TRAFFICSHAPER"],
	["traffic-shaper-reverse","TRAFFICSHAPER-REVERSE"],
	["per-ip-shaper","PERIP-SHAPER"],
	["nat","NAT"],
	["session-ttl","SESSIONTTL"],
	["vlan-cos-fwd","VLANCOS-FWD"],
	["vlan-cos-rev","VLANCOS-REV"],
	["wccp","WCCP"],
	["groups","GROUPS"],
	["users","USERS"],
	["devices","DEVICES"],
	["disclaimer","DISCLAIMER"],
	["natip","NATIP"],
	["match-vip","MATCHVIP"],
	["diffserv-forward","DIFFSERVFORWARD"],
	["diffserv-reverse","DIFFSERVREVERSE"],
	["tcp-mss-sender","TCPMSS-SENDER"],
	["tcp-mss-receiver","TCPMSS-RECEIVER"],
	["comments","COMMENTS"],
	["block-notification","BLOCKNOTIFICATION"],
	["custom-log-fields","CUSTOMLOG-FIELDS"],
	["tags","TAGS"],
	["replacemsg-override-group","REPLACEMSGOVERRIDE-GROUP"],
	["srcaddr-negate","SRCADDRNEGATE"],
	["dstaddr-negate","DSTADDRNEGATE"],
	["service-negate","SERVICENEGATE"],
	["timeout-send-rst","TIMEOUTSEND-RST"],
	["captive-portal-exempt","CAPTIVEPORTAL-EXEMPT"]
]

def matchContent(exp, line, g):
    if sp+sp+"set "+exp+" " in line:
        if not g:
            return re.findall(r'set '+exp+' ([^]]*)\n', line)[0]
        else:
            return re.findall(r'set '+exp+' "([^]]*)"\n', line)[0] 
    else:
        return False


with open(file, "r") as conf:
    for line in conf:
        if "config firewall policy" in line and not "6" in line:
            insideConfig=True
            mypolicy = {}
            header="\""
            for command, alias in parametres:
                header+=alias+"\",\""
            header+="\""
            print header
        if insideConfig and "end" in line:
            insideConfig=False
        if insideConfig and sp+"edit " in line:
            insidePolicy=True
        if insidePolicy and sp+"next" in line:
            insidePolicy=False
            printablePolicy=""
            for i in range(0, len(parametres)):
                if parametres[i][1] in mypolicy.keys():
                    printablePolicy+=mypolicy[parametres[i][1]].replace("\"","")+"\",\""
                else:
                    printablePolicy+="\",\""
            printablePolicy+="\""
            print printablePolicy
            mypolicy = {}

        if insidePolicy:
            for command, alias in parametres:
                result = matchContent(command, line, False)
                if result:
                    mypolicy[alias]=result

