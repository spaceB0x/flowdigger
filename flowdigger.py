#!/usr/bin/env python
from scapy.all import *
import sys
import time
import re
import netaddr
import argparse

# Argument parsing/handling
parser = argparse.ArgumentParser()
parser.add_argument("-i", "--interface",
                    default='localhost', help="Interface to listen on")
parser.add_argument("-t", "--type", default="ipudp", choices=[
                    "all", "ipudp"], help="If set to 'all', captures all protocols, else just captures tcp/udp")
parser.add_argument("-c", "--collector", default="127.0.0.1",
                    help="Source IP of netflow collector. Defaults to 127.0.0.1")
parser.add_argument("-p", "--port", type=int, default=18000,
                    help="Port that netflow collector is listening on. Defaults to 18000.")
parser.add_argument("-x", "--xforwarded", type=int, default=0, help="Look through IP header info to extract X-Forwarded-For header. \
                                                                Replaces the original source with that IP from that point on. 0 for off, 1 for on.")

args = parser.parse_args()

# Globals
# regexes
# X-Forwareded-For IP
XFFreg = re.compile('X\-Forwarded\-For\:\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
UDPreg = re.compile('\{\|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\}')  # UDP IP
list = []
addresses = netaddr.IPNetwork("172.16.0.0/12")
localaddr = netaddr.IPNetwork("127.0.0.1/32")
collector = args.collector
colport = args.port

# define callback


def packet_decider(packet):

  p = packet
  if args.type == "all":
    sendAll(p)
  elif args.type == "ipudp":
    if(packet.haslayer(IP)):
      if (packet[IP].proto == 6):
        TCPsend(p)
      elif (packet[IP].proto == 17):
        UDPsend(p)
      else:
        print packet.show()

    else:
      print "[*][*] Not an IP based packet."
  else:
    print "error with type determination"

#def sendAll(p):



def TCPsend(p):
  epoch = getEpoch()
  sip = p[IP].src
  dip = p[IP].dst
  sport = p[TCP].sport
  dport = p[TCP].dport

  if args.xforwarded == 1:
    lus = lookup(sip, sport)
    lud = lookup(dip, dport)
    if((lus is None) and (lud is None)):
      if (p.haslayer(Raw)):
        raw = str(p[Raw])
        xff = XFFreg.search(raw)
        if (xff is None):
          print "Not a match"

        else:
          newsrc = (xff.group(0)).strip('X-Forwarded-For: ')
          addToList(sip, sport, newsrc)
          sip = str(newsrc)

      else:
        print "No TCP Raw"
    elif(lus is not None):
      sip = str(lus)

    else:
      dip = str(lud)

  try:
    send(IP(dst=collector) / UDP(dport=colport) / NetflowV5Header(sysUptime=5, unixSecs=epoch, unixNanoSeconds=3)
         / NetflowV5Record(src=str(sip), dst=str(dip), srcport=sport, dstport=dport, prot=6))
    print "[*] TCP netflow send successful"
    print sip

  except:
    print "[*][*] TCP Netflow not sent"


def UDPsend(p):

  epoch = getEpoch()
  sip = p[IP].src
  dip = p[IP].dst
  sport = p[UDP].sport
  dport = p[UDP].dport
  if args.xforwarded == 1:
    lu = lookup(sip, sport)
    # If not in list, then add to list and try and strip headerinfo
    if(lu is None):
      if (p.haslayer(Raw)):
        raw = str(p[Raw])
        ureg = UDPreg.search(raw)
        if (ureg is None):
          print "Not a match"
        else:
          newsrc = (ureg.group(0)).strip('{|').strip('}')
          addToList(sip, sport, newsrc)
          sip = str(newsrc)

      else:
        print "No UDP Raw"
  else:
    lu = lookup(sip, sport)
    sip = str(lu)

  try:
    send(IP(dst=collector) / UDP(dport=colport) / NetflowV5Header(sysUptime=5, unixSecs=epoch, unixNanoSeconds=3)
         / NetflowV5Record(src=str(sip), dst=str(dip), srcport=sport, dstport=dport, prot=17))
    print "[*] UDP netflow send successful"
    print sip
  except:
    print "[*][*] UDP Netflow not sent"


def getEpoch():
  a = int(time.time())
  return a


def lookup(sip, sport):
  for x in list:
    if (x[0] == sip and x[1] == sport):
      return x[2]
    else:
      return None


def addToList(sip, sport, newsrc):
  if((sip not in addresses)and (newsrc not in localaddr)):
    listitem = [sip, sport, newsrc]
    list.append(listitem)
    print list


def main():
  if args.interface:
    sniff(iface=args.interface, prn=packet_decider, store=0)


main()
