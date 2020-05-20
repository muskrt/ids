from scapy.all import *
from collections import Counter
import time
import pandas as pd
import Rules as check

count = Counter()
trafics=[]
base={}
paket_lst=[]
base['src ip']= []
base['src port']=[]
base['protocol']=[]
base['dst ip']=[]
base['dst port']=[]
src_ip=None
paketler=None
def print_packet(packet):
	global clock
	global time_interval
	

    # print(ip_laye[0].summary())
def create_dataset():
	print(dataset_Create)
	
def label_data():
	#etiketle butonu icin
	pass
	
def tst(packet):
	ip_laye=packet.getlayer(IP)
	protocol=ip_laye.get_field('proto')
	# print(ip_laye[1].src)
	#print('src:{}\nsrc_port:{}\nprotocol:{}\ndst:{}\ndst_port:{}\n'.format(ip_laye.src,ip_laye.sport,protocol.i2s[packet.proto],ip_laye.dst,ip_laye.dport))
	global src_ip
	global paketler
	global raw_data
	src_ip=str(ip_laye.src)
	dst_ip=str(ip_laye.dst)
	src_port=str(ip_laye.sport)
	dst_port=str(ip_laye.dport)
	raw_data=packet.payload
	

	global veri
	if dataset_Create:
		protokol=str(protocol.i2s[packet.proto])
		base['src ip'].append(src_ip)
		base['src port'].append(src_port)
		base['protocol'].append(protokol)
		base['dst ip'].append(dst_ip)
		base['dst port'].append(dst_port)
		paketler=('--> src: '+src_ip+' dst: '+dst_ip+' sport: '+src_port+' dport: '+dst_port+' proto: '+protokol+' --> '+str(ip_laye.summary()))
		paket_lst.append([paketler,raw_data])
		veri=pd.DataFrame(base)
		check.check_packet(src_ip,src_port,protokol,dst_ip,dst_port)
		
		label_data()
		
		#dataframei parcala
		#print(veri.iloc[2:,2:3])
	else:
		print(packet.summary())


def main(interface):

	print('[*] Start Sniffing...')
	global dataset_Create
	dataset_Create=1
	# Thread(target=clock_time).start()
	sniff(iface=interface,filter='ip',prn=tst)
	print('[*] Stop sniffing')
# from scapy.all import *
 
# import matplotlib.pyplot as plt
 
# import argparse
 
# import os
 
# parser = argparse.ArgumentParser(description='Live Traffic Examiner')
 
# parser.add_argument('interface', help="Network interface to listen on i.e. en0", type=str)
 
# parser.add_argument('--count', help="Capture X packets and exit", type=int)
 
# args=parser.parse_args()
 
# #Check to see if we are root, otherwise Scapy might not be able to listen
 

 
# print("Warning: Not running as root, packet listening may not work.")

# try:

#    print("--Trying to listen on {}".format(args.interface))

#    sniff(iface=args.interface,count=1)

#    print("--Success!")

# except:

#    print("--Failed!\nError: Unable to sniff packets, try again using sudo.")

#    quit()
 
# if args.count:
 
#    print("Capturing {} packets on interface {} ".format(args.count, args.interface))
 
# else:
 
#    print("Capturing unlimited packets on interface {} \n--Press CTRL-C to exit".format(args.interface))
 
# #Interactive Mode
 
# plt.ion()
 
# #Labels
 
# plt.ylabel("Bytes")
 
# plt.xlabel("Count")
 
# plt.title("Real time Network Traffic")
 
# plt.tight_layout()
 
# #Empty list to hold bytes
 
# yData=[]
 
# i=0
 
# #Listen indefinitely, or until we reach count
 
# while True:
 
#    #Listen for 1 packet
 
#    for pkt in sniff(iface=args.interface,count=1):
 
#        try:
 
#            if IP in pkt:
 
#                yData.append(len(pkt))
 
#                plt.plot(yData)
 
#                #Pause and draw
 
#                plt.pause(0.1)
 
#                i+=1
 
#                if args.count:
 
#                    if i >= args.count:
 
#                        quit()
 
#        except KeyboardInterrupt:
 
#            print("Captured {} packets on interface {} ".format(i, args.interface))
 
#            quit()
