

# from subprocess import *
# import os 
# import  argparse
# # call(["dir","/B"])
# #print(help(Popen))
# parser=argparse.ArgumentParser()
# parser.add_argument('-t',help='first number',type=str)
# args=vars(parser.parse_args())
# print(args['t'])
# os.system('taskkill /F /im python.exe')
# os.system('taskkill /F /im pythonw.exe

# import tkinter as tk
# import socket
# import os
# from threading import Thread
# import time
# import psutil 
# import time
# import sys
# import struct
# from struct import unpack
# from struct import pack
# from ctypes import *
# rx_tx=''





# # import sniffer
# s = ''
# host = ''
# data = ''
# devam = ''
# data_for_learn = {}
# ip_lst = set()

# class IP(Structure):
# 	_fields_=[
# 	('ihl',c_ubyte,4),
# 	('version',c_ubyte,4),
# 	('tos',c_ubyte,),
# 	('len',c_ushort),
# 	('id',c_ushort),
# 	('offset',c_ushort),
# 	('ttl',c_ubyte),
# 	('protocol_num',c_ubyte),
# 	('sum',c_ushort),
# 	('src',c_ulong),
# 	('dst',c_ulong)
# 	]
# 	def __new__(self,socket_buffer=None):
# 		return self.from_buffer_copy(socket_buffer)
# 	def __init__(self,socket_buffer=None):
# 		self.protocol_map={1:'ICMP',6:'TCP',17:'UDP'}
# 		self.src_address=socket.inet_ntoa(struct.pack('<L',self.src))
# 		self.dst_address=socket.inet_ntoa(struct.pack('<L',self.dst))
# 		# self.ihl=socket.inet_ntoa(struct.pack('B',self.ihl))

# 		try:
# 			self.protocol=self.protocol_map[self.protocol_num]
# 		except :
# 			self.protocol=str(self.protocol_num)


# def analysis(veri):
# 	pkt=veri
# 	iphdr=unparck('!BBHHHBBH4s4s',pkt[0:20])
# 	iplen=(iphdr[0]&0xf)*4
# 	tcphdr=unpack('!HHLLBBHHH',pkt[iplen:iplen+20])
# 	print(tcphdr)
# 	# source=tcphdr[0]
# 	# dest=tcphdr[1]
# 	# seq=tcphdr[2]
# 	# ack_seq=tcphdr[3]
# 	# dr=tcphdr[4]
# 	# flags=tcphdr[5]
# 	# window=tcphdr[6]
# 	# check=tcphdr[7]
# 	# urg_ptr=tcphdr[8]
# 	# doff=dr>>4
# 	# fin=flags&0x01
# 	# syn=flags&0x02
# 	# rst=flags&0x04
# 	# psh=flags&0x08
# 	# ack=flags&0x10
# 	# urg=flags&0x20
# 	# ece=flags&0x40
# 	# cwr=flags&0x80
# 	# tcplen=(doff)*4
# 	# h_size=iplen+tcplen
# 	# data=pkt[h_size:]
# 	# print(data)

# def create_socket():
# 	global s
# 	global host
# 	global data
# 	global devam
# 	s = socket.socket(socket.AF_INET, socket.SOCK_RAW,socket.IPPROTO_IP)
# 	host = '255.255.255.255'
	
# 	s.bind((host, 0))
	
# 	s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 3)
# 	s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
# 	Thread(target=dinle).start()
# 	try:
# 		yield s
# 	finally:
# 		s.close()
# def dinle():
# 	global ip_lst
# 	global devam
# 	print('started...')
# 	devam = ''
# 	tst=''
# 	try:
# 		while True:
# 			data = s.recvfrom(65565)[0]

# 			if data:
# 				ip_header=IP(data[0:20])
				
# 				print(ip_header.src_address,ip_header.dst_address)
# 				tst=int(data[0:1])
# 				try:
# 					print(tst.decode())
# 				except:
# 					print('error')
				
# 			if devam == 1:
# 				print('stopping')
# 				break
# 			else:
# 				pass
# 			time.sleep(1)
# 		s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
# 		sys.exit()
# 	except:
# 		sys.exit()
	
# def menu():
# 	adapters = ifaddr.get_adapters()
# 	ips = {}
# 	ips['exit'] = 1
# 	ips['default'] = '255.255.255.255'

# 	for adapter in adapters:
# 		ips[adapter.nice_name] = ''
# 		for ip in adapter.ips:
# 			if len(ip.ip) < 33:
# 				ips[adapter.nice_name] = ip.ip
# 	keys = []
# 	for key in enumerate(ips):
# 		keys.append(key[1])
# 	print(str(key[0])+' ### '+str(key[1])+'  --->>>  '+str(ips[key[1]]))
# 	choice = int(input('>>'))
# 	return ips[keys[choice]]





# 	# global data
# 	# window=tk.Tk()
# 	# window.configure(width=600, height=600)
# 	# window.resizable(width=False,height=False)
# 	# tst=tk.StringVar()
# 	# label1=tk.Label(window,text=tst,width=15,height=15)
# 	# label1.pack()
# 	# Thread(target=degis,args=(label1,window)).start()

# 	# window.mainloop()

# def sniff():
# 	global s
# 	global host
# 	global data
# 	global devam
# 	s = socket.socket(socket.AF_INET, socket.SOCK_RAW,socket.IPPROTO_IP)
# 	host = '255.255.255.255'
# 	if host == 1:
# 		sys.exit()
# 	#print(host)
# 	#print(socket.gethostname())
# 	#print(help(s.ioctl))
# 	s.bind((host, 0))
# 	# print(s.ioctl)
# 	s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 3)
# 	s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
# 	Thread(target=dinle).start()
# 	# window_thread=Thread(target=win)
# 	#window_thread.start()
# 	#s.ioctl(socket.SIO_RCVALL,socket.RCVALL_OFF)
# 	count = 0
# 	while True:
# 		if data:
# 			if not(data[0].__contains__('192')):
# 		# sys.stdout.write(data[0])

# 				count += 1
# 			if count == 50:
# 				count = 0
# 			try:
# 				for sec in range(5, 0, -1):
# 					print('\rwaiting for %d ...'%sec, flush=True, end='')
# 					time.sleep(1.5)
# 				print('\n')
# 			except KeyboardInterrupt:
# 				devam = input('\n:')
# 				if devam:
# 					window_thread._stop()
# 					sys.exit()
# 					break



import tkinter as tk
import socket
import os
from threading import Thread
import time
import psutil 
import time
import sys
import struct
from struct import unpack
from struct import pack
from ctypes import *
rx_tx=''
from scapy.all import *
from collections import Counter
import time
import pandas as pd
from subprocess import PIPE,Popen
import Rules as check
import sniff
from win10toast import ToastNotifier
from tkinter import messagebox,simpledialog
interface='Wi-Fi'

Ip_flags=['version','ihl','tos','len','id','flags','frag','ttl','proto','chksum','src','dst']
tcp_flags=[ 'sport','dport','seq','ack','dataofs','reserved','flags','window','chksum','urgptr','options']
udp_flags=['sport','dport','len','chksum']
ethernet_flags=['dst','src','type']
base={}
base['src ip']= []
base['src port']=[]
base['protocol']=[]
base['dst ip']=[]
base['dst port']=[]
src_ip=''
dst_ip=''
dst_port=''
src_port=''
veri=''
 
class ids_app(tk.Frame):
	

	def current_bandwitht(self):
		global rx_tx
		old_value =0
		old_value2=0
		while True:
			new_value=psutil.net_io_counters().bytes_recv
			new_value2=psutil.net_io_counters().bytes_sent
			if old_value:
				rx=round((new_value-old_value)/1024.0,2)
				tx=round((new_value2-old_value2)/1024.0,2)
				rx_tx=round(((new_value - old_value+new_value2-old_value2)/1024.0)*8,2)
			old_value=new_value
			old_value2=new_value2
			
	def __init__(self,window):
	
		tk.Frame.__init__(self,master=window)

		self.window=window
		width_of_screen=self.window.winfo_screenwidth()/2
		height_of_screen=self.window.winfo_screenheight()/2
		self.window.geometry("1000x680+%d+%d"%( (width_of_screen-500),(height_of_screen-380)  ))
		# self.window.resizable(width=False,height=False)
		self.window.protocol('WM_DELETE_WINDOW', self.exit)
		# self.ip_lst=set()
		open('rules.txt','w')
		open('log.txt','w')
		
		
		global label_var
		label_var=tk.StringVar()
		

		self.main_screen()
		self.guncelle()
		Thread(target=self.current_bandwitht).start()
		self.bandwidth_guncelle()


		self.window.mainloop()
	def exit(self):
		try:
			os.system('taskkill /F /IM python.exe')
		except:
			print('tst')
	def listbox_click(self,event):
		if len(self.lst.curselection())>0:
			selected=int(self.lst.curselection()[0])
			#print(self.list1.get(selected))
			paketara=str(self.lst.get(selected))
		try:
			for item in sniff.paket_lst:
				if item[0] ==paketara:
					self.rawlist.delete(0,tk.END)
					for i in range(0,len(str(item[1]) )):
						self.rawlist.insert(tk.END,str(item[1][i:(i+5)] )+'\n')

						i+=5
		except:
			pass
				
				#
				#insert(item[1])
	def guncelle(self):
		
		#self.lst.insert(tk.END,rx_tx)
		
		
		self.lst.insert(tk.END,sniff.paketler)
		# self.label_bandwith['text']=src_ip
		self.window.after(1500,self.guncelle)
	
	
		
		# self.window.destroy()
	def export_btn(self):
		pass
	def trafik_sniff(self):
		print(self.ipdata.data)
		while True:
		
			for item in  ips:
				print('tst')
				print('>>>>>>>>>'+str(item))
				self.lst.insert(tk.END,item)
				self.label_ip['text']=item
				time.sleep(1)
	def add_rule(self):
		def ekle():
			
			with open('rules.txt','a') as file:
				file.write('\n'+str(self.rule_ADD.get('1.0',tk.END).replace('\n','')))
				file.close()
				messagebox.showinfo("Info","kural eklendi")	
				
		
		self.add_rule=tk.Tk()
		self.add_rule.config(bg='green')
		width_of_screen=self.window.winfo_screenwidth()/2
		height_of_screen=self.window.winfo_screenheight()/2
		self.rule_ADD=tk.Text(self.add_rule,width=80,height=8)
		self.rule_ADD.pack(pady=5)
		self.rule_addbtn=tk.Button(self.add_rule,text='ekle',command=ekle).pack(pady=5)
		self.add_rule.geometry("500x340+%d+%d"%( (width_of_screen-250),(height_of_screen-190)  ))
		self.add_rule.resizable(width=False,height=False)
		self.add_rule.mainloop()
	async def tstasy(self):
		print('async deneme')		
	def rule_lst(self):
	 	rulewindow=tk.Tk()
	 	width_of_screen=self.window.winfo_screenwidth()/2
	 	height_of_screen=self.window.winfo_screenheight()/2
	 	rulewindow.geometry("500x340+%d+%d"%( (width_of_screen-250),(height_of_screen-190)  ))
	 	rulewindow.resizable(width=False,height=False)
	 	rulelist=tk.Frame(rulewindow)
	 	textlst=tk.Listbox(rulelist,width=50,height=20)
	 	texscrol=tk.Scrollbar(rulelist)
	 	texscrol.config(command=textlst.yview)
	 	textlst.config(yscrollcommand=texscrol.set)


	 	texscrol.grid(row=0,column=1,sticky='nes')
	 	textlst.grid(row=0,column=0)
	 	print(textlst)
	 	rulelist.pack()
	 	with open('rules.txt','r') as file:
	 		for row in file.readlines():
	 			textlst.insert(tk.END,row)
	 	rulewindow.mainloop()
		
	def rule_matches(self):

		rulewindow=tk.Tk()
	
		width_of_screen=self.window.winfo_screenwidth()/2
		height_of_screen=self.window.winfo_screenheight()/2

		rulewindow.geometry("500x340+%d+%d"%( (width_of_screen-250),(height_of_screen-190)  ))
		rulewindow.resizable(width=False,height=False)
		

		rulelist=tk.Frame(rulewindow)
		textlst=tk.Listbox(rulelist,width=50,height=20)
		textscrol=tk.Scrollbar(rulelist)
		textscrol.config(command=textlst.yview)
		textlst.config(yscrollcommand=textscrol.set)
		textscrol.grid(row=0,column=1,sticky='nes')
		textlst.grid(row=0,column=0)
		print(textlst)
		rulelist.pack()
		count=0
		try:
			with open('log.txt','r') as file:
				for row in file.readlines():
					textlst.insert(tk.END,row)
					if count==20:
						count=0

						time.sleep(1)
						
				count+=1
		except:
			pass
	

	def bandwidth_guncelle(self):
		
	
		try:
			
			self.label_bandwith['text']=src_ip
		except:
			pass
		self.window.after(1000, self.bandwidth_guncelle)
	def main_screen(self):
		self.menu_frame=tk.Frame(self.window,bg='green',width=200,height=680)
		self.label_menu=tk.Label(self.menu_frame,text='menu',anchor='nw',bg='blue',width=30)
		self.btn1=tk.Button(self.menu_frame,text='add rule',width=30,command=self.add_rule)
		self.btn2=tk.Button(self.menu_frame,text='rule matches',width=30,command=self.rule_matches)
		self.btn3=tk.Button(self.menu_frame,text='rule list',width=30,command=self.rule_lst)
		self.btn4=tk.Button(self.menu_frame,text='pcap read',width=30,command=self.add_rule)
		
		self.menu_frame.grid_propagate(0)

		
		self.label_menu.grid()
		self.btn1.grid()
		self.btn2.grid()
		self.btn3.grid()



		self.trafic_frame=tk.Frame(self.window,bg='#ccffcc',width=800,height=340)
		self.label_ip=tk.Label(self.trafic_frame,text='ip trafik',anchor='nw',justify='left',bg='red')
		self.trafic_frame.grid_propagate(0)

		self.lst=tk.Listbox(self.trafic_frame,width=130,height=18)
		self.lstscrool=tk.Scrollbar(self.trafic_frame)
		self.lstscrool.config(command=self.lst.yview)
		self.lst.config(yscrollcommand=self.lstscrool.set)
		self.lst.bind('<<ListboxSelect>>',self.listbox_click)

		self.lstscrool.grid(row=1,column=1,sticky='nes')
		self.lst.grid(row=1,column=0)

		# self.traf_scr=tk.Scrollbar(self.trafic_frame,command=self.canvas.yview,orient=tk.VERTICAL)
		# self.canvas.config(yscrollcommand=self.traf_scr.set)
		
		
		self.label_ip.grid(row=0,column=0)
		
		# self.traf_scr.grid(row=1,column=0,sticky='nes')

		self.bandwframe=tk.Frame(self.window,bg='green',width=400,height=340)
		
		self.label_bandwith=tk.Label(self.bandwframe,text='bandwith',anchor='nw',justify='left',bg='blue')
	
		self.bandwframe.grid_propagate(0)

		# self.label_bandwith.grid(row=0,column=0)


		self.analysis_frame=tk.Frame(self.window,bg='green',width=800,height=340)
		self.label_trafik_istatistik=tk.Label(self.analysis_frame,text='Raw Data',anchor='nw',justify='left',bg='red')
		self.analysis_frame.grid_propagate(0)
		self.rawlist=tk.Listbox(self.analysis_frame,width=130,height=18)
		self.rawscrol=tk.Scrollbar(self.analysis_frame)
		self.rawscrol.config(command=self.rawlist.yview)
		self.rawlist.config(yscrollcommand=self.rawscrol.set)

		self.rawscrol.grid(row=1,column=1,sticky='nes')
		self.rawlist.grid(row=1,column=0)

		self.label_trafik_istatistik.grid(row=0,column=0,sticky='w')
		


		self.mlframe=tk.Frame(self.window,bg='red',width=400,height=340)
		self.label_trafik_MListatistik=tk.Label(self.mlframe,text='MLanalysis',anchor='e',bg='#ccffcc')
		self.mlframe.grid_propagate(0)
		
		
		self.label_trafik_MListatistik.grid(row=0,column=1)
		

		self.menu_frame.grid(row=0,column=0,rowspan=2,sticky='wn')
		self.trafic_frame.grid(row=0,column=1,sticky='nw')
		self.bandwframe.grid(row=0,column=2,sticky='ne')
		self.analysis_frame.grid(row=1,column=1,columnspan=2,sticky='sw')
		

def func():
	pass

def main():
	# tst=	Thread(target=sniff)
	# tst.daemon=True
	# tst.start()
	global dataset_Create
	dataset_Create=1
	global interface
	interface='Wi-Fi'
	app=tk.Tk()
	
	func=Thread(target=sniff.main,args=[interface])
	func.daemon=True
	func.start()
	App=ids_app(app)


	app.mainloop()

if __name__ == '__main__':
	main()







# import socket
# from threading import Thread
# import sys
# import os
# import time
# from sys import stdout
# from sys import argv
# import ifaddr
# import tkinter as tk
# import pandas as pd
# global s
# global host
# global data
# global devam
# global data_for_learn


# def dinle():
# 	global s
# 	global data
# 	global devam
# 	global data_for_learn
# 	data_for_learn ={}
	
	
# 	print('started...')
# 	devam=''
# 	while True:
# 		data=s.recvfrom(65565)[1]
		
# 		if devam =='1':
# 			sys.exit()
# 		else:
# 			pass
			
# 			# num=int.from_bytes(data[9:10],byteorder='big')
# 			# if count ==80:
# 			# 	sys.exit()
# 			# 	break
# def menu():
# 	adapters=ifaddr.get_adapters()
# 	ips={}
# 	ips['exit']=1
# 	ips['default']='255.255.255.255'

# 	for adapter in adapters:
# 		ips[adapter.nice_name]=''
# 		for ip in adapter.ips:
# 			if len(ip.ip)<33:
# 				ips[adapter.nice_name]=ip.ip
# 	keys=[]
# 	for key in enumerate(ips):
# 		keys.append(key[1])
# 		print(str(key[0])+' ### '+str(key[1])+'  --->>>  '+str(ips[key[1]]))
# 	choice=int(input('>>'))
# 	return ips[keys[choice]]

# def win():
	
# 	def degis(label1,window):
# 		sayac=0
# 		while True:
# 			if data:
# 				if not(data[0].__contains__('192')):
# 					label1['text']+=str(data[0]+'\n')
# 					if sayac==4:
# 						time.sleep(1)
# 					sayac+=1
# 			if sayac==5:
# 				sayac=0
# 				label1['text']=' '
# 			if devam:
# 				window.destroy()
# 				this._stop()
			
	
# 	global data
# 	window=tk.Tk()
# 	window.configure(width=600, height=600)
# 	window.resizable(width=False,height=False)
# 	tst=tk.StringVar()
# 	label1=tk.Label(window,text=tst,width=15,height=15)
# 	label1.pack()
# 	Thread(target=degis,args=(label1,window)).start()

# 	window.mainloop()


# def ids():	
# 	global s
# 	global host
# 	global data
# 	global devam


# 	s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP)

# 	host=menu()
# 	if host==1:
# 		sys.exit()
# 	#print(host)
# 	#print(socket.gethostname())
# 	#print(help(s.ioctl))
# 	s.bind((host,0))
# 	# print(s.ioctl)
# 	s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,3)
# 	s.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)
# 	Thread(target=dinle).start()
# 	window_thread=Thread(target=win)
# 	#window_thread.start()

# 	#s.ioctl(socket.SIO_RCVALL,socket.RCVALL_OFF)

# 	data=()
# 	count=0

# 	while True:
# 		if data:
# 			if not(data[0].__contains__('192')):
# 				# sys.stdout.write(data[0])
# 				print(data[0])
# 				count+=1
# 		if count==50:
# 			count=0
# 			try: 
# 				for sec in range(5,0,-1):
# 					print('\rwaiting for %d ...'%sec,flush=True,end='')
# 					time.sleep(1)	
# 				print('\n')	
# 			except KeyboardInterrupt:
# 				devam=input('\n:')
# 				if devam:
# 					window_thread._stop()
# 					sys.exit()
# 					break
			



















'''----------=======-----packet-creaation-----------------------'''
#import socket

# s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
# s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# ip_header  = b'\x45\x00\x00\x28'  # Version, IHL, Type of Service | Total Length
# ip_header += b'\xab\xcd\x00\x00'  # Identification | Flags, Fragment Offset
# ip_header += b'\x40\x06\xa6\xec'  # TTL, Protocol | Header Checksum
# ip_header += b'\x0a\x0a\x0a\x02'  # Source Address
# ip_header += b'\x0a\x0a\x0a\x01'  # Destination Address

# tcp_header  = b'\x30\x39\x00\x50' # Source Port | Destination Port
# tcp_header += b'\x00\x00\x00\x00' # Sequence Number
# tcp_header += b'\x00\x00\x00\x00' # Acknowledgement Number
# tcp_header += b'\x50\x02\x71\x10' # Data Offset, Reserved, Flags | Window Size
# tcp_header += b'\xe6\x32\x00\x00' # Checksum | Urgent Pointer

# packet = ip_header + tcp_header
# s.sendto(packet, ('10.10.10.1', 0))
############
'''
import socket

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(("eth0", 0))

ethernet  = b'\x00\x0c\x29\xd3\xbe\xd6' # MAC Adresse Ziel
ethernet += b'\x00\x0c\x29\xe0\xc4\xaf' # MAC Adresse Quelle
ethernet += b'\x08\x00'                 # Protocol-Type: IPv4

ip_header  = b'\x45\x00\x00\x28'  # Version, IHL, Type of Service | Total Length
ip_header += b'\xab\xcd\x00\x00'  # Identification | Flags, Fragment Offset
ip_header += b'\x40\x06\xa6\xec'  # TTL, Protocol | Header Checksum
ip_header += b'\x0a\x0a\x0a\x02'  # Source Address
ip_header += b'\x0a\x0a\x0a\x01'  # Destination Address

tcp_header  = b'\x30\x39\x00\x50' # Source Port | Destination Port
tcp_header += b'\x00\x00\x00\x00' # Sequence Number
tcp_header += b'\x00\x00\x00\x00' # Acknowledgement Number
tcp_header += b'\x50\x02\x71\x10' # Data Offset, Reserved, Flags | Window Size
tcp_header += b'\xe6\x32\x00\x00' # Checksum | Urgent Pointer

packet = ethernet + ip_header + tcp_header
s.send(packet)
'''
###-------------======---packet-creation----------------------###













# import socket

# # the public network interface
# HOST = socket.gethostbyname(socket.gethostname())

# # create a raw socket and bind it to the public interface
# s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
# s.bind(('192.168.43.69', 0))

# # Include IP headers
# s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# # receive all packages
# s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# # receive a package

# print(s.recvfrom(443))

# # disabled promiscuous mode
# s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
