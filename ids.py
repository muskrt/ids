

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
from pathlib import Path
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
		if not(Path('log.txt').is_file()) :
			open('rules.txt','w')
		if not(Path('rules.txt').is_file()) :
			open('rules.txt','w')	
		
		
		
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
	func=Thread(target=sniff.main)
	func.daemon=True
	func.start()

	App=ids_app(app)


	app.mainloop()

if __name__ == '__main__':
	main()







