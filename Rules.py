import os 
import sys
import socket,struct
import socket,struct
from pathlib import Path
from win10toast import ToastNotifier
import subprocess, ctypes, os, sys
from subprocess import Popen, DEVNULL
import platform

def check_admin():
    """ Force to start application with admin rights """
    try:
        isAdmin = ctypes.windll.shell32.IsUserAnAdmin()
    except AttributeError:
        isAdmin = False
    if not isAdmin:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
def add_rule(rule_name, src):
    """ Add rule to Windows Firewall """
    command1=f"netsh advfirewall firewall add rule name={rule_name}  dir=out remoteip={src} action=block "
    command2=f"netsh advfirewall firewall add rule name={rule_name}  dir=in remoteip={src}  action=block "
    subprocess.call(
        command1, 
        shell=True, 
        stdout=DEVNULL, 
        stderr=DEVNULL
    )
    subprocess.call(
        command2, 
        shell=True, 
        stdout=DEVNULL, 
        stderr=DEVNULL
    )
    print(f"Rule {rule_name} for {src} added")

def modify_rule(rule_name, state):
    """ Enable/Disable specific rule, 0 = Disable / 1 = Enable """
    state, message = ("yes", "Enabled") if state else ("no", "Disabled")
    subprocess.call(
        f"netsh advfirewall firewall set rule name={rule_name} new enable={state}", 
        shell=True, 
        stdout=DEVNULL, 
        stderr=DEVNULL
    )
    print(f"Rule {rule_name} {message}")

# def addressInNetwork1(ip,net):
#    "Is an address in a network"
#    ipaddr = struct.unpack('L',socket.inet_aton(ip))[0]
#    netaddr,bits = net.split('/')
#    netmask = struct.unpack('L',socket.inet_aton(netaddr))[0] & ((2L<<int(bits)-1) - 1)
#    return ipaddr & netmask == netmask

# def makeMask(n):
#     "return a mask of n bits as a long integer"
#     mask=(2'L'<<n-1) - 1
#     return mask

# def dottedQuadToNum(ip):
#     "convert decimal dotted quad string to long integer"
#     print(ip)
#     return struct.unpack('L',socket.inet_aton(ip))[0]

# def networkMask(ip,bits):
#     "Convert a network address to a long integer" 
#     return dottedQuadToNum(ip) & makeMask(bits)

# def addressInNetwork(ip,net):
#    "Is an address in a network"
#    return ip & net == net

# address = dottedQuadToNum("192.168.1.1")
# networka = networkMask("10.0.0.0",24)
# networkb = networkMask("192.168.0.0",24)
# print (address,networka,networkb)

def ip_to_binary(ip):
    octet_list_int = ip.split(".")
    octet_list_bin = [format(int(i), '08b') for i in octet_list_int]
    binary = ("").join(octet_list_bin)
    return binary


def get_addr_network(address, net_size):
    #Convert ip address to 32 bit binary
    ip_bin = ip_to_binary(address)
    #Extract Network ID from 32 binary
    network = ip_bin[0:32-(32-net_size)]    
    return network
def ip_in_prefix(ip_address, prefix):
    #CIDR based separation of address and network size
    [prefix_address, net_size] = prefix.split("/")
    #Convert string to int
    net_size = int(net_size)
    #Get the network ID of both prefix and ip based net size
    prefix_network = get_addr_network(prefix_address, net_size)
    ip_network = get_addr_network(ip_address, net_size)
    return ip_network == prefix_network

def check_packet(src,sprt,proto,dst,dprt):
    logs=open('log.txt','r').readlines()
    toaster=ToastNotifier()
    
    
    rules=open('rules.txt','r')
    packet=(src+sprt+proto+dst+dprt)
    # print(packet)
    for item in rules.readlines():
        item=item.replace(' ','')
        item=item.split('\n')
        
        if item[0]==packet and ((item[0]+'\n')not in logs):
            if platform.system()=='Windows':
                check_admin()
                add_rule('deneme',src)
            toaster.show_toast('Notification!','Alert!',threaded=True,icon_path=None,duration=5)
            if Path('log.txt').is_file():
                open('log.txt','a').write(str(packet)+'\n')
            else:
                open('log.txt','w').write(str(packet)+'\n')


       


# if __name__ == '__main__':
#     check_admin()
#     add_rule("RULE_NAME", "PATH_TO_FILE")
#     modify_rule("RULE_NAME", 1)