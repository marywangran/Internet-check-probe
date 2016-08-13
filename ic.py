#!/usr/local/bin/python

import sys
import time
from time import sleep,ctime

import signal
import threading
from scapy.all import *

target = sys.argv[1]
tot = int(sys.argv[2])
tot_per = int(sys.argv[3])
vl = int(sys.argv[4])
flt = "host " + target + " and icmp"

handle = open("/dev/null", 'w')

out_list = []
in_list = []

def output():
	all = out_list + in_list
	all.sort(lambda x,y:cmp(x[3],y[3]))
	for item in all:
		print item[0], item[1], item[2], item[3]*10
	sys.stdout.flush()
        os._exit(0)

def signal_handler(signal, frame):
	output()

class ThreadWraper(threading.Thread):
	def __init__(self,func,args,name=''):
		threading.Thread.__init__(self)
		self.name=name
		self.func=func
		self.args=args

	def run(self):
		apply(self.func,self.args)

def printrecv(pktdata):
	if ICMP in pktdata and pktdata[ICMP]:
		seq = str(pktdata[ICMP].seq)
		if seq == tot_per + 2:
			return
		if str(pktdata[IP].dst) == target:
    			handle.write('*')
    			handle.flush()
			out_list.append(('+', 1, seq, time.clock()))
		else:
			if vl == 2:
    				handle.write('.')
			else:
			      # 擦除一个字符并用空格替换
    				handle.write('\b \b')
    			handle.flush()
			in_list.append(('-', 0, seq, time.clock()))

def checkstop(pktdata):
	if ICMP in pktdata and pktdata[ICMP]:
		seq = str(pktdata[ICMP].seq)
		if int(seq) == tot_per + 2 and str(pktdata[IP].src) == target:
    			handle.write("\nExit:" + ctime() + '\n')
			output()
			return True
	return False
	
def send_packet():
	times = 0
	while times < tot:
		times += 1
    		send(IP(dst = target)/ICMP(seq = (0, tot_per))/"test", verbose = 0, loop = 1, count = 1)
		#out_list.append(('++++++++', 1, -1, str(time.clock())))
    	send(IP(dst = target)/ICMP(seq = tot_per+2)/"bye", verbose = 0)


def recv_packet():
	sniff(prn = printrecv, store = 1, filter = flt, stop_filter = checkstop)

def startup():
    	handle.write("Start:" + ctime() + '\n')

	send_thread = ThreadWraper(send_packet,(),send_packet.__name__)
	send_thread.setDaemon(True)  
	send_thread.start()

	recv_thread = ThreadWraper(recv_packet,(),recv_packet.__name__)
	recv_thread.setDaemon(True)  
	recv_thread.start()

	signal.pause()

if __name__ == '__main__':
	if vl != 0:
		handle.close()
		handle = sys.stderr
	signal.signal(signal.SIGINT, signal_handler)
	startup()
