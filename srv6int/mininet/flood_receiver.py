import socket
from time import time
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
packet_bytes = 0
f = open('tmp/receiver_status.txt','w')
while True:
    print(time(),packet_bytes,file=f,flush=True)
    for i in range(100) : packet_bytes += len(s.recv(65535))