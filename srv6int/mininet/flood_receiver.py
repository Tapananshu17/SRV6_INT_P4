import socket
from time import perf_counter
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
packets = 0
f = open('tmp/receiver_status.txt','w')
while True:
    print(perf_counter(),packets,file=f,flush=True)
    for i in range(1000):s.recv(65535)
    packets += 1000
