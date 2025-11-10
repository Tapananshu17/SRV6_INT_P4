import socket
import sys, time
from lookup_path import lookup
import os

intf = sys.argv[1]
src = sys.argv[2]
dst = sys.argv[3]
rate = float(sys.argv[4]) # Mbps
rate = rate / 8 # MBps
if len(sys.argv) >= 6:L = int(sys.argv[5])
else:L = 500
if len(sys.argv) >= 7:n = int(sys.argv[6])
else:n =1
if len(sys.argv) >= 7:MAX_BYTES = int(sys.argv[7])
else:MAX_BYTES = 5
MAX_BYTES = MAX_BYTES * 1000000

burst = n*L
dt = burst/rate # micro-seconds
dt = dt * 1e-6 # seconds
UDP_SEND_PORT = 9999

random_bytes = os.urandom(L - 14 - 40 - 8)
IP_dst,MAC_dst = lookup(src,dst)
addr = (IP_dst,UDP_SEND_PORT)



t = time.time() + dt
s = socket.socket(socket.AF_INET6,socket.SOCK_DGRAM)
packet_bytes = 0
with open("tmp/flood_start.txt",'w') as f: print(time.time(),file=f,flush=True)
try:
    while packet_bytes < MAX_BYTES:
        # This loop consumes CPU cycles to wait precisely
        while time.time() < t:pass
        for i in range(n):s.sendto(random_bytes,addr)
        packet_bytes += burst
        t += dt
    s.close()
    with open("tmp/flood_end.txt",'w') as f: 
        print(time.time(),file= f,flush=True)
        print('bytes sent:',packet_bytes,file=f,flush=True)
    time.sleep(1) # let the receiver get everything
except KeyboardInterrupt:
    print("stopped by Ctrl+C")
    s.close()
    with open("tmp/flood_end.txt",'w') as f: 
        print(t,file= f,flush=True)
        print('packets sent:',packets,file=f,flush=True)