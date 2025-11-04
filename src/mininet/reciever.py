import socket,sys,binascii

f = open('tmp/received.txt', 'w')
g = open('tmp/reciever_status.txt','w')

INT = ( "--int" in sys.argv)
args = [x for x in sys.argv if not x.startswith("-")]

print("arguments parsed",file=g,flush=True)

if INT:
    iface = args[1]
    print("interface :",iface,file=g,flush=True)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    s.bind((iface, 0))
    print("socket ready",file=g,flush=True)
    while True:
        packet = s.recv(65535)
        pack_bytes = str(binascii.hexlify(packet))[2:-1]
        D = {}
        D["dst_MAC"] = pack_bytes[0:12]
        D["src_MAC"] = pack_bytes[12:24]
        D["ethertype"] = ethertype = pack_bytes[24:28]
        print("Recieved packet with ethertype ", ethertype,file=f,flush=True)
        if ethertype == 'ffff':
            D["inth"] = pack_bytes[28:36]
            D["src_IP"] = pack_bytes[-32:]
            D["dst_IP"] = pack_bytes[-64:-32]
            D["IPv6feilds"] = pack_bytes[-80:-64]
            D["meta_list"] = pack_bytes[36:-80]
            print("Received INT probe:", pack_bytes,file=f,flush=True)
            for feild,val in D.items():print('\t',feild,":",val,file=f,flush=True)

else:
    sock = socket.socket(socket.AF_INET6,socket.SOCK_RAW, socket.IPPROTO_UDP)
    sock.bind(('2001:1:2::1', 5020))   # h2's IPv6 + port
    print("socket ready",file=g,flush=True)
    data, addr = sock.recvfrom(1024)    # Receive 1 datagram
    print('Received from',addr,file=g,flush=True)
    print(data.hex(),file=f,flush=True)
sock.close()

print("socket closed",file=g,flush=True)

f.close()
g.close()
