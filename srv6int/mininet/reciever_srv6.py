"""
parses packet with INT and SRv6.
Outputs to received.txt
Logs to receiver_status.txt
"""

import socket,binascii

f = open('tmp/received.txt', 'w')
g = open('tmp/reciever_status.txt','w')
hex_to_bin = {hex(i)[2:]:'0'*(4-len(bin(i)[2:]))+bin(i)[2:] for i in range(16)}
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
print("socket ready",file=g,flush=True)
while True:
    packet,addr = s.recvfrom(65535)
    pack_bytes = str(binascii.hexlify(packet))[2:-1]
    D = {}
    D["dst_MAC"] = pack_bytes[0:12]
    D["src_MAC"] = pack_bytes[12:24]
    D["ethertype"] = ethertype = pack_bytes[24:28]
    print("Recieved packet with ethertype ", ethertype,"on",addr[0],file=f,flush=True)
    if ethertype == 'ffff':
        D["inth"] = inth = pack_bytes[28:36]
        flag_and_M = inth[0]
        hop_count = inth[1:3]
        inst_bitmap = inth[3:8]
        n = int(hop_count,16)
        D['n'] = n
        bitmap = ''.join([hex_to_bin[c] for c in inst_bitmap])
        D['bitmap'] = bitmap
        bitmap = (int(c) for c in bitmap[:10])
        meta_sizes = [8,8,8,48,48,16,24,32,32,32]
        l = sum(x*y for x,y in zip(bitmap,meta_sizes))
        D["metadata bits"] = l
        l = l//4
        D["meta_list"] = pack_bytes[36:36+n*l]
        D["IPv6feilds"] = pack_bytes[36+n*l:36+n*l+16] # 8 bytes
        D["dst_IP"] = pack_bytes[36+n*l+16:36+n*l+32+16] # 16 bytes
        D["src_IP"] = pack_bytes[36+n*l+16+32:36+n*l+64+16] # 16 bytes
        D["srv6"] = pack_bytes[36+n*l+64+16:]
        print("Received INT probe:", pack_bytes,file=f,flush=True)
        for feild,val in D.items():print('\t',feild,":",val,file=f,flush=True)
sock.close()

print("socket closed",file=g,flush=True)

f.close()
g.close()
