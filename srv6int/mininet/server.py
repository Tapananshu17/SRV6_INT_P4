"""
parses packet with INT and SRv6.
Outputs to received.txt
Logs to receiver_status.txt
Sends metadata back to sender via UDP.
"""

import socket, sys, time, threading
from scapy.all import *
from scapy.layers.inet6 import IPv6ExtHdrRouting
import json, binascii
from lookup_path import *
import queue,threading

# Define UDP port for results
L4_PORT = 9999

# Pre-compute hex-to-binary conversion table
HEX_TO_BIN = {hex(i)[2:]:'0'*(4-len(bin(i)[2:]))+bin(i)[2:] for i in range(16)}

# Define custom INT header (example placeholder)
class INTHdr(Packet):
    name = "INT"
    fields_desc = [
        BitField("flag", 0, 2),
        BitField("M", 0, 2),
        BitField("hop_count", 0, 8),
        BitField("inst_bitmap", 0, 10),
        BitField("reserved", 0, 10)
    ]

bind_layers(Ether, INTHdr, type=0xFFFF)  # INT


def build_srh(sids):
    """
    Builds SRv6 extension header and segment list given the SIDs 
    """
    srh = IPv6ExtHdrRouting(
        type=4,
        addresses=sids
    )
    raw = bytearray(bytes(srh))
    raw[4] = len(sids) - 1 # byte 4 = lastentry
    return IPv6ExtHdrRouting(bytes(raw))

def send_probe_packet(pkt, intf, s:socket.socket=None, log=True, f= None, g= None):
    """Sends the crafted probe packet."""
    try:
        if s is None: sendp(pkt, iface=intf, verbose=False, socket=s)
        else: s.send(pkt)
        if log : print(f"Probe packet sent on interface {intf}", file=f, flush=True)
    except Exception as e:
        print(f"Error sending packet: {e}", file=g, flush=True)


def send_results_back(destination_ip, port, payload_bytes, log_file):
    """
    Sends the processed results back to the sender via UDP.
    """
    try:
        # Create a new socket to send the UDP reply
        udp_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        udp_sock.sendto(payload_bytes, (destination_ip, port))
        udp_sock.close()
        
        print(f"Sent metadata results to [{destination_ip}]:{port}", file=log_file, flush=True)

    except Exception as e:
        print(f"Error sending UDP results: {e}", file=log_file, flush=True)

def parse_meta_list(meta_list,bitmap_bits,hop_count,nibbles,f)-> list[dict]:
    parsed_meta_list = []
    feild_names = ["switchID","inPortID","ePortID","inTimeStamp",
        "eTimeStamp","qDepth","qDelay","proDelay","linkLatency","leftBand",]
    feild_sizes = [8,8,8,48,48,16,24,32,32,32]
    feild_sizes = [x//4 for x in feild_sizes] # nibbles
    for i in range(hop_count):
        Meta = meta_list[i*nibbles:(i+1)*nibbles]
        parsed_metadata = {}
        for j in range(10):
            if not bitmap_bits[j] : continue
            val = Meta[:feild_sizes[j]]
            Meta = Meta[feild_sizes[j]:]
            name = feild_names[j]
            val = int(val,16)
            parsed_metadata[name] = val
        parsed_meta_list.append(parsed_metadata)
    return parsed_meta_list


def parse_and_process_probe(pack_bytes, f=None, g=None, debug=True):
    """
    Parses the INT/SRv6 probe packet and stores data in a file.
    """
    D = {}
    def log(*args,file=f,**kwargs):
        if debug : print(*args,file=f,flush=True,**kwargs)
    try:
        if debug:
            D["dst_MAC"] = pack_bytes[0:12]
            D["src_MAC"] = pack_bytes[12:24]
            D["ethertype"] = pack_bytes[24:28] # 'ffff'
        
        inth = pack_bytes[28:36]
        flag_and_M = inth[0]
        hop_count = inth[1:3]
        inst_bitmap = inth[3:8]

        if debug: D["inth"] = inth
        
        n = int(hop_count,16)
        if debug: D['n'] = n
        
        bitmap = ''.join([HEX_TO_BIN[c] for c in inst_bitmap])
        if debug: D['bitmap'] = bitmap
        
        bitmap_bits = [int(c) for c in bitmap[:10]]
        meta_sizes = [8,8,8,48,48,16,24,32,32,32]
        l = sum(x*y for x,y in zip(bitmap_bits,meta_sizes)) // 4
        if debug:
            if debug: D["metadata bytes"] = l//2
            D["meta_list"] = pack_bytes[36:36+n*l]
            D["IPv6feilds"] = pack_bytes[36+n*l:36+n*l+16]
            D["dst_IP_hex"] = pack_bytes[36+n*l+16:36+n*l+32+16]
            D["src_IP_hex"] = pack_bytes[36+n*l+16+32:36+n*l+64+16]
            D["srv6"] = pack_bytes[36+n*l+64+16:]
            D["SRH"] = pack_bytes[36+n*l+64+16:36+n*l+64+16+16]
            D["SL"] = pack_bytes[36+n*l+64+16+16:]
            log("Received INT Probe:", pack_bytes)
            for feild,val in D.items():log('\t',feild,":",val)
            log("\tParsed meta list:")
        SL = pack_bytes[36+n*l+64+16+16:]
        meta_list = parse_meta_list(pack_bytes[36:36+n*l],bitmap_bits,n,l,f)
        if debug: 
            for metadata in meta_list:log('\t',metadata)
        return SL,meta_list
        
    except Exception as e:
        log(f"Error during packet parsing: {e}", file=g)
        log(f"Problematic packet bytes: {pack_bytes}", file=g)

class Request:
    def __init__(self,receiving_intf=None,src_IP=None,req_type="path",meta_types=None,nodes:str=None):
        self.intf = receiving_intf
        self.IP = IP
        self.rtype = req_type
        self.nodes = nodes
        self.bitmap = meta_types
        self.probe = None
        self.sending = False
    def craft_probe(self):
        global craft_packet
        self.probe = craft_packet(self.intf,self.nodes,self.bitmap)
    def send_probes(self):
        global send_probe_packet
        print("starting service")
        self.sending = True
        while self.sending:
            send_probe_packet(self.probe,self.intf)
            time.sleep(1)
    def fulfill(self,f=None,g=None):
        if self.rtype == "path":
            self.craft_probe()
            self.sending = True
            threading.Thread(target=self.send_probes).start()
            # self.send_probes()
        else: print("request type",self.rtype,"not available",file=f,flush=True)
    def get_data(self,data): # TODO
        print("got data!")
    def close(self):
        self.sending = False

def parse_request(pack_bytes, f, g) -> (Request|None):
    """
    Given a packet, it will parse it the packet is
    """
    # TODO

def craft_packet(intf:str,path:str,inst_bitmap:str=None,debug=True,f=None) -> Packet:
    default_inst_bitmap = 0b0010000000
    current_node,next_node,path = path.split(',',2)
    dstIP,dstMAC =lookup(current_node,next_node)
    if debug:print("Destination IP:",dstIP,"\nDestination MAC",dstMAC,file=f,flush=True)
    srcIP,srcMAC =lookup(next_node,current_node)
    if debug:print("Source IP:",srcIP,"\nSource MAC",srcMAC,file=f,flush=True)
    srv6_sids = path_lookup(next_node,path)
    srv6_sids = srv6_sids[::-1]
    if debug:print("srv6_sids:",srv6_sids,file=f,flush=True)
    if inst_bitmap is not None:inst_bitmap = int(inst_bitmap + "0"*(10-len(inst_bitmap)),2)
    else:inst_bitmap = default_inst_bitmap
    inth = INTHdr(flag = 1, inst_bitmap=inst_bitmap, M=0, hop_count=0)
    if debug:print("INT header :",bytes(inth).hex(),file=f,flush=True)
    srv6_stuff = build_srh(srv6_sids)
    if debug:print("SRv6 extension header:",bytes(srv6_stuff).hex(),file=f,flush=True)
    
    pkt = (
        Ether(src=srcMAC, dst=dstMAC) /
        inth /
        IPv6(src=srcIP, dst=dstIP) /
        srv6_stuff
    )
    if debug:print("Crafted Packet:",bytes(pkt).hex(),file=f,flush=True)

    return pkt

REQUESTS = queue.Queue()
ACTIVE_REQUESTS = queue.Queue()
PROBES = queue.Queue()

def receiver(f=None):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        packet, addr = s.recvfrom(65535)
        pkttype = addr[2]
        if pkttype == 4 : continue # looped back packet
        pack_bytes = str(binascii.hexlify(packet))[2:-1]
        ethertype = pack_bytes[24:28]
        print(f"Received packet with ethertype {ethertype} on {addr[0]}", file=f, flush=True)
        if ethertype=='ffff':
            PROBES.put(pack_bytes)
        elif ethertype == "86dd":
            REQUESTS.put(pack_bytes)

# def sender(f=None,g=None):

DATA:dict[str,queue.Queue] = {}

def probe_parser(f=None,g=None):
    global PROBES,DATA
    while True:
        try: 
            probe = PROBES.get(timeout=0.1)
            path,data = parse_and_process_probe(probe,debug=False)
            print(path)
            print(data)
            if path not in DATA:DATA[path] = queue.Queue()
            DATA[path].put(data)
        except Exception as e:pass
            # print(e)
        time.sleep(0.1)

def request_issuer(f=None,g=None):
    global REQUESTS
    while True:
        try:
            req = REQUESTS.get(timeout=0.1)
            req = parse_request(req, f, g)
            if req is None:continue
            req.fulfill()
            ACTIVE_REQUESTS.put(req)
        except Exception as e:print(e)
        time.sleep(1)


def main(req):
    threading.Thread(target=receiver,daemon=True).start()
    threading.Thread(target=probe_parser,daemon=True).start()
    req.fulfill()
    # threading.Thread(target=request_issuer,daemon=True).start()


def time_probe(req:Request,f=None,g=None,iterations=100,no_scapy = False):
    RD = []
    PD = []
    if req.rtype == "path":
        pkt = craft_packet(req.intf,req.nodes,req.bitmap)
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        if no_scapy:
            s2 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            s2.bind((req.intf,0))
            pkt = bytes(pkt)
        else: 
            s2 = None
            pkt = bytes(pkt)
        timeout = 0.1
        arrived = 0
        for i in range(iterations):
            t1 = 0
            if no_scapy:s2.send(pkt)
            if not no_scapy: send_probe_packet(pkt,req.intf,s2,False,f,g)
            t0 = time.time()
            t0p = t0 + timeout
            while t1 < t0p:
                packet, addr = s.recvfrom(65535)
                if addr[2] == 4 : continue
                pack_bytes = packet.hex()
                ethertype = pack_bytes[24:28]
                t1 = time.time()
                if ethertype!='ffff':continue
                path,data = parse_and_process_probe(pack_bytes, debug=False)
                t2 = time.time()
                RD.append(t1-t0)
                PD.append(t2-t1)
                arrived += 1
                break
            else:
                RD.append(t1-t0)
                PD.append(None)
            time.sleep(0.1)
    from numpy import std,mean,array
    print("Routing delay: mean=",mean(RD),", std=",std(RD))
    print("Processing delay: mean=",mean(PD),", std=",std(PD))
    print("Packets arrived back:",arrived,'/',iterations,'=',round(100*arrived/iterations),'%')
    import matplotlib.pyplot as plt
    plt.hist(1000*array(RD))
    plt.hist(1000*array(PD))
    plt.legend(["Routing Delay","Processing Delay"])
    plt.xlabel("time (ms)")
    plt.ylabel("frequency")
    plt.title("INT delay")
    plt.savefig("mininet/INT_delay.png",format='PNG')
    print("saved to mininet/INT_delay.png")

if __name__=="__main__":
    timeit = ("--time" in sys.argv)
    args = [x for x in sys.argv if not (x.startswith('-'))]
    if any(args[0].startswith(x+str(y)) 
    for x in 'hcrs' for y in range(10)):
        args = args[1:]
    if len(args) == 3:
        intf,path = args[1:]
        req = Request(intf,nodes=path)
        if timeit:time_probe(req)
        else: main(req)
    else:print("Wrong arguments",args,
    "\nUsage: python3 mininet/server.py <interface> <path> [OPTIONS]",
    "\nExample: h3 python3 mininet/server.py h3-eth0 h3,s1,s2,h3 --time")
