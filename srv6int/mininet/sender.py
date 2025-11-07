import socket, sys, time, threading
from scapy.all import *
from scapy.layers.inet6 import IPv6ExtHdrRouting
import json
from lookup_path import *

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

# Define UDP port for results
UDP_RETURN_PORT = 9999

def build_srh(sids):
    srh = IPv6ExtHdrRouting(
        type=4,
        addresses=sids
    )
    raw = bytearray(bytes(srh))
    raw[4] = len(sids) - 1 # byte 4 = lastentry
    return IPv6ExtHdrRouting(bytes(raw))

def send_probe_packet(pkt, intf):
    """Sends the crafted probe packet."""
    try:
        sendp(pkt, iface=intf)
        print(f"Probe packet sent on interface {intf}")
    except Exception as e:
        print(f"Error sending packet: {e}")

def listen_for_results(listen_ip, port):
    print(f"Listener thread started. Waiting for INT results on [{listen_ip}]:{port}...")
    s_udp = None
    try:
        s_udp = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s_udp.bind((listen_ip, port))
        
        data, addr = s_udp.recvfrom(2048)
        
        print("\n--- Received Telemetry Results ---")
        print(f"From: {addr[0]}")
        
        # Decode the data payload sent by receiver.py
        payload = data.decode()
        meta_list = json.loads(payload)
        for key,value in meta_list.items():
            print(f"{key} : {value}")
        print("------------------------------------")
        
    except Exception as e:
        print(f"\n--- Error in listener thread: {e} ---")
    finally:
        if s_udp:
            s_udp.close()
        print("Listener thread exiting.")

if __name__ == "__main__":
    bind_layers(Ether, INTHdr, type=0xFFFF)  # INT

    args = [x for x in sys.argv if not x.startswith("-")]
    if len(args) < 7 and len(args)!=3:
        print("Usage: python sender.py <intf> <srcMAC> <srcIP> <dstMAC> <dstIP> <sid1,sid2,...>")
        sys.exit(1)

    print("arguments parsed")
    intf = args[1]
    if ',' in args[2]:
        path = args[2]
        current_node,next_node,path = path.split(',',2)
        dstIP,dstMAC =lookup(current_node,next_node)
        srcIP,srcMAC =lookup(next_node,current_node)
        srv6_sids = path_lookup(next_node,path)
        srv6_sids = srv6_sids[::-1]
    else:
        srcMAC = args[2]
        srcIP = args[3]
        dstMAC = args[4]
        dstIP = args[5]
        srv6_sids = args[6].split(',')
    print("src MAC :",srcMAC)
    print("src IP :",srcIP)
    print("dst MAC :",dstMAC)
    print("dst IP :",dstIP)
    print('srv6 SIDs :',srv6_sids)

    inth = INTHdr(flag = 1, inst_bitmap=0b0000000100, M=0, hop_count=0)
    print("INT header :",bytes(inth).hex())
    srv6_stuff = build_srh(srv6_sids)
    print("SRv6 stuff :",bytes(srv6_stuff).hex())
    
    pkt = (
        Ether(src=srcMAC, dst=dstMAC) /
        inth /
        IPv6(src=srcIP, dst=dstIP) /
        srv6_stuff
    )
    print("Crafted Packet:",bytes(pkt).hex())

    # Start the listener thread first
    # daemon=True ensures thread exits when main script exits
    listener_thread = threading.Thread(
        target=listen_for_results, 
        args=(srcIP, UDP_RETURN_PORT), 
        daemon=True
    )
    listener_thread.start()

    # Give the listener a moment to bind
    time.sleep(0.1) 

    # Now send the probe
    send_probe_packet(pkt, intf)

    # Wait for the listener thread to finish, with a timeout
    # This keeps the main script alive to see the result
    listener_thread.join(timeout=5.0)
    print("Main script finished.")