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
    try:
        sendp(pkt, iface=intf)
        print(f"Probe packet sent on interface {intf}")
    except Exception as e:
        print(f"Error sending packet: {e}")

def listen_for_results(listen_ip, port):
    s_udp = None
    try:
        s_udp = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_UDP)
        #s_udp.bind((listen_ip, port))
        print(f"Listener thread started. Waiting for INT results on [{listen_ip}]:{port}...")

        while True:
            try:
                data, addr = s_udp.recvfrom(2048)
                
                print(f"\n[Listener] Raw packet received from {addr[0]}! Processing...")
                print("--- Received Telemetry Results ---")
                print(f"From: {addr[0]}")
                
                payload_bytes = data[48:] 
                payload_str = payload_bytes.decode()
                meta_list = json.loads(payload_str)
                
                print("Parsed Hop Data:")
                for i, hop_data in enumerate(meta_list):
                    print(f"  [Hop {i+1}]")
                    for key, value in hop_data.items():
                        print(f"    {key} : {value}")
                print("------------------------------------")
            
            except Exception as e:
                print(f"\n--- Error processing one packet (will continue): {e} ---")
        
    except Exception as e:
        print(f"\n--- CRITICAL Error in listener thread: {e} ---")
        
    finally:
        if s_udp:
            s_udp.close()
        print("Listener thread exiting.")

if __name__ == "__main__":
    bind_layers(Ether, INTHdr, type=0xFFFF)  # INT

    args = [x for x in sys.argv if not x.startswith("-")]
    
    if any(args[0].startswith(x+str(y)) for x in 'chsr' for y in range(10)):
        args = args[1:]

    if (len(args) < 7 and len(args)>4) or (len(args) < 3):
        print("Usage: python3 sender.py <intf> <srcMAC> <srcIP> <dstMAC> <dstIP> <sid1,sid2,...> [<bitmap>]")
        sys.exit(1)

    intf = args[1]
    default_inst_bitmap = 0b0000000100
    if ',' in args[2]:
        path = args[2]
        current_node,next_node,path = path.split(',',2)
        dstIP,dstMAC =lookup(current_node,next_node)
        srcIP,srcMAC =lookup(next_node,current_node)
        srv6_sids = path_lookup(next_node,path)
        srv6_sids = srv6_sids[::-1]
        if len(args) > 3:inst_bitmap = int(args[3] + "0"*(10-len(args[3])),2)
        else:inst_bitmap = default_inst_bitmap
    else:
        srcMAC = args[2]
        srcIP = args[3]
        dstMAC = args[4]
        dstIP = args[5]
        srv6_sids = args[6].split(',')
        if len(args) > 7:inst_bitmap = int(args[7] + "0"*(10-len(args[7])),2)
        else:inst_bitmap = default_inst_bitmap
    print("arguments parsed")
    print("src MAC :",srcMAC)
    print("src IP :",srcIP)
    print("dst MAC :",dstMAC)
    print("dst IP :",dstIP)
    print('srv6 SIDs :',srv6_sids)

    inth = INTHdr(flag = 1, inst_bitmap=inst_bitmap, M=0, hop_count=0)
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

    # try:
    #     while True:
    #         send_probe_packet(pkt, intf)
    #         time.sleep(1) 
    # except KeyboardInterrupt:
    #     print("\nStopping sender...")

    send_probe_packet(pkt, intf)
    listener_thread.join(timeout=30.0)
    print("Main script finished.")
