import socket, sys, time, threading, binascii
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

UDP_RETURN_PORT = 9999

def build_srh(sids):
    srh = IPv6ExtHdrRouting(
        type=4,
        addresses=sids
    )
    raw = bytearray(bytes(srh))
    raw[4] = len(sids) - 1 
    return IPv6ExtHdrRouting(bytes(raw))

def send_probe_packet(pkt, intf):
    try:
        sendp(pkt, iface=intf, verbose=False)
        print(f"Probe packet sent on interface {intf}")
    except Exception as e:
        print(f"Error sending packet: {e}")

def listen_for_results(listen_ip, port, interface):
    s_udp = None
    try:
        # Use AF_PACKET to get Ethernet headers (like receiver does)
        s_udp = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        # Don't bind to a specific interface
        # s_udp.bind((interface, 0)) # NO
        # print(f"Listener bound to interface {interface}") # NO
        print(f"Waiting for INT results on [{listen_ip}]:{port}...")

        while True:
            try:
                data, addr = s_udp.recvfrom(2048)

                # skip loopback
                if addr[2] == 4:continue
                
                # Convert to hex for easier parsing
                pack_bytes = binascii.hexlify(data).decode('ascii')
                
                print(f"[Listener] Raw packet of length {len(data)} bytes received on {addr[0]}!")
                # print(f"Raw packet length: {len(data)} bytes")
                # print(f"Packet hex (first 200 chars): {pack_bytes[:200]}")
                
                # Ethernet header: 14 bytes (28 hex chars)
                # Check EtherType (bytes 12-14, hex chars 24-28)
                ethertype = pack_bytes[24:28]
                # print(f"EtherType: {ethertype}")
                
                # 86dd = IPv6
                if ethertype != '86dd':
                    print(f"Skipping non-IPv6 packet (ethertype: {ethertype})")
                    continue
                
                # IPv6 header starts at byte 14 (hex char 28), is 40 bytes (80 hex chars)
                ipv6_header_start = 28
                
                # Get next header field (byte 6 of IPv6 header = hex chars 40-42)
                next_header = pack_bytes[ipv6_header_start + 12:ipv6_header_start + 14]
                next_header_int = int(next_header, 16)
                # print(f"Next header: {next_header_int} (17=UDP)")
                
                # UDP = 17 (0x11)
                if next_header_int != 17:
                    print(f"Skipping non-UDP packet (next header: {next_header_int})")
                    continue
                
                # UDP header starts after Ethernet (28) + IPv6 (80) = 108 hex chars
                udp_start = ipv6_header_start + 80
                udp_header = pack_bytes[udp_start:udp_start + 16]  # 8 bytes = 16 hex chars
                
                # Parse UDP header
                src_port = int(udp_header[0:4], 16)
                dst_port = int(udp_header[4:8], 16)
                udp_length = int(udp_header[8:12], 16)
                
                # print(f"UDP src_port: {src_port}, dst_port: {dst_port}, length: {udp_length}")
                
                # Verify it's for our port
                if dst_port != port:
                    print(f"Skipping packet - wrong destination port (expected {port}, got {dst_port})")
                    continue
                
                # Payload starts after Ethernet (28) + IPv6 (80) + UDP (16) = 124 hex chars
                payload_start = udp_start + 16
                payload_hex = pack_bytes[payload_start:]
                
                # Convert hex payload to bytes
                payload_bytes = bytes.fromhex(payload_hex)
                
                print("--- Received Telemetry Results ---")
                print(f"Payload length: {len(payload_bytes)} bytes")
                # print(f"Payload (raw): {payload_bytes}")
                
                # Decode JSON payload
                payload_str = payload_bytes.decode('utf-8')
                # print(f"Payload (decoded): {payload_str}")
                
                meta_list = json.loads(payload_str)
                
                print("Parsed Hop Data:")
                for i, hop_data in enumerate(meta_list):
                    print(f"  [Hop {i+1}]")
                    for key, value in hop_data.items():
                        print(f"    {key} : {value}")
                print("------------------------------------")
                
                # Exit after receiving one result
                break
            
            except json.JSONDecodeError as je:
                print(f"\n--- JSON decode error: {je} ---")
                print(f"Payload string was: {payload_bytes[:200]}")
            except UnicodeDecodeError as ue:
                print(f"\n--- Unicode decode error: {ue} ---")
                print(f"Raw payload bytes (first 100): {payload_bytes[:100].hex()}")
            except Exception as e:
                print(f"\n--- Error processing one packet (will continue): {e} ---")
                import traceback
                traceback.print_exc()
        
    except Exception as e:
        print(f"\n--- CRITICAL Error in listener thread: {e} ---")
        import traceback
        traceback.print_exc()
        
    finally:
        if s_udp:s_udp.close()

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
    print("Packet Information")
    print("\tsrc MAC :",srcMAC)
    print("\tsrc IP :",srcIP)
    print("\tdst MAC :",dstMAC)
    print("\tdst IP :",dstIP)
    print('\tsrv6 SIDs :',srv6_sids)

    inth = INTHdr(flag = 1, inst_bitmap=inst_bitmap, M=0, hop_count=0)
    # print("INT header :",bytes(inth).hex())
    srv6_stuff = build_srh(srv6_sids)
    # print("SRv6 stuff :",bytes(srv6_stuff).hex())
    
    pkt = (
        Ether(src=srcMAC, dst=dstMAC) /
        inth /
        IPv6(src=srcIP, dst=dstIP) /
        srv6_stuff
    )
    # print("Crafted Packet:",bytes(pkt).hex())
    print("Crafted probe!")

    # Start the listener thread first
    listener_thread = threading.Thread(
        target=listen_for_results, 
        args=(srcIP, UDP_RETURN_PORT, intf), 
        daemon=True
    )
    listener_thread.start()

    # Give the listener a moment to bind
    time.sleep(0.5) 

    print("Sending packet...")
    send_probe_packet(pkt, intf)
    
    print("Waiting for response (timeout: 30 seconds)...")
    listener_thread.join(timeout=30.0)
    
    if listener_thread.is_alive():
        print("Timeout: No response received within 30 seconds")
    
    print("-"*10 + "sender.py finished" + "-"*10)