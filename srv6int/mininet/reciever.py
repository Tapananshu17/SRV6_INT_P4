"""
parses packet with INT and SRv6.
Outputs to received.txt
Logs to receiver_status.txt
Sends metadata back to sender via UDP.
"""

import socket, binascii, json, sys

# Define UDP port for results
UDP_RETURN_PORT = 9999

# Pre-compute hex-to-binary conversion table
HEX_TO_BIN = {hex(i)[2:]:'0'*(4-len(bin(i)[2:]))+bin(i)[2:] for i in range(16)}

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
        print(f"Payload size: {len(payload_bytes)} bytes", file=log_file, flush=True)
        print(f"Payload preview: {payload_bytes[:100]}", file=log_file, flush=True)

    except Exception as e:
        print(f"Error sending UDP results: {e}", file=log_file, flush=True)
        import traceback
        traceback.print_exc(file=log_file)


def parse_meta_list(meta_list, bitmap_bits, hop_count, nibbles):
    """
    Parses the metadata list based on the bitmap and hop count.
    """
    parse_meta_list = []
    for i in range(hop_count):
        meta = meta_list[i*nibbles:(i+1)*nibbles]
        field_names = ["switchID","inPortID","ePortID","inTimeStamp",
        "eTimeStamp","qDepth","qDelay","proDelay","linkLatency","leftBand"]
        field_sizes = [8,8,8,48,48,16,24,32,32,32]
        field_sizes = [x//4 for x in field_sizes] # convert to nibbles
        parsed_metadata = {}
        for j in range(10):
            if not bitmap_bits[j]: 
                continue
            val = meta[:field_sizes[j]]
            meta = meta[field_sizes[j]:]
            name = field_names[j]
            val = int(val, 16)
            parsed_metadata[name] = val
        parse_meta_list.append(parsed_metadata)
    return parse_meta_list

def parse_and_process_probe(pack_bytes, f, g):
    """
    Parses the INT/SRv6 probe packet and orchestrates sending the reply.
    """
    D = {}
    try:
        D["dst_MAC"] = pack_bytes[0:12]
        D["src_MAC"] = pack_bytes[12:24]
        D["ethertype"] = pack_bytes[24:28] # 'ffff'
        
        D["inth"] = inth = pack_bytes[28:36]
        flag_and_M = inth[0]
        hop_count = inth[1:3]
        inst_bitmap = inth[3:8]
        
        n = int(hop_count, 16)
        D['n'] = n
        
        bitmap = ''.join([HEX_TO_BIN[c] for c in inst_bitmap])
        D['bitmap'] = bitmap
        
        bitmap_bits = [int(c) for c in bitmap[:10]]
        meta_sizes = [8,8,8,48,48,16,24,32,32,32]
        l = sum(x*y for x,y in zip(bitmap_bits, meta_sizes))
        D["metadata bits"] = l
        l = l//4 # Convert bits to hex chars (nibbles)
        
        D["meta_list"] = pack_bytes[36:36+n*l]
        D["IPv6fields"] = pack_bytes[36+n*l:36+n*l+16]
        D["src_IP_hex"] = pack_bytes[36+n*l+16:36+n*l+32+16]
        D["dst_IP_hex"] = pack_bytes[36+n*l+16+32:36+n*l+64+16]
        D["srv6"] = pack_bytes[36+n*l+64+16:]
        
        print("Received INT probe:", pack_bytes, file=f, flush=True)
        for field, val in D.items():
            print('\t', field, ":", val, file=f, flush=True)
        
        meta_list = parse_meta_list(D["meta_list"], bitmap_bits, n, l)
        print("\tParsed meta list:", file=f, flush=True)
        for metadata in meta_list:
            print('\t', metadata, file=f, flush=True)
        
        # --- Prepare and Send Reply ---
        print("Converting source IP...", file=g, flush=True)
        
        # Convert hex IP string to a usable IPv6 address
        src_ip_hex = D["src_IP_hex"]
        print(f"Source IP hex: {src_ip_hex}", file=g, flush=True)
        
        # Make sure it's 32 hex chars (128 bits / 4 = 32)
        if len(src_ip_hex) != 32:
            print(f"ERROR: Source IP hex length is {len(src_ip_hex)}, expected 32", file=g, flush=True)
            return
        
        src_ip_addr = socket.inet_ntop(socket.AF_INET6, bytes.fromhex(src_ip_hex))
        print(f"Source IP address: {src_ip_addr}", file=g, flush=True)
        
        # Create JSON payload
        payload_str = json.dumps(meta_list)
        payload_bytes = payload_str.encode('utf-8')
        
        print(f"JSON payload created: {len(payload_bytes)} bytes", file=g, flush=True)
        print(f"JSON preview: {payload_str[:200]}", file=g, flush=True)

        print(f"Preparing to send results back to [{src_ip_addr}]:{UDP_RETURN_PORT}", file=g, flush=True)
        send_results_back(src_ip_addr, UDP_RETURN_PORT, payload_bytes, g)
        
    except Exception as e:
        print(f"Error during packet parsing: {e}", file=g, flush=True)
        print(f"Problematic packet bytes: {pack_bytes}", file=g, flush=True)
        import traceback
        traceback.print_exc(file=g)

if __name__ == "__main__":
    try:
        if len(sys.argv) == 1:
            f = 'tmp/received.txt'
            g = 'tmp/receiver_status.txt'
        else:
            f = sys.argv[1]
            g = sys.argv[2]
        f = open(f, 'w')
        g = open(g, 'w') 
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        print("Socket ready", file=g, flush=True)
        
        while True:
            packet, addr = s.recvfrom(65535)
            pack_bytes = str(binascii.hexlify(packet))[2:-1]
            ethertype = pack_bytes[24:28]
            
            print(f"Received packet with ethertype {ethertype} on {addr[0]}", file=g, flush=True)
            
            if ethertype == 'ffff':
                print("Processing INT probe packet...", file=g, flush=True)
                parse_and_process_probe(pack_bytes, f, g)
                
    except KeyboardInterrupt:
        print("Receiver stopped by user", file=g, flush=True)
    except Exception as e:
        print(f"Critical error in main: {e}", file=g, flush=True)
        import traceback
        traceback.print_exc(file=g)
    finally:
        print("Closing files and socket.", file=g, flush=True)
        if 's' in locals():
            s.close()
        if 'f' in locals():
            f.close()
        if 'g' in locals():
            g.close()
