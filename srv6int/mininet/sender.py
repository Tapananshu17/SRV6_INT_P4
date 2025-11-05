import socket,sys
from scapy.all import *

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

INT = ( "--int" in sys.argv)
args = [x for x in sys.argv if not x.startswith("-")]

print("arguments parsed")

if INT:

    intf = args[1]
    print("interface :",intf)
    srcMAC = args[2]
    print("src MAC :",srcMAC)
    srcIP = args[3]
    print("src IP :",srcIP)
    dstMAC = args[4]
    print("dst MAC :",dstMAC)
    dstIP = args[5]
    print("dst IP :",dstIP)

    inth = INTHdr(flag = 1, inst_bitmap=0b0000000100, M=0, hop_count=0)
    print("INt header :",bytes(inth).hex())

    pkt = (
        Ether(src=srcMAC, dst=dstMAC) /
        inth /
        IPv6(src=srcIP, dst=dstIP)
    )

    print("Sent:",bytes(pkt).hex())
    sendp(pkt, iface=intf)

else:
    dstIP = args[1]
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.sendto(b'Hello, H2!', (dstIP, 5020))
print("sent data")





