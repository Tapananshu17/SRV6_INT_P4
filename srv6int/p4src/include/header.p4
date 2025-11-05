#ifndef __HEADER__
#define __HEADER__

#include "define.p4"

#define MAX_HOPS 4

@controller_header("packet_in")
header packet_in_header_t {
    port_num_t ingress_port;
    bit<7> _pad; 
}

@controller_header("packet_out")
header packet_out_header_t {
    port_num_t egress_port;
    bit<7> _pad;
}

header ethernet_t {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header ipv6_t {
    bit<4> version;
    bit<8> traffic_class;
    bit<20> flow_label;
    bit<16> payload_len;
    bit<8> next_hdr;
    bit<8> hop_limit;
    bit<128> src_addr;
    bit<128> dst_addr;
}

header srv6h_t {
    bit<8> next_hdr;
    bit<8> hdr_ext_len;
    bit<8> routing_type;
    bit<8> segment_left;
    bit<8> last_entry;
    bit<8> flags;
    bit<16> tag;
}

header srv6_list_t {
    bit<128> segment_id;
}header icmpv6_t {
    bit<8> type;
    bit<8> code;
    bit<16> checksum;
}
header inth_t {
  bit<2> flag;
  bit<2> m;
  
  bit<8> hop_count;
  bit switchID;
  bit inPortID;
  bit ePortID;
  bit inTimeStamp;
  bit eTimeStamp;
  bit qDepth;
  bit qDelay;
  bit proDelay;
  bit linkLatency;
  bit leftBand;
  bit<10> reserved; 
}

header switchID_t {bit<8> value;} 
header inPortID_t {bit<8> value;}
header ePortID_t {bit<8> value;}
header inTimeStamp_t {bit<48> value;}
header eTimeStamp_t {bit<48> value;}
header qDepth_t {bit<16> value;}
header qDelay_t {bit<24> value;}
header proDelay_t {bit<32> value;}
header linkLatency_t {bit<32> value;}
header leftBand_t {bit<32> value;}

header meta_t {bit<8> value;}struct local_metadata_t {
    
    
    bool xconnect;
    ipv6_addr_t next_srv6_sid;
    ipv6_addr_t ua_next_hop;
    bit<8> ip_proto;
    bit<8> icmp_type;
    l4_port_t l4_src_port;
    l4_port_t l4_dst_port;
    
    bit<8> switch_id; 
}

struct parsed_headers_t {
    ethernet_t ethernet;
    ipv6_t ipv6;
    ipv6_t ipv6_inner;
    
    srv6h_t srv6h;
    srv6_list_t[MAX_HOPS] srv6_list;
    
    
    
    
    icmpv6_t icmpv6;
    
    
    packet_out_header_t packet_out;
    packet_in_header_t packet_in;
    inth_t inth;
    meta_t[MAX_HOPS << 5] meta_list;

    
    switchID_t switchID;
    inPortID_t inPortID;
    ePortID_t ePortID;
    inTimeStamp_t inTimeStamp;
    eTimeStamp_t eTimeStamp;
    qDepth_t qDepth;
    qDelay_t qDelay;
    proDelay_t proDelay;
    linkLatency_t linkLatency;
    leftBand_t leftBand;
}

#endif
