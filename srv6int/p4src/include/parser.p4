#ifndef __PARSER__
#define __PARSER__

#include "define.p4"

parser ParserImpl (packet_in packet,
                   out parsed_headers_t hdr,
                   inout local_metadata_t local_metadata,
                   inout standard_metadata_t standard_metadata)
{
    state start {
        transition select(standard_metadata.ingress_port) {
            CPU_PORT: parse_packet_out;
            default: parse_ethernet;
        }
    }

    state parse_packet_out {
        packet.extract(hdr.packet_out);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        
        transition select(hdr.ethernet.ether_type){
            
            
            ETHERTYPE_IPV6: parse_ipv6;
            ETHERTYPE_INT: parse_int;
            default: accept;
        }
    }

    state parse_int {
        packet.extract(hdr.inth);
        transition select(hdr.inth.hop_count){
            0 : parse_ipv6;
            default : parse_meta_list;
        }
    }

    state parse_meta_list {
        transition parse_switchID;
    }
    
        state parse_switchID {
            transition select(hdr.inth.switchID){
                1 : extract_switchID;
                default : parse_inPortID;}
        }
        state extract_switchID {
            packet.extract(hdr.meta_list.next); 
            transition parse_inPortID;
        }

    
        state parse_inPortID {
            transition select(hdr.inth.inPortID){
                1 : extract_inPortID;
                default : parse_ePortID;}
        }
        state extract_inPortID {
            packet.extract(hdr.meta_list.next); 
            transition parse_ePortID;
        }

    
        state parse_ePortID {
            transition select(hdr.inth.ePortID){
                1 : extract_ePortID;
                default : parse_inTimeStamp;}
        }
        state extract_ePortID {
            packet.extract(hdr.meta_list.next); 
            transition parse_inTimeStamp;
        }

    
        state parse_inTimeStamp {
            transition select(hdr.inth.inTimeStamp){
                1 : extract_inTimeStamp;
                default : parse_eTimeStamp;}
        }
        state extract_inTimeStamp {
            packet.extract(hdr.meta_list.next);
            packet.extract(hdr.meta_list.next); 
            packet.extract(hdr.meta_list.next); 
            packet.extract(hdr.meta_list.next);
            packet.extract(hdr.meta_list.next); 
            packet.extract(hdr.meta_list.next);  
            
            transition parse_eTimeStamp;
        }

    
        state parse_eTimeStamp {
            transition select(hdr.inth.eTimeStamp){
                1 : extract_eTimeStamp;
                default : parse_qDepth;}
        }
        state extract_eTimeStamp {
            packet.extract(hdr.meta_list.next);
            packet.extract(hdr.meta_list.next); 
            packet.extract(hdr.meta_list.next); 
            packet.extract(hdr.meta_list.next);
            packet.extract(hdr.meta_list.next); 
            packet.extract(hdr.meta_list.next);  
            
            transition parse_qDepth;
        }

    
        state parse_qDepth {
            transition select(hdr.inth.qDepth){
                1 : extract_qDepth;
                default : parse_qDelay;}
        }
        state extract_qDepth {
            packet.extract(hdr.meta_list.next);
            packet.extract(hdr.meta_list.next);  
            
            transition parse_qDelay;
        }
    
        state parse_qDelay {
            transition select(hdr.inth.qDelay){
                1 : extract_qDelay;
                default : parse_proDelay;}
        }
        state extract_qDelay {
            packet.extract(hdr.meta_list.next);
            packet.extract(hdr.meta_list.next);  
            packet.extract(hdr.meta_list.next);  
            
            transition parse_proDelay;
        }
    
        state parse_proDelay {
            transition select(hdr.inth.proDelay){
                1 : extract_proDelay;
                default : parse_linkLatency;}
        }
        state extract_proDelay {
            packet.extract(hdr.meta_list.next);
            packet.extract(hdr.meta_list.next);  
            packet.extract(hdr.meta_list.next); 
            packet.extract(hdr.meta_list.next);  
            
            transition parse_linkLatency;
        }
    
        state parse_linkLatency {
            transition select(hdr.inth.linkLatency){
                1 : extract_linkLatency;
                default : parse_leftBand;}
        }
        state extract_linkLatency {
            packet.extract(hdr.meta_list.next);
            packet.extract(hdr.meta_list.next);  
            packet.extract(hdr.meta_list.next); 
            packet.extract(hdr.meta_list.next);  
            
            transition parse_leftBand;
        }
    
        state parse_leftBand {
            transition select(hdr.inth.leftBand){
                1 : extract_leftBand;
                default : check_last_int;}
        }
        state extract_leftBand {
            packet.extract(hdr.meta_list.next);
            packet.extract(hdr.meta_list.next);  
            packet.extract(hdr.meta_list.next); 
            packet.extract(hdr.meta_list.next);  
            
            transition check_last_int;
        }
    state check_last_int {
        bit<32> met_size = (
            ((bit<32>)hdr.inth.switchID) +
            ((bit<32>)hdr.inth.inPortID) +
            ((bit<32>)hdr.inth.ePortID) +
            ((
                ((bit<32>)hdr.inth.inTimeStamp) +
                ((bit<32>)hdr.inth.eTimeStamp)
            )*6) +
            ((bit<32>)hdr.inth.qDepth * 2) +
            ((bit<32>)hdr.inth.qDelay * 3) +
            ((
                ((bit<32>)hdr.inth.proDelay) +
                ((bit<32>)hdr.inth.linkLatency) +
                ((bit<32>)hdr.inth.leftBand)
            )*4)
        ); 
        bool is_last = (met_size * (bit<32>)hdr.inth.hop_count == hdr.meta_list.lastIndex +1);
        
        transition select(is_last) {
            true: parse_ipv6;
            default: parse_meta_list;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        local_metadata.ip_proto = hdr.ipv6.next_hdr;
        transition select(hdr.ipv6.next_hdr) {
            
            
            PROTO_ICMPV6: parse_icmpv6;
            PROTO_SRV6: parse_srv6;
            PROTO_IPV6: parse_ipv6_inner;
            
            default: accept;
        }
    }

    state parse_srv6 {
        packet.extract(hdr.srv6h);
        transition parse_srv6_list;
    }
    state parse_srv6_list {
        packet.extract(hdr.srv6_list.next);
        bool next_segment = (bit<32>)hdr.srv6h.segment_left - 1 == (bit<32>)hdr.srv6_list.lastIndex;
        transition select(next_segment) {
            true: mark_current_srv6;
            _: check_last_srv6;
        }
    }

    state mark_current_srv6 {
        
        local_metadata.next_srv6_sid = hdr.srv6_list.last.segment_id;
        transition check_last_srv6;
    }

    state check_last_srv6 {
        
        bool last_segment = (bit<32>)hdr.srv6h.last_entry == (bit<32>)hdr.srv6_list.lastIndex;
        transition select(last_segment) {
           true: parse_srv6_next_hdr;
           false: parse_srv6_list;
        }
    }
    state parse_srv6_next_hdr {
        transition select(hdr.srv6h.next_hdr) {
            
            
            PROTO_ICMPV6: parse_icmpv6;
            PROTO_IPV6: parse_ipv6_inner;
            
            default: accept;
        }
    }
    
       state parse_ipv6_inner {
        packet.extract(hdr.ipv6_inner);

        transition select(hdr.ipv6_inner.next_hdr) {
            
            
            PROTO_ICMPV6: parse_icmpv6;
            PROTO_SRV6: parse_srv6;
            default: accept;
        }
    }

       state parse_icmpv6 {
        packet.extract(hdr.icmpv6);
        local_metadata.icmp_type = hdr.icmpv6.type;
        transition select(hdr.icmpv6.type) {
            
            
            default: accept;
        }

    }
       
}

control DeparserImpl(packet_out packet, in parsed_headers_t hdr) {
    apply {
        packet.emit(hdr.packet_in);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.inth);
        packet.emit(hdr.meta_list);

        packet.emit(hdr.switchID);
        packet.emit(hdr.inPortID);
        packet.emit(hdr.ePortID);
        packet.emit(hdr.inTimeStamp);
        packet.emit(hdr.eTimeStamp);
        packet.emit(hdr.qDepth);
        packet.emit(hdr.qDelay);
        packet.emit(hdr.proDelay);
        packet.emit(hdr.linkLatency);
        packet.emit(hdr.leftBand);
    
        packet.emit(hdr.ipv6);
        packet.emit(hdr.srv6h);
        packet.emit(hdr.srv6_list);
        packet.emit(hdr.ipv6_inner);
        packet.emit(hdr.icmpv6);
        
        
    }
}

#endif
