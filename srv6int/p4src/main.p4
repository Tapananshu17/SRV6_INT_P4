#include <core.p4>
#include <v1model.p4>

#include "include/header.p4"
#include "include/parser.p4"
#include "include/checksum.p4"

#define CPU_CLONE_SESSION_ID 99
#define UN_BLOCK_MASK     0xffffffff000000000000000000000000

control IngressPipeImpl (inout parsed_headers_t hdr,
                         inout local_metadata_t local_metadata,
                         inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_output_port(port_num_t port_num) {
        standard_metadata.egress_spec = port_num;
    }

    
    table unicast {
        key = {
            hdr.ethernet.dst_addr: exact; 
        }
        actions = {
            set_output_port;
            drop;
            NoAction;
        }
        
        default_action = NoAction();
    }

    action set_next_hop(mac_addr_t next_hop) {
	    hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
	    hdr.ethernet.dst_addr = next_hop;
	    hdr.ipv6.hop_limit = hdr.ipv6.hop_limit - 1;
    }

    table routing_v6 {
	    key = {
	        hdr.ipv6.dst_addr: lpm;
	    }
        actions = {
	        set_next_hop;
        }
    }

 
    action srv6_end() {}

    action srv6_end_x(ipv6_addr_t next_hop) {
        hdr.ipv6.dst_addr = (hdr.ipv6.dst_addr & UN_BLOCK_MASK) | ((hdr.ipv6.dst_addr << 32) & ~((bit<128>)UN_BLOCK_MASK));
        local_metadata.xconnect = true;

        local_metadata.ua_next_hop = next_hop;
    }

    action srv6_end_dx6() {
        hdr.ipv6.version = hdr.ipv6_inner.version;
        hdr.ipv6.traffic_class = hdr.ipv6_inner.traffic_class;
        hdr.ipv6.flow_label = hdr.ipv6_inner.flow_label;
        hdr.ipv6.payload_len = hdr.ipv6_inner.payload_len;
        hdr.ipv6.next_hdr = hdr.ipv6_inner.next_hdr;
        hdr.ipv6.hop_limit = hdr.ipv6_inner.hop_limit;
        hdr.ipv6.src_addr = hdr.ipv6_inner.src_addr;
        hdr.ipv6.dst_addr = hdr.ipv6_inner.dst_addr;

        hdr.ipv6_inner.setInvalid();
        hdr.srv6h.setInvalid();
        hdr.srv6_list[0].setInvalid();
    }

    
    action srv6_end_t() {
        
        if (hdr.srv6h.segment_left > 0) {
            
            hdr.ipv6.dst_addr = local_metadata.next_srv6_sid;
            
            hdr.srv6h.segment_left = hdr.srv6h.segment_left - 1;
        } else {
            
            hdr.ipv6.dst_addr = hdr.srv6_list[0].segment_id;
        }
        
        
    }

    action srv6_end_encaps(ipv6_addr_t src_addr, ipv6_addr_t s1) {
        hdr.ipv6_inner.setValid();
        hdr.ipv6_inner.version = hdr.ipv6.version;
        hdr.ipv6_inner.traffic_class = hdr.ipv6.traffic_class;
        hdr.ipv6_inner.flow_label = hdr.ipv6.flow_label;
        hdr.ipv6_inner.payload_len = hdr.ipv6.payload_len;
        hdr.ipv6_inner.next_hdr = hdr.ipv6.next_hdr;
        hdr.ipv6_inner.hop_limit = hdr.ipv6.hop_limit;
        hdr.ipv6_inner.src_addr = hdr.ipv6.src_addr;
        hdr.ipv6_inner.dst_addr = hdr.ipv6.dst_addr;

        hdr.ipv6.version = 6;
        hdr.ipv6.traffic_class = hdr.ipv6_inner.traffic_class;
        hdr.ipv6.flow_label = hdr.ipv6_inner.flow_label;
        hdr.ipv6.payload_len = hdr.ipv6_inner.payload_len + 40; 
        hdr.ipv6.next_hdr = PROTO_IPV6; 
        hdr.ipv6.hop_limit = hdr.ipv6_inner.hop_limit;
        hdr.ipv6.src_addr = src_addr;
        hdr.ipv6.dst_addr = s1;
    }

    
    table srv6_localsid_table {
        key = {
            hdr.ipv6.dst_addr: lpm;
        }
        actions = {
            srv6_end;
            srv6_end_x;
            srv6_end_dx6;
            srv6_end_t;
            srv6_end_encaps;          
            NoAction;
        }
        default_action = NoAction;
        
    }

    action xconnect_act(mac_addr_t next_hop) {
        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = next_hop;
    }

    
    table xconnect_table {
        key = {
            local_metadata.ua_next_hop: lpm;
        }
        actions = {
            xconnect_act;
            NoAction;
        }
        default_action = NoAction;
        
    }


    action clone_to_cpu() {        
        clone_preserving_field_list(CloneType.I2E, CPU_CLONE_SESSION_ID, 0);
    }

    table acl {
        key = {
            standard_metadata.ingress_port: ternary;
            hdr.ethernet.dst_addr: ternary;
            hdr.ethernet.src_addr: ternary;
            hdr.ethernet.ether_type: ternary;
            local_metadata.ip_proto: ternary;
            local_metadata.icmp_type: ternary;
            local_metadata.l4_src_port: ternary;
            local_metadata.l4_dst_port: ternary;
        }
        actions = {
            clone_to_cpu;
            drop;
        }
        
    }

    action set_switch_id(bit<8> id) {
        local_metadata.switch_id = id;
    }

    table set_switch_id_table {
        actions = { set_switch_id; }
        size = 1;
        
    }

    action put_switchID(){
        hdr.switchID.setValid();
        hdr.switchID.value = local_metadata.switch_id;
        // log_msg("local_metadata.switch_id = {}", {local_metadata.switch_id});
    }

    action put_inPortID(){
        hdr.inPortID.setValid();

        hdr.inPortID.value = (bit<8>)(standard_metadata.ingress_port);
        // log_msg("hdr.inPortID.value = {}", {hdr.inPortID.value});
        // log_msg("standard_metadata.ingress_port = {}", {standard_metadata.ingress_port});
        
    }

    action put_ePortID(){
        hdr.ePortID.setValid();
        hdr.ePortID.value = (bit<8>)(standard_metadata.egress_spec);
    }
    
    action put_inTimeStamp(){
        hdr.inTimeStamp.setValid();
        hdr.inTimeStamp.value = (bit<48>)(standard_metadata.ingress_global_timestamp);
    }
    
    action put_qDepth(){
        hdr.qDepth.setValid();
        hdr.qDepth.value = (bit<16>)(standard_metadata.enq_qdepth);
    }
    
    action put_qDelay(){
        hdr.qDelay.setValid();
        hdr.qDelay.value = (bit<24>)(standard_metadata.deq_timedelta);
    }

    
    apply {
        set_switch_id_table.apply();

        if (hdr.packet_out.isValid()) {
            standard_metadata.egress_spec = hdr.packet_out.egress_port;
            hdr.packet_out.setInvalid();
            exit;
        }

        if (hdr.ipv6.hop_limit == 0) {
	            drop();
	        }

     
	    if(hdr.srv6h.isValid()){

            switch(srv6_localsid_table.apply().action_run) {
                srv6_end: {
                    
                    if (hdr.srv6h.segment_left > 0) {
                        
                        hdr.ipv6.dst_addr = local_metadata.next_srv6_sid;
                        
                        hdr.srv6h.segment_left = hdr.srv6h.segment_left - 1;
                    } else {
                        
                        hdr.ipv6.dst_addr = hdr.srv6_list[0].segment_id;
                    }
                }
                
                
                
            }        
        }
        
        if (!local_metadata.xconnect) {
            routing_v6.apply();
        } else {
            xconnect_table.apply();
        }
        
        unicast.apply();
       
        if (hdr.inth.flag == 1){
            hdr.inth.hop_count = hdr.inth.hop_count + 1;
            if((bool)hdr.inth.switchID){put_switchID();}
            if((bool)hdr.inth.inPortID){put_inPortID();}
            if((bool)hdr.inth.ePortID){put_ePortID();}
            if((bool)hdr.inth.inTimeStamp){put_inTimeStamp();}
            
            if((bool)hdr.inth.qDepth){put_qDepth();}
            if((bool)hdr.inth.qDelay){put_qDelay();}
        }
        acl.apply();    
    }
}

control EgressPipeImpl (inout parsed_headers_t hdr,
                        inout local_metadata_t local_metadata,
                        inout standard_metadata_t standard_metadata) {
    
    action put_eTimeStamp(){
        hdr.eTimeStamp.setValid();
        hdr.eTimeStamp.value = (bit<48>)(standard_metadata.egress_global_timestamp);
    }

    action put_proDelay(){
        hdr.proDelay.setValid();
        hdr.proDelay.value = ((bit<32>)standard_metadata.egress_global_timestamp
        -(bit<32>)standard_metadata.ingress_global_timestamp-(bit<32>)standard_metadata.deq_timedelta);
    }
    
    apply {
        if (standard_metadata.egress_port == CPU_PORT) {
		    hdr.packet_in.setValid();
		    hdr.packet_in.ingress_port = standard_metadata.ingress_port;		
        }

        if (hdr.inth.flag == 1){
            if((bool)hdr.inth.eTimeStamp){put_eTimeStamp();}
            if((bool)hdr.inth.proDelay){put_proDelay();}
            
            
        }
    }
}

V1Switch(
    ParserImpl(),
    VerifyChecksumImpl(),
    IngressPipeImpl(),
    EgressPipeImpl(),
    ComputeChecksumImpl(),
    DeparserImpl()
) main;
