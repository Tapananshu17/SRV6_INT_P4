#ifndef __DEFINE__
#define __DEFINE__

typedef bit<9>   port_num_t;
typedef bit<48>  mac_addr_t;

typedef bit<128> ipv6_addr_t;
typedef bit<16>  l4_port_t;

const bit<16> ETHERTYPE_IPV6 = 0x86dd;
const bit<16> ETHERTYPE_INT  = 0xffff;

const bit<8> PROTO_SRV6 = 43;
const bit<8> PROTO_ICMPV6 = 58;
const bit<8> PROTO_IPV6 = 41;
#endif
