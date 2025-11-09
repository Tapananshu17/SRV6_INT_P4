import json,sys
from p4runtime_sh_module.shell import TableEntry
import p4runtime_sh_module.shell as sh

DONE = set()

def set_switch_id(sh,Id):
    k = ('set_switch_id',Id)
    if k in DONE:return
    te = sh.TableEntry("set_switch_id_table")(action="set_switch_id")
    te.action["id"] = Id
    te.insert()
    print(f"switch IP set to {Id}")
    DONE.add(k)

def add_unicast_entry(sh, dst_mac, out_port):
    k = ('add_unicast_entry',dst_mac, out_port)
    if k in DONE: return
    te = sh.TableEntry('unicast')(action='set_output_port')
    te.match["hdr.ethernet.dst_addr"] = dst_mac
    te.action["port_num"] = out_port
    te.insert()
    print(f"Unicast entry added: {dst_mac} -> port {out_port}")
    DONE.add(k)

def add_xconnect_entry(sh, next_hop_mac):
    k = ('add_xconnect_entry',next_hop_mac)
    if k in DONE: return
    te = sh.TableEntry('xconnect_table')(action='xconnect_act')
    te.match["local_metadata.ua_next_hop"] = next_hop_mac
    te.action["next_hop"] = next_hop_mac
    te.insert()
    print(f"XConnect entry added for next hop {next_hop_mac}")
    DONE.add(k)

def add_routing_v6_entry(sh, dst_ip, next_hop_mac):
    k = ('add_routing_v6_entry',dst_ip, next_hop_mac)
    if k in DONE: return
    te = sh.TableEntry('routing_v6')(action='set_next_hop')
    te.match["hdr.ipv6.dst_addr"] = dst_ip  # LPM format: '2001:1:1::/64'
    te.action["next_hop"] = next_hop_mac
    te.insert()
    print(f"Routing_v6 entry added: {dst_ip} -> next hop {next_hop_mac}")
    DONE.add(k)

def add_srv6_localsid_entry(sh, dst_ip, action_name, next_hop=None, src_addr=None, s1=None, s2=None):
    """
    Add entry to srv6_localsid_table
    action_name: 'srv6_end', 'srv6_end_x', 'srv6_end_dx6', 'srv6_end_t', 'srv6_end_encaps', 'srv6_end_dx4', 'srv6_usid_un', 'srv6_usid_ua'
    For actions that require next_hop or SRv6 addresses, pass them as keyword args
    """
    k = ('add_srv6_localsid_entry',dst_ip, action_name,next_hop,src_addr,s1,s2)
    if k in DONE: return
    te = sh.TableEntry('srv6_localsid_table')(action=action_name)
    te.match["hdr.ipv6.dst_addr"] = dst_ip
    if next_hop is not None:te.action["next_hop"] = next_hop
    if src_addr is not None:te.action["src_addr"] = src_addr
    if s1 is not None:te.action["s1"] = s1
    if s2 is not None:te.action["s2"] = s2
    te.insert()
    print(f"SRv6 localsid entry added: {dst_ip} -> action {action_name}")
    DONE.add(k)

ROUTER_CONFIGS = {}

pipe_config = sh.FwdPipeConfig('p4src/p4info.txt', 'p4src/main.json')

def connect_to_router(switch_name):

    global ROUTER_CONFIGS,DONE

    try:sh.teardown()
    except:print('teardown failed')

    if switch_name not in ROUTER_CONFIGS:

        # --- Load config ---
        with open(f'tmp/bmv2-{switch_name}-netcfg.json') as f:netcfg = json.load(f)
        mgmt_addr = netcfg['devices'][f'device:bmv2:{switch_name}']['basic']['managementAddress']
        grpc_addr = mgmt_addr.split('?')[0].replace('grpc://', '')
        device_id = int(mgmt_addr.split('device_id=')[1])
        rcf = {"device_id":device_id,"grpc_addr":grpc_addr}
        ROUTER_CONFIGS[switch_name] = rcf
    
    else:
        rcf = ROUTER_CONFIGS[switch_name]
        device_id = rcf['device_id']
        grpc_addr = rcf['grpc_addr']

    # --- Connect to switch ---
    sh.setup(
        device_id=device_id,
        grpc_addr=grpc_addr,
        election_id=(1, 0),
        config= pipe_config
        # config=sh.FwdPipeConfig('p4src/p4info.txt', 'p4src/main.json')
    )

    DONE = set()

def set_IPv6(dst_ipv6,dst_mac,out_port,switch_name=None,only_IP=False):
    if switch_name is not None:connect_to_router(switch_name)
    add_routing_v6_entry(sh, dst_ipv6, dst_mac)
    if not only_IP : add_unicast_entry(sh, dst_mac, str(out_port))


def set_from_file(sh,mapping_file):
    with open(mapping_file,'r') as mf:Flow = json.load(mf)
    for s in Flow:
        if s.startswith('h'):continue
        switch_id = int(s[1:])
        connect_to_router(s)
        # set_switch_id(sh,str(switch_id)) # TODO: figure out why this doesn't work in newer versions
        if "out_infered" in Flow[s]:entries = Flow[s]["out_infered"]
        else:entries = Flow[s]["out"] 
        for s2,L in entries.items():
            for IP,MAC,port in L:
                set_IPv6(IP,MAC,port)
        for IP,MAC in Flow[s]['in']: 
            add_srv6_localsid_entry(sh,IP,'srv6_end')
        print(s,":")
        for x in DONE: print(x)


# TwoRouters

if "--2" in sys.argv:

    set_IPv6('2001:1:1::1/64','00:00:00:00:00:10','1',switch_name="s1")
    set_IPv6('2001:1:2::1/64','00:00:00:00:00:21','2')
    set_switch_id(sh,"1")

    set_IPv6('2001:1:1::1/64','00:00:00:00:00:11','1',switch_name="s2")
    set_IPv6('2001:1:2::1/64','00:00:00:00:00:20','2')
    set_switch_id(sh,"2")

# TwoRoutersThreeHosts

elif "--2-3" in sys.argv:

    set_IPv6('2001:1:1::1/128','00:00:00:00:00:10','1',switch_name="s1")
    set_IPv6('2001:1:2::1/128','00:00:00:00:00:20','2')
    set_IPv6('2001:1:3::1/128','00:00:00:00:00:30','3')
    # set_IPv6('2001:1:b::fa/128','00:00:00:00:00:ab','4')
    set_IPv6('2001:1:a::fb/128','00:00:00:00:00:ab','4')

    add_srv6_localsid_entry(sh,'2001:1:1::fa/128','srv6_end')
    add_srv6_localsid_entry(sh,'2001:1:2::fa/128','srv6_end')
    add_srv6_localsid_entry(sh,'2001:1:3::fa/128','srv6_end')
    # add_srv6_localsid_entry(sh,'2001:1:a::fb/128','srv6_end')
    add_srv6_localsid_entry(sh,'2001:1:b::fa/128','srv6_end')

    set_switch_id(sh,"1")

    set_IPv6('2001:1:1::2/128','00:00:00:00:00:11','1',switch_name="s2")
    set_IPv6('2001:1:2::2/128','00:00:00:00:00:21','2')
    set_IPv6('2001:1:3::2/128','00:00:00:00:00:31','3')
    # set_IPv6('2001:1:a::fb/128','00:00:00:00:00:ba','4')
    set_IPv6('2001:1:b::fa/128','00:00:00:00:00:ba','4')

    add_srv6_localsid_entry(sh,'2001:1:1::fb/128','srv6_end')
    add_srv6_localsid_entry(sh,'2001:1:2::fb/128','srv6_end')
    add_srv6_localsid_entry(sh,'2001:1:3::fb/128','srv6_end')
    # add_srv6_localsid_entry(sh,'2001:1:b::fa/128','srv6_end')
    add_srv6_localsid_entry(sh,'2001:1:a::fb/128','srv6_end')

    set_switch_id(sh,"2")

else:set_from_file(sh,'mininet/flow.json')

sh.teardown()
