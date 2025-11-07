import argparse

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo

from bmv2_cleaned import ONOSBmv2Switch
from host6 import IPv6Host
import json
import graphviz

CPU_PORT = 255

def OneRouter():
    net = Mininet(controller=RemoteController)  # don’t auto-create default
    ctrlIP = "10.0.0.1"
    c0 = net.addController('c0',ip=ctrlIP)
    h1 = net.addHost('h1', cls=IPv6Host, mac="00:00:00:00:00:10",
                           ipv6='2001:1:1::1/64', ipv6_gw='2001:1:1::ff')
    h2 = net.addHost('h2', cls=IPv6Host, mac="00:00:00:00:00:20",
                          ipv6='2001:1:2::1/64', ipv6_gw='2001:1:2::ff')
    r1_ipv6_addrs = [
        '2001:1:1::ff/64',
        '2001:1:2::ff/64'
    ]
    r1 = net.addSwitch('r1', cls=ONOSBmv2Switch,cpuport=CPU_PORT,json="p4src/main.json", ipv6_addresses=r1_ipv6_addrs)
    net.addLink(h1, r1)
    net.addLink(h2, r1)
    net.addLink(r1, c0)
    for intf in c0.intfList():c0.setIP(ctrlIP,intf=intf)
    r1.AddIPv6Addrs() # must be after adding links, or interfaces won't be added
    net.start()
    CLI(net)
    net.stop()

def AddSwitch(net,name,ipv6_addresses):
    return net.addSwitch(name, 
        cls=ONOSBmv2Switch,
        cpuport=CPU_PORT,
        json="p4src/main.json",
        pktdump=True,
        ipv6_addresses=ipv6_addresses)

def TwoRouters():
    ctrlIP = "10.0.0.1"
    net = Mininet(controller=RemoteController)
    c0 = net.addController('c0', ip=ctrlIP)
    h1 = net.addHost('h1', cls=IPv6Host, mac="00:00:00:00:00:10",
                           ipv6='2001:1:1::1/64', ipv6_gw='2001:1:1::ff')
    h2 = net.addHost('h2', cls=IPv6Host, mac="00:00:00:00:00:20",
                          ipv6='2001:1:2::1/64', ipv6_gw='2001:1:2::ff')
    
    r1_ipv6_addrs = [
        ['2001:1:1::ff/64',"00:00:00:00:00:11"],
        ['2001:1:1::fe/64',"00:00:00:00:00:12"]
    ]
    r2_ipv6_addrs = [
        ['2001:1:2::fe/64',"00:00:00:00:00:21"],
        ['2001:1:2::ff/64',"00:00:00:00:00:22"]
    ]

    r1 = AddSwitch(net,'r1',r1_ipv6_addrs)
    r2 = AddSwitch(net,'r2',r2_ipv6_addrs)
    net.addLink(h1, r1)
    net.addLink(r1, r2)
    net.addLink(r2, h2)
    net.addLink(r1, c0)
    net.addLink(r2, c0)
    for intf in c0.intfList():c0.setIP(ctrlIP,intf=intf)
    r1.AddIPv6Addrs() # must be after adding links, or interfaces won't be added
    r2.AddIPv6Addrs()
    net.start();CLI(net);net.stop()

def TwoRoutersThreeHosts(cli=False,only_cli=False):
    ctrlIP = "10.0.0.1"
    net = Mininet(controller=RemoteController)
    c0 = net.addController('c0', ip=ctrlIP)
    h1 = net.addHost('h1', cls=IPv6Host, mac="00:00:00:00:00:10",
            ipv6='2001:1:1::1/64', ipv6_gw='2001:1:1::fa')
    h2 = net.addHost('h2', cls=IPv6Host, mac="00:00:00:00:00:20",
            ipv6='2001:1:2::1/64', ipv6_gw='2001:1:2::fa')
    h3 = net.addHost('h3', cls=IPv6Host, mac="00:00:00:00:00:30",
            ipv6='2001:1:3::1/64', ipv6_gw='2001:1:3::fa')
    
    r1_ipv6_addrs = [
        ['2001:1:1::fa/128',"00:00:00:00:00:1a"], # h1
        ['2001:1:2::fa/128',"00:00:00:00:00:2a"], # h2
        ['2001:1:3::fa/128',"00:00:00:00:00:3a"], # h3
        ['2001:1:b::fa/128',"00:00:00:00:00:ba"], # r2
    ]
    r2_ipv6_addrs = [
        ['2001:1:1::fb/128',"00:00:00:00:00:1b"], # h1
        ['2001:1:2::fb/128',"00:00:00:00:00:2b"], # h2
        ['2001:1:3::fb/128',"00:00:00:00:00:3b"], # h3
        ['2001:1:a::fb/128',"00:00:00:00:00:ab"], # r1
    ]

    h1_ipv6_addrs = [
        ['2001:1:1::1/128',"00:00:00:00:00:10"], # r1
        ['2001:1:1::2/128',"00:00:00:00:00:11"], # r2
    ]
    h2_ipv6_addrs = [
        ['2001:1:2::1/128',"00:00:00:00:00:20"], # r1
        ['2001:1:2::2/128',"00:00:00:00:00:21"], # r2
    ]
    h3_ipv6_addrs = [
        ['2001:1:3::1/128',"00:00:00:00:00:30"], # r1
        ['2001:1:3::2/128',"00:00:00:00:00:31"], # r2
    ]

    r1 = AddSwitch(net,'r1',r1_ipv6_addrs)
    net.addLink(r1, h1)
    net.addLink(r1, h2)
    net.addLink(r1, h3)
    r2 = AddSwitch(net,'r2',r2_ipv6_addrs)
    net.addLink(r2, h1)
    net.addLink(r2, h2)
    net.addLink(r2, h3)


    net.addLink(r1,r2)
    net.addLink(r1, c0)
    net.addLink(r2, c0)

    for intf in c0.intfList():c0.setIP(ctrlIP,intf=intf)
    r1.AddIPv6Addrs() # must be after adding links, or interfaces won't be added
    r2.AddIPv6Addrs()
    h1.AddIPv6Addrs(h1_ipv6_addrs)
    h2.AddIPv6Addrs(h2_ipv6_addrs)
    h3.AddIPv6Addrs(h3_ipv6_addrs)
    net.start()
    if only_cli:CLI(net)
    else:CLI(net,script="mininet/mininet_script.txt")
    if cli:CLI(net)
    net.stop()


def custom_topo(file,mapping_file=None,cli=False,only_cli=False,vis=True):
    with open(file,'r') as f:edges = f.read()
    edges = edges.split('\n')
    edges = [edge.split(',') for edge in edges[1:] if edge]
    print('\nEdges')
    for edge in edges:print(edge)
    nodes = [edge[0].strip() for edge in edges] + [edge[1].strip() for edge in edges]
    nodes:list[str] = list(set(nodes))
    hosts = [h for h in nodes if h.startswith('h')]
    print('\nHosts:',hosts)
    switches = [s for s in nodes if s.startswith('s') or s.startswith('r')]
    print('Switches:',switches)
    Addresses = {}
    Host_Addresses = {}
    Out_Adds = {}
    if vis:G = graphviz.Graph()
    for edge in edges:
        A,B,IP_A,MAC_A,IP_B,MAC_B = edge
        if A.startswith('h') and B == '':
            Host_Addresses[A] = [IP_A,MAC_A,IP_B]
            if vis: G.node(A,f"{A}\nIP:{IP_A}\nMAC:{MAC_A}\nIP_g:{IP_B}")
            continue

        assert all(x!='' for x in edge)
        
        if A not in Addresses:Addresses[A] = [[IP_A,MAC_A]]
        else:Addresses[A].append([IP_A,MAC_A])

        if B not in Out_Adds:Out_Adds[B] = [[IP_A,MAC_A]]
        else:Out_Adds[B].append([IP_A,MAC_A])

        if B not in Addresses:Addresses[B] = [[IP_B,MAC_B]]
        else:Addresses[B].append([IP_B,MAC_B])

        if A not in Out_Adds:Out_Adds[A] = [[IP_B,MAC_B]]
        else:Out_Adds[A].append([IP_B,MAC_B])

        if vis:G.edge(A,B)


    print("\nHost config")
    for h,ads in Host_Addresses.items():print(h,':',ads)
    print("\nAddresses")
    for node,ads in Addresses.items():
        print('\t' + node)
        for ad in ads:print('\t\t'+','.join(ad))
    edges = [edge for edge in edges if edge[1]!='']
    assert all((h in Host_Addresses for h in hosts)),"Ill specified CSV"
    assert all((h in Host_Addresses for h in hosts)),"Ill specified CSV"
    assert all((s in Addresses for s in switches)),"Ill specified CSV"
    assert all(((A in hosts) or (A in switches) for A in Addresses)),"Ill specified CSV"

    ctrlIP = "10.0.0.1"
    net = Mininet(controller=RemoteController)
    c0 = net.addController('c0', ip=ctrlIP)

    Nodes = {}

    for h in hosts:
        IP,MAC,IP_g = Host_Addresses[h]
        if IP_g=="":IP_g = Addresses[h][0][0]
        Nodes[h] = net.addHost(h, cls=IPv6Host, mac=MAC, ipv6=IP, ipv6_gw=IP_g)

    for s in switches:Nodes[s] = AddSwitch(net,s,None)

    Done = []

    for A,B,IP_A,MAC_A,IP_B,MAC_B in edges:
        if (A,B) in Done: continue
        if (B,A) in Done: continue
        net.addLink(Nodes[A],Nodes[B])
        print("added link",(A,B))
        Done.append((A,B))

    for s in switches:
        Nodes[s].ipv6_addresses = Addresses[s]
        Nodes[s].AddIPv6Addrs()
    for h in hosts:
        Nodes[h].AddIPv6Addrs(Addresses[h])

    if mapping_file:
        Flow = {}
        for s in switches:
            Flow[s] = {
                "out":[x + [str(i+1)] for i,x in enumerate(Out_Adds[s])],
                "in":Addresses[s]
                }
        # Out_Adds = {s:ads for s,ads in Out_Adds.items() if s in switches}
        with open(mapping_file,'w') as mf:
            json.dump(Flow,mf,indent=4)

    if vis:G.render("mininet/topo",format="png")

    net.start()
    if only_cli:CLI(net)
    else:CLI(net,script="mininet/mininet_script.txt")
    if cli:CLI(net)
    net.stop()




if __name__=="__main__":
    import sys
    cli = ("--cli" in sys.argv)
    only_cli = ("--only_cli" in sys.argv)
    # TwoRoutersThreeHosts(cli,only_cli)
    custom_topo("mininet/interfaces.csv","mininet/flow.json",cli,only_cli)
