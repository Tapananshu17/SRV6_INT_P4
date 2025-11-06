import argparse

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo

from bmv2_cleaned import ONOSBmv2Switch
from host6 import IPv6Host

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

if __name__=="__main__":
    import sys
    cli = ("--cli" in sys.argv)
    only_cli = ("--only_cli" in sys.argv)
    TwoRoutersThreeHosts(cli,only_cli)
