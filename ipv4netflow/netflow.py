from mininet.net import Mininet
from mininet.node import Host
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

class Router(Host):
    """IP4 Router"""
    def config(self, **params):
        super().config(**params)
        self.cmd('sysctl -w net.ipv4.ip_forward=1')

    def terminate(self):
        self.cmd('sysctl -w net.ipv4.ip_forward=0')
        super().terminate()

def build_topology():
    """
     h1-----r1------h2
      |      |
      +-----r2
             |
           collector
    """
    
    net = Mininet(host=Host, autoSetMacs=True, link=TCLink)

    info('*** Adding nodes\n')
    h1 = net.addHost('h1', ip=None)
    h2 = net.addHost('h2', ip=None)
    collector = net.addHost('collector', ip=None)
    r1 = net.addHost('r1', cls=Router, ip=None)
    r2 = net.addHost('r2', cls=Router, ip=None)

    info('*** Adding links\n')
    
    # h1 <-> r1 (Subnet 10.0.1.0/24)
    net.addLink(h1, r1,
                intfName1='h1-eth0', intfName2='r1-eth0',
                params1={'ip': '10.0.1.100/24'},
                params2={'ip': '10.0.1.1/24'},
                bw=100)

    # h1 - r2 (Subnet 10.0.2.0/24)
    net.addLink(h1, r2,
                intfName1='h1-eth1', intfName2='r2-eth0',
                params1={'ip': '10.0.2.100/24'},
                params2={'ip': '10.0.2.1/24'},
                bw=100)

    # r1 - r2 (Subnet 10.0.3.0/24)
    net.addLink(r1, r2,
                intfName1='r1-eth1', intfName2='r2-eth1',
                params1={'ip': '10.0.3.1/24'},
                params2={'ip': '10.0.3.2/24'},
                bw=100)
    
    # r1 - h2 (Subnet 10.0.4.0/24)
    net.addLink(h2, r1,
                intfName1='h2-eth0', intfName2='r1-eth2',
                params1={'ip': '10.0.4.100/24'},
                params2={'ip': '10.0.4.1/24'},
                bw=100)
    
    # r2 - collector (Subnet 10.0.5.0/24)
    net.addLink(collector, r2,
                intfName1='collector-eth0', intfName2='r2-eth2',
                params1={'ip': '10.0.5.100/24'},
                params2={'ip': '10.0.5.1/24'},
                bw=100)

    return net

def run():
    """Starts the network, runs softflowd daemons in r1 and r2, and opens the CLI for testing"""

    net = build_topology()
    net.start()

    h1 = net.get('h1')
    h2 = net.get('h2')
    r1 = net.get('r1')
    r2 = net.get('r2')
    collector = net.get('collector')

    info('*** Adding routes')
    # Host Routes 
    # h1 - r1 - h2
    h1.cmd('ip route add 10.0.4.0/24 via 10.0.1.1 dev h1-eth0')

    # h1 - r2 - collector
    h1.cmd('ip route add 10.0.5.0/24 via 10.0.2.1 dev h1-eth1')
    
    # h2 only has one gateway
    h2.cmd('ip route add default via 10.0.4.1')
    # collector only has one gateway
    collector.cmd('ip route add default via 10.0.5.1')

    # Router Routes 
    # r1 - r2 -collector
    r1.cmd('ip route add 10.0.5.0/24 via 10.0.3.2')
    # r1 - r2 - h1
    r1.cmd('ip route add 10.0.2.0/24 via 10.0.3.2')
    
    # r2 - r1 - h2
    r2.cmd('ip route add 10.0.4.0/24 via 10.0.3.1')
    # r2 - r1 - h1
    r2.cmd('ip route add 10.0.1.0/24 via 10.0.3.1')

    collector_ip = '10.0.5.100'

    #info('*** Clearing previous logs on collector\n')
    #collector.cmd('rm -rf /tmp/netflow')
    #collector.cmd('mkdir -p /tmp/netflow')

    info('*** Start Collector\n')
    collector.cmd('mkdir -p /tmp/netflow')
    collector.cmd('nfcapd -p 9995 -l /tmp/netflow -D')

    # collector is responsible for storing the flows logically based on which 
    # {interface,router} passed that flow
    info('*** Start Softflowd on ALL routers\n')
    # monitor host-facing interfaces on r1
    r1.cmd(f'softflowd -i r1-eth0 -n {collector_ip}:9995 -v 9 -D &') # to h1
    r1.cmd(f'softflowd -i r1-eth2 -n {collector_ip}:9995 -v 9 -D &') # to h2
    
    # monitor host-facing interfaces on r2
    r2.cmd(f'softflowd -i r2-eth0 -n {collector_ip}:9995 -v 9 -D &') # to h1
    r2.cmd(f'softflowd -i r2-eth2 -n {collector_ip}:9995 -v 9 -D &') # to collector

    info('\nRun these to test h1 -> h2 traffic:\n')
    info('  mininet> h2 iperf3 -s -D\n')
    info('  mininet> h1 iperf3 -c 10.0.4.100 -t 10\n')
    info('  ...wait 20 seconds, then:\n')
    info('  mininet> collector nfdump -R /tmp/netflow\n\n')

    CLI(net)

    info('*** Stopping daemons\n')
    r1.cmd('killall softflowd')
    r2.cmd('killall softflowd')
    collector.cmd('killall nfcapd')
    net.stop()

if __name__ == "__main__":
    setLogLevel('info')
    run()