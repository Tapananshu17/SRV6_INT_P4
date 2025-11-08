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

def configure_snmp(router):
    router.cmd("/usr/sbin/snmpd -f -Lo -c /etc/snmp/snmpd.conf &")


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

    net.addLink(h1, r1,
                intfName1='h1-eth0', intfName2='r1-eth0',
                params1={'ip': '10.0.1.100/24'},
                params2={'ip': '10.0.1.1/24'},
                bw=100)

    net.addLink(h1, r2,
                intfName1='h1-eth1', intfName2='r2-eth0',
                params1={'ip': '10.0.2.100/24'},
                params2={'ip': '10.0.2.1/24'},
                bw=100)

    net.addLink(r1, r2,
                intfName1='r1-eth1', intfName2='r2-eth1',
                params1={'ip': '10.0.3.1/24'},
                params2={'ip': '10.0.3.2/24'},
                bw=100)

    net.addLink(h2, r1,
                intfName1='h2-eth0', intfName2='r1-eth2',
                params1={'ip': '10.0.4.100/24'},
                params2={'ip': '10.0.4.1/24'},
                bw=100)

    net.addLink(collector, r2,
                intfName1='collector-eth0', intfName2='r2-eth2',
                params1={'ip': '10.0.5.100/24'},
                params2={'ip': '10.0.5.1/24'},
                bw=100)

    return net

def run():
    net = build_topology()
    net.start()

    h1 = net.get('h1')
    h2 = net.get('h2')
    r1 = net.get('r1')
    r2 = net.get('r2')
    collector = net.get('collector')

    info('*** Adding routes\n')

    h1.cmd('ip route add 10.0.4.0/24 via 10.0.1.1 dev h1-eth0')
    h1.cmd('ip route add 10.0.5.0/24 via 10.0.2.1 dev h1-eth1')

    h2.cmd('ip route add default via 10.0.4.1')
    collector.cmd('ip route add default via 10.0.5.1')

    r1.cmd('ip route add 10.0.5.0/24 via 10.0.3.2')
    r1.cmd('ip route add 10.0.2.0/24 via 10.0.3.2')

    r2.cmd('ip route add 10.0.4.0/24 via 10.0.3.1')
    r2.cmd('ip route add 10.0.1.0/24 via 10.0.3.1')

    info('*** Configuring SNMP\n')
    configure_snmp(r1)
    configure_snmp(r2)

    collector.cmd('apt-get install -y snmp >/dev/null 2>&1')

    collector_ip = '10.0.5.100'

    info('*** Start Collector\n')

    info("\n=== TEST COMMANDS ===\n")
    info("mininet> collector snmpwalk -v2c -c public 10.0.1.1\n")
    info("mininet> collector snmpwalk -v2c -c public 10.0.2.1\n")

    CLI(net)
    net.stop()

if __name__ == "__main__":
    setLogLevel('info')
    run()
