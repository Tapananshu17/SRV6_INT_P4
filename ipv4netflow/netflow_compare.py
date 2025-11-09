from mininet.net import Mininet
from mininet.node import Host
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import time
import re

class Router(Host):
    """IP4 Router"""
    def config(self, **params):
        super().config(**params)
        self.cmd('sysctl -w net.ipv4.ip_forward=1')

    def terminate(self):
        self.cmd('sysctl -w net.ipv4.ip_forward=0')
        super().terminate()

def build_topology():
    """Builds the Mininet topology."""
    
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

def setup_routes(net):
    """Configures all static routes for hosts and routers."""
    info('*** Adding routes\n')
    h1 = net.get('h1')
    h2 = net.get('h2')
    collector = net.get('collector')
    r1 = net.get('r1')
    r2 = net.get('r2')

    # Host Routes 
    h1.cmd('ip route add 10.0.4.0/24 via 10.0.1.1 dev h1-eth0')
    h1.cmd('ip route add 10.0.5.0/24 via 10.0.2.1 dev h1-eth1')
    h2.cmd('ip route add default via 10.0.4.1')
    collector.cmd('ip route add default via 10.0.5.1')

    # Router Routes 
    r1.cmd('ip route add 10.0.5.0/24 via 10.0.3.2')
    r1.cmd('ip route add 10.0.2.0/24 via 10.0.3.2')
    r2.cmd('ip route add 10.0.4.0/24 via 10.0.3.1')
    r2.cmd('ip route add 10.0.1.0/24 via 10.0.3.1')

def start_netflow_daemons(net):
    """Starts nfcapd on collector and softflowd on routers."""
    info('*** Starting NetFlow Daemons\n')
    r1 = net.get('r1')
    r2 = net.get('r2')
    collector = net.get('collector')
    collector_ip = '10.0.5.100'

    collector.cmd('rm -rf /tmp/netflow')
    collector.cmd('mkdir -p /tmp/netflow')
    collector.cmd('nfcapd -p 9995 -l /tmp/netflow -D')

    r1.cmd(f'softflowd -i r1-eth0 -n {collector_ip}:9995 -v 9 -D -t 15,60 &')
    r1.cmd(f'softflowd -i r1-eth2 -n {collector_ip}:9995 -v 9 -D -t 15,60 &')
    r2.cmd(f'softflowd -i r2-eth0 -n {collector_ip}:9995 -v 9 -D -t 15,60 &')
    r2.cmd(f'softflowd -i r2-eth2 -n {collector_ip}:9995 -v 9 -D -t 15,60 &')

def stop_netflow_daemons(net):
    """Stops all NetFlow daemons."""
    info('*** Stopping NetFlow Daemons\n')
    net.get('r1').cmd('killall softflowd')
    net.get('r2').cmd('killall softflowd')
    net.get('collector').cmd('killall nfcapd')

def parse_iperf_time(output):
    """get time for data transfer"""
    
    match = re.search(r'0\.00-(\d+\.\d+)\s+sec.*sender', output)
    
    if match:
        return float(match.group(1))
    
    info(f'  PARSE FAILED. Full iperf output:\n{output}\n')
    return None

def run_experiment(net, num_runs=5):
    """Runs iperf3 test and returns the average time."""
    h1 = net.get('h1')
    h2 = net.get('h2')

    info(f'*** Running experiment ({num_runs} runs)...\n')
    h2.cmd('iperf3 -s -D')
    time.sleep(1) # Wait for server to start

    times = []
    for i in range(num_runs):
        info(f'  Run {i+1}/{num_runs}...')
        # Run iperf3 client and capture output
        output = h1.cmd('iperf3 -c 10.0.4.100 -n 100M')
        
        run_time = parse_iperf_time(output)
        if run_time:
            times.append(run_time)
            info(f'  Time: {run_time}s\n')
        else:
            info(f'  Failed to parse output for run {i+1}\n')
            print(output) 
        
        time.sleep(0.5) 

    h2.cmd('killall iperf3')

    if not times:
        return None
        
    avg_time = sum(times) / len(times)
    return avg_time

# --- Main Execution ---

if __name__ == "__main__":
    setLogLevel('info')
    
    num_runs = 5 # Number of iperf runs per scenario
    
    # --- Scenario A: Baseline (No NetFlow) ---
    info('--- SCENARIO A: Running baseline test (NO NetFlow) ---\n')
    net_baseline = build_topology()
    net_baseline.start()
    setup_routes(net_baseline)
    
    avg_time_no_netflow = run_experiment(net_baseline, num_runs)
    
    net_baseline.stop()
    
    # --- Scenario B: With NetFlow ---
    info('\n--- SCENARIO B: Running overhead test (WITH NetFlow) ---\n')
    net_with_netflow = build_topology()
    net_with_netflow.start()
    
    setup_routes(net_with_netflow)
    start_netflow_daemons(net_with_netflow)
    time.sleep(1) # Give daemons a second to start up
    
    avg_time_with_netflow = run_experiment(net_with_netflow, num_runs)
    
    stop_netflow_daemons(net_with_netflow)
    net_with_netflow.stop()
    
    # --- Report Results ---
    info('\n--- Experiment Results ---\n')
    if avg_time_no_netflow and avg_time_with_netflow:
        overhead_abs = avg_time_with_netflow - avg_time_no_netflow
        overhead_pct = (overhead_abs / avg_time_no_netflow) * 100
        
        info(f'  Test parameters: {num_runs} runs of 100M transfer\n')
        info(f'  Average time without NetFlow: {avg_time_no_netflow:.4f}s\n')
        info(f'  Average time WITH NetFlow:    {avg_time_with_netflow:.4f}s\n')
        info('--------------------------------------------------\n')
        info(f'  Overhead (absolute):          {overhead_abs:+.4f}s\n')
        info(f'  Overhead (percentage):        {overhead_pct:+.2f}%\n')
    else:
        info('  Error: Could not complete one or both scenarios.\n')