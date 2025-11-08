## Demonstration
### Requirements
```
sudo apt-get update
sudo apt-get install nfdump
sudo apt-get install softflowd
sudo apt-get install iperf3
```

### Overview
Runs the NetFlow V9 inside Mininet.

### Instructions 
```
sudo python3 netflow.py 
```
Then follow the outout logs.

## What is NetFlow?
### Overview
Netflow is a data plane network telemetry method to get flow statistics from network devices. The network devices group packet streams based on source and destination, layer4 protocol and ingress interface into flows. These flows are temporarily stored in the flow cache on devices and exported to a central collector every export interval. So, NetFlow provides flow-level visibility rather than per-packet detail, enabling analysis of traffic volume, communication pairs, protocol usage, and application behavior.

### Specifications
\> Export Protocol and Port: UDP, 2055\
\> Version Histroy: v5, v9, IPFIX (standardised), PSAMP \
\> Export timeout: 15-300 s (based on flow protocol)
\> Data Format: Flow Record