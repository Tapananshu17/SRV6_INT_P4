## Demonstration
### Requirements
```
sudo apt-get update
sudo apt-get install snmpd
sudo apt-get install snmpd
```

### Configuration
```
sudo mv /etc/snmp/snmpd.conf  /etc/snmp/snmpd.conf.org
sudo vim /etc/snmp/snmpd.conf
# Add these lines
# Change public by your SecretPassword if you like
rocommunity  public
```

```
sudo vim /etc/default/snmpd
```
Change from:
```
# snmpd options (use syslog, close stdin/out/err).
SNMPDOPTS='-Lsd -Lf /dev/null -u snmp -I -smux -p /var/run/snmpd.pid 127.0.0.1'
```

To:
```
# snmpd options (use syslog, close stdin/out/err).
#SNMPDOPTS='-Lsd -Lf /dev/null -u snmp -I -smux -p /var/run/snmpd.pid 127.0.0.1'
SNMPDOPTS='-Lsd -Lf /dev/null -u snmp -I -smux -p /var/run/snmpd.pid -c /etc/snmp/snmpd.conf'
```
Start
```
 /etc/init.d/snmpd restart
```

### Overview
Runs the SNMP inside Mininet.


### Instructions 
```
sudo python3 snmp.py 
```
Then follow the outout logs.

## What is SNMP?
### Overview
SNMP is a management plane, network telemetry protocol used for monitoring and managing network devices. It follows the manager-agent architecutre. The manager (collector) issues queries to SNMP agents running insider network devices. These agents maintain state and information on the device as defined in MIB, which consist of hierarchically structured variables representing device configuration, performance metrics, and operational status.

### Specifications
\> Protocol and Port used for queries: UDP, 161 \
\> Data Format: MIB \
\> Version History: v1, v2 and v3
