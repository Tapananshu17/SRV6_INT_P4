import json
import multiprocessing
import os
import random
import re
import socket
import sys
import threading
import time
import urllib3
from contextlib import closing

from mininet.log import info, warn, debug
from mininet.node import Switch, Host

SIMPLE_SWITCH_GRPC = 'simple_switch_grpc' 
PKT_BYTES_TO_DUMP = 200 
VALGRIND_PREFIX = 'valgrind --leak-check=yes' 
SWITCH_START_TIMEOUT = 10  
BMV2_LOG_LINES = 5 
BMV2_DEFAULT_DEVICE_ID = 1 
DEFAULT_PIPECONF = "org.onosproject.pipelines.basic" 



STRATUM_BMV2 = 'stratum_bmv2' 
STRATUM_BINARY = '/bazel-bin/stratum/hal/bin/bmv2/' + STRATUM_BMV2 
STRATUM_INIT_PIPELINE = '/stratum/hal/bin/bmv2/dummy.json' 



def getStratumRoot():
    """
    Checks if the stratum repo is downloaded and set-up
    """
    if 'STRATUM_ROOT' not in os.environ:
        raise Exception("Env variable STRATUM_ROOT not set")
    return os.environ['STRATUM_ROOT']


def parseBoolean(value):
    if value in ['1', 1, 'true', 'True']:
        return True
    else:
        return False


def pickUnusedPort():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('localhost', 0))
    addr, port = s.getsockname()
    s.close()
    return port


def writeToFile(path, value):
    f = open(path, "w")
    f.write(str(value))
    f.close()


def watchDog(sw):
    """
    Ensures that the BMv2 switch stays alive.
    This is done using a keep-alive file; 
    which on removal, signals the watchdog to kill the switch
    """
    try:
        writeToFile(sw.keepaliveFile,
                    "Remove this file to terminate %s" % sw.name)
        while True:
            if ONOSBmv2Switch.mininet_exception == 1 \
                    or not os.path.isfile(sw.keepaliveFile):
                sw.killBmv2(log=False)
                return
            if sw.stopped:
                return
            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
                port = sw.grpcPortInternal if sw.grpcPortInternal else sw.grpcPort
                if s.connect_ex(('localhost', port)) == 0:
                    time.sleep(1)
                else:
                    warn("\n*** WARN: switch %s crashed ☠️, restarting... \n"
                         % sw.name)
                    sw.stop()
                    sw.start()
                    return
    except Exception as e:
        warn("*** ERROR: " + e.message)
        sw.killBmv2(log=True)


class ONOSHost(Host):
    def __init__(self, name, inNamespace=True, **params):
        Host.__init__(self, name, inNamespace=inNamespace, **params)

    def config(self, **params):
        r = super(Host, self).config(**params)
        for off in ["rx", "tx", "sg"]:
            cmd = "/sbin/ethtool --offload %s %s off" \
                  % (self.defaultIntf(), off)
            self.cmd(cmd)
        
        self.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")
        return r


class ONOSBmv2Switch(Switch):
    """BMv2 software switch with gRPC server"""
    
    
    
    
    mininet_exception = multiprocessing.Value('i', 0)

    def __init__(self, name, json=None, debugger=False, loglevel="trace",
                 elogger=False, grpcport=None, cpuport=255, notifications=False,
                 thriftport=None, netcfg=False, dryrun=False,
                 pipeconf=DEFAULT_PIPECONF, pktdump=False, valgrind=False,
                 gnmi=False, portcfg=True, onosdevid=None, stratum=False,
                 ipv6_addresses:list[str]=None,
                 **kwargs):
        Switch.__init__(self, name, **kwargs)
        self.ipv6_addresses = ipv6_addresses
        self.grpcPort = grpcport
        self.grpcPortInternal = None  
        self.thriftPort = thriftport
        self.cpuPort = cpuport
        self.json = json
        self.useStratum = parseBoolean(stratum)
        self.debugger = parseBoolean(debugger)
        self.notifications = parseBoolean(notifications)
        self.loglevel = loglevel
        
        
        
        self.logfile = 'tmp/bmv2-%s-log' % self.name
        self.elogger = parseBoolean(elogger)
        self.pktdump = parseBoolean(pktdump)
        self.netcfg = parseBoolean(netcfg)
        self.dryrun = parseBoolean(dryrun)
        self.valgrind = parseBoolean(valgrind)
        self.netcfgfile = 'tmp/bmv2-%s-netcfg.json' % self.name
        self.chassisConfigFile = 'tmp/bmv2-%s-chassis-config.txt' % self.name
        self.pipeconfId = pipeconf
        self.injectPorts = parseBoolean(portcfg)
        self.withGnmi = parseBoolean(gnmi)
        self.longitude = kwargs['longitude'] if 'longitude' in kwargs else None
        self.latitude = kwargs['latitude'] if 'latitude' in kwargs else None
        if onosdevid is not None and len(onosdevid) > 0:
            self.onosDeviceId = onosdevid
        else:
            self.onosDeviceId = "device:bmv2:%s" % self.name
        self.p4DeviceId = BMV2_DEFAULT_DEVICE_ID
        self.logfd = None
        self.bmv2popen = None
        self.stopped = True
        
        
        self.keepaliveFile = 'tmp/bmv2-%s-watchdog.out' % self.name
        self.targetName = STRATUM_BMV2 if self.useStratum else SIMPLE_SWITCH_GRPC
        self.controllers = None

        
        self.cleanupTmpFiles()

    def getSourceIp(self, dstIP):
        """
        Queries the Linux routing table (`ip route`) to get the IP address (and hence the interface) that can talk with
        dstIP (the controller's IP address, passed in by static method `getControllerIP` for the MiniNet `Switch` class).
        Note that sometimes, due to AS policies, only srcIP addresses in the same subnet as the dstIP can talk with dstIP.
        Also note that the same interface may have multiple IP addresses, which may all be from different IP address blocks.
        This function returns any one of the src IP addresses that are in the same subnet.
        """
        
        ipRouteOut = self.cmd('ip route get %s' % dstIP) 
        
        
        r = re.search(r"src (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", ipRouteOut) 
        
        return r.group(1) if r else None 

    def getDeviceConfig(self, srcIP):
        """
        Returns a JSON string that describes the driver, port id for grpc, etc. for this switch.
        This JSON string will be passed to the ONOS controller using it Netcfg REST API later (`doOnosNetcfg`).
        Thus, we get automatic router discovery.
        """
        basicCfg = {
            "managementAddress": "grpc://%s:%d?device_id=%d" % (
                srcIP, self.grpcPort, self.p4DeviceId),
            "driver": "stratum-bmv2" if self.useStratum else "bmv2",
            "pipeconf": self.pipeconfId
        }

        if self.longitude and self.latitude:
            basicCfg["longitude"] = self.longitude
            basicCfg["latitude"] = self.latitude

        cfgData = {
            "basic": basicCfg
        }

        if not self.useStratum and self.injectPorts:
            portData = {}
            portId = 1
            for intfName in self.intfNames():
                if intfName == 'lo':
                    continue
                portData[str(portId)] = {
                    "number": portId,
                    "name": intfName,
                    "enabled": True,
                    "removed": False,
                    "type": "copper",
                    "speed": 10000
                }
                portId += 1

            cfgData['ports'] = portData

        return cfgData

    def chassisConfig(self):
        """
        Stratum specific. 
        Returns a JSON string describing only the hardware config.
        """
        config = """description: "BMv2 simple_switch {name}"
chassis {{
  platform: PLT_P4_SOFT_SWITCH
  name: "{name}"
}}
nodes {{
  id: {nodeId}
  name: "{name} node {nodeId}"
  slot: 1
  index: 1
}}\n""".format(name=self.name, nodeId=self.p4DeviceId)

        intfNumber = 1
        for intfName in self.intfNames():
            if intfName == 'lo':
                continue
            config = config + """singleton_ports {{
  id: {intfNumber}
  name: "{intfName}"
  slot: 1
  port: {intfNumber}
  channel: 1
  speed_bps: 10000000000
  config_params {{
    admin_state: ADMIN_STATE_ENABLED
  }}
  node: {nodeId}
}}\n""".format(intfName=intfName, intfNumber=intfNumber,
              nodeId=self.p4DeviceId)
            intfNumber += 1

        return config

    def doOnosNetcfg(self, controllerIP):
        """
        Notifies ONOS about the new device via Netcfg.
        The controllerIP is given to the function by MiniNet
        """
        srcIP = self.getSourceIp(controllerIP)
        if not srcIP:
            warn("*** WARN: unable to get switch IP address, won't do netcfg\n")
            return

        cfgData = {
            "devices": {
                self.onosDeviceId: self.getDeviceConfig(srcIP)
            }
        }

        
        with open(self.netcfgfile, 'w') as fp:
            json.dump(cfgData, fp, indent=4) 

        if not self.netcfg:
            
            print("")
            return

        

        
        url = 'http://%s:8181/onos/v1/network/configuration/' % controllerIP
        
        pm = urllib3.HTTPPasswordMgrWithDefaultRealm()
        pm.add_password(None, url,
                        os.environ['ONOS_WEB_USER'],
                        os.environ['ONOS_WEB_PASS'])
        urllib3.install_opener(urllib3.build_opener(
            urllib3.HTTPBasicAuthHandler(pm)))
        
        req = urllib3.Request(url, json.dumps(cfgData),
                              {'Content-Type': 'application/json'})
        try:
            f = urllib3.urlopen(req)
            print(f.read())
            f.close()
        except urllib3.URLError as e:
            warn("*** WARN: unable to push config to ONOS (%s)\n" % e.reason)

    def AddIPv6Addrs(self, **kwargs):
        
        self.cmd('sysctl -w net.ipv6.conf.all.forwarding=0')

        if self.ipv6_addresses is not None:
            intfs = [intf for intf in self.intfNames() if intf != 'lo']
            
            for idx, intf_name in enumerate(intfs):
                if idx < len(self.ipv6_addresses):
                    ipv6 = self.ipv6_addresses[idx]
                    
                    if isinstance(ipv6,list): ipv6,mac = ipv6
                    else: mac = None
                    print(ipv6,mac)
                    if mac is not None:self.intf(intf_name).setMAC(mac)
                    
                    self.cmd(f'ip -6 addr add {ipv6} dev {intf_name}') 
                    print(f"Assigned {ipv6} to {self.name}:{intf_name}")

    def start(self, controllers=None):
        """
        Main loop. 
        This is what MiniNet will run while doing `net.start()` 
        """
        if not self.stopped:
            warn("*** %s is already running!\n" % self.name)
            return

        if controllers is not None:
            
            
            self.controllers = controllers

        
        self.cleanupTmpFiles()

        if self.grpcPort is None:
            self.grpcPort = pickUnusedPort()
        writeToFile("tmp/bmv2-%s-grpc-port" % self.name, self.grpcPort)
        if self.thriftPort is None:
            self.thriftPort = pickUnusedPort()
        writeToFile("tmp/bmv2-%s-thrift-port" % self.name, self.thriftPort)

        if self.useStratum:
            config_dir = "tmp/bmv2-%s-stratum" % self.name
            os.mkdir(config_dir)
            with open(self.chassisConfigFile, 'w') as fp:
                fp.write(self.chassisConfig())
            if self.grpcPortInternal is None:
                self.grpcPortInternal = pickUnusedPort()
            cmdString = self.getStratumCmdString(config_dir)
        else:
            cmdString = self.getBmv2CmdString()

        if self.dryrun:
            info("\n*** DRY RUN (not executing %s)\n" % self.targetName)

        debug("\n%s\n" % cmdString)

        try:
            if not self.dryrun:
                
                self.stopped = False
                self.logfd = open(self.logfile, "w")
                self.logfd.write(cmdString + "\n\n" + "-" * 80 + "\n\n")
                self.logfd.flush()
                
                self.bmv2popen = self.popen(cmdString,
                                            stdout=self.logfd,
                                            stderr=self.logfd)
                self.waitBmv2Start()
                
                threading.Thread(target=watchDog, args=[self]).start()
            ctrlIP = self.controllerIp(self.controllers)
            self.doOnosNetcfg(ctrlIP)

        except Exception:
            ONOSBmv2Switch.mininet_exception = 1
            self.killBmv2()
            self.printBmv2Log()
            raise

    def getBmv2CmdString(self):
        bmv2Args = [SIMPLE_SWITCH_GRPC] + self.bmv2Args() 
        if self.valgrind:
            bmv2Args = VALGRIND_PREFIX.split() + bmv2Args
        return " ".join(bmv2Args)

    def getStratumCmdString(self, config_dir):
        stratumRoot = getStratumRoot()
        args = [
            stratumRoot + STRATUM_BINARY,
            '-device_id=%d' % self.p4DeviceId,
            '-chassis_config_file=%s' % self.chassisConfigFile,
            '-forwarding_pipeline_configs_file=/dev/null',
            '-persistent_config_dir=' + config_dir,
            '-initial_pipeline=' + stratumRoot + STRATUM_INIT_PIPELINE,
            '-cpu_port=%s' % self.cpuPort,
            '-external_hercules_urls=0.0.0.0:%d' % self.grpcPort,
            '-local_hercules_url=localhost:%d' % self.grpcPortInternal,
            '-bmv2_thrift_port=%d' % self.thriftPort,
            '-bmv2_log_level=%s' % self.loglevel,
            '-max_num_controllers_per_node=10',
            '-write_req_log_file=/dev/null'
        ]
        return " ".join(args)

    def bmv2Args(self):
        args = ['--device-id %s' % str(self.p4DeviceId)]
        for port, intf in self.intfs.items():
            if not intf.IP():
                args.append('-i %d@%s' % (port, intf.name))
        args.append('--thrift-port %s' % self.thriftPort)
        if self.notifications:
            ntfaddr = 'ipc:///tmp/bmv2-%s-notifications.ipc' % self.name
            args.append('--notifications-addr %s' % ntfaddr)
        if self.elogger:
            nanologaddr = 'ipc:///tmp/bmv2-%s-nanolog.ipc' % self.name
            args.append('--nanolog %s' % nanologaddr)
        if self.debugger:
            dbgaddr = 'ipc:///tmp/bmv2-%s-debug.ipc' % self.name
            args.append('--debugger-addr %s' % dbgaddr)
        args.append('--log-console')
        if self.pktdump:
            args.append('--pcap --dump-packet-data %s' % PKT_BYTES_TO_DUMP)
        args.append('-L%s' % self.loglevel)
        if not self.json:
            args.append('--no-p4')
        else:
            args.append(self.json)
        
        args.append('--')
        args.append('--cpu-port %s' % self.cpuPort)
        args.append('--grpc-server-addr 0.0.0.0:%s' % self.grpcPort)
        return args

    def waitBmv2Start(self):
        
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        endtime = time.time() + SWITCH_START_TIMEOUT
        while True:
            port = self.grpcPortInternal if self.grpcPortInternal else self.grpcPort
            result = sock.connect_ex(('localhost', port))
            if result == 0:
                
                sys.stdout.write("⚡️ %s @ %d" % (self.targetName, self.bmv2popen.pid))
                sys.stdout.flush()
                
                sock.close()
                break
            
            if endtime > time.time():
                sys.stdout.write('.')
                sys.stdout.flush()
                time.sleep(0.05)
            else:
                
                raise Exception("Switch did not start before timeout")

    def printBmv2Log(self):
        if os.path.isfile(self.logfile):
            print("-" * 80)
            print("%s log (from %s):" % (self.name, self.logfile))
            with open(self.logfile, 'r') as f:
                lines = f.readlines()
                if len(lines) > BMV2_LOG_LINES:
                    print("...")
                for line in lines[-BMV2_LOG_LINES:]:
                    print(line.rstrip())

    @staticmethod
    def controllerIp(controllers):
        try:
            
            clist = controllers[0].nodes()
        except AttributeError:
            clist = controllers
        assert len(clist) > 0
        return random.choice(clist).IP()

    def killBmv2(self, log=False):
        self.stopped = True
        if self.bmv2popen is not None:
            self.bmv2popen.terminate()
            self.bmv2popen.wait()
            self.bmv2popen = None
        if self.logfd is not None:
            if log:
                self.logfd.write("*** PROCESS TERMINATED BY MININET ***\n")
            self.logfd.close()
            self.logfd = None

    def cleanupTmpFiles(self):
        self.cmd("rm -rf /tmp/bmv2-%s-*" % self.name)

    def stop(self, deleteIntfs=True):
        """Terminate switch."""
        self.killBmv2(log=True)
        Switch.stop(self, deleteIntfs)


class ONOSStratumSwitch(ONOSBmv2Switch):
    def __init__(self, name, **kwargs):
        kwargs["stratum"] = True
        super(ONOSStratumSwitch, self).__init__(name, **kwargs)



switches = {
    'onosbmv2': ONOSBmv2Switch,
    'stratum': ONOSStratumSwitch,
}
hosts = {'onoshost': ONOSHost}
