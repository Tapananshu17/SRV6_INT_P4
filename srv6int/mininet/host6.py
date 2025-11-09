from mininet.node import Host

class IPv6Host(Host):

    def config(self, ipv6, ipv6_gw=None, **params):
        super(IPv6Host, self).config(**params)
        self.cmd('ip -4 addr flush dev %s' % self.defaultIntf())
        self.cmd('ip -6 addr flush dev %s' % self.defaultIntf())
        self.cmd('ip -6 addr add %s dev %s' % (ipv6, self.defaultIntf()))
        if ipv6_gw:
            self.cmd('ip -6 route add default via %s' % ipv6_gw)

        def updateIP():
            return ipv6.split('/')[0]
        self.defaultIntf().updateIP = updateIP

    def terminate(self):
        
        super(IPv6Host, self).terminate()

    def AddIPv6Addrs(self, ipv6_addresses, debug=False, **kwargs):
        
        self.cmd('sysctl -w net.ipv6.conf.all.forwarding=0')

        intfs = [intf for intf in self.intfNames() if intf != 'lo']
        
        for idx, intf_name in enumerate(intfs):
            if idx < len(ipv6_addresses):
                ipv6 = ipv6_addresses[idx]
                
                if isinstance(ipv6,list): ipv6,mac = ipv6
                else: mac = None
                if mac is not None:self.intf(intf_name).setMAC(mac)
                
                self.cmd(f'ip -6 addr add {ipv6} dev {intf_name}') 
                if debug: print(f"Assigned {ipv6} to {self.name}:{intf_name}")