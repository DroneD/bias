#!/usr/bin/python
###############################################################################
#   Copyright 2012, DroneD Project.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
###############################################################################


from twisted.python import usage, util
import socket
import struct
import time
import sys
import os

__author__ = "Justin Venus <justin.venus@gmail.com>"
__doc__ = """This utility builds configuration for a hypervisor inorder
to quickly allocate Virtual Machine resources in a repeatable way. This utility
should handle virtual supernets."""

APPNAME = sys.argv[0].split(os.path.sep)[0]
VERSION = '0.0.1'

###############################################################################
# Utility Methods
###############################################################################
def dottedQuadToNum(ip):
    "convert decimal dotted quad string to long integer"
    return struct.unpack('>L',socket.inet_aton(ip))[0]

def numToDottedQuad(n):
    "convert long int to dotted quad string"
    return socket.inet_ntoa(struct.pack('>L',n))

def makeName(index, padding=4, base="vm"):
    "create a padded network name"
    pad = str(index)
    while not len(pad) == padding:
         s = pad
         pad = '0' + s
    return '%s%s' % (base,pad)

def netbits(netmask):
    """take a network mask and figure out Total bits, Host bits, #of subnets,
       and address range.
    """
    #position in this list is very important.
    TBLMASK = ['0','128','192','224','240','248','252','254','255']
    a,b,c,d = netmask.split('.')
    x = [TBLMASK.index(a),TBLMASK.index(b),TBLMASK.index(c),TBLMASK.index(d)]
    Tb = sum(x)
    Hb = 32 - Tb
    subnets = 2**sum([ y for y in x if (8-y) != 0 ])
    return (Tb, Hb, subnets, (2**Hb))

#setup macaddr as locally administrated.
MACADDR = (6 << 44) + (6 << 40) + (6 << 36) + (1 << 32)

###############################################################################
# Headers and Templates
###############################################################################
dhcp_header = """#Generated Configuration
ddns-update-style none;
ignore client-updates;

subnet %(subnet)s netmask %(netmask)s {
        option domain-name "%(domain)s";
        option routers %(gateway)s;
        option ip-forwarding off;
        option broadcast-address %(BROADCAST)s;
        option subnet-mask %(netmask)s;
        option ntp-servers %(gateway)s;
        option domain-name-servers %(gateway)s;
}
"""

dhcp_tempate = """
host %(ident)s {
	hardware ethernet %(mac)s;
	fixed-address %(ip)s;
}
"""

reverse_template = """%(reverse)s\t\tPTR\t%(ident)s.%(domain)s.\n"""

libvirt_network = """<!-- 
Generated Configuration
-->

<network>
  <name>default</name>
  <uuid>3f967f6a-c1ab-afac-564a-649208fc8394</uuid>
  <forward mode='nat'/>
  <bridge name='%(virtbridge)s' stp='on' delay='0' />
  <mac address='%(GATEWAYMAC)s'/>
  <ip address='%(gateway)s' netmask='%(netmask)s'>
  </ip>
</network>
"""

named_header = """//Generated Configuration
options {
        listen-on port 53 { 127.0.0.1; %(gateway)s; };
        listen-on-v6 port 53 { ::1; };
        directory       "/var/named";
        dump-file       "/var/named/data/cache_dump.db";
        statistics-file "/var/named/data/named_stats.txt";
        memstatistics-file "/var/named/data/named_mem_stats.txt";
        allow-query     { any; };
        allow-recursion { %(CIDR)s; 127.0.0.1; };
        recursion yes;

        dnssec-enable yes;
        dnssec-validation yes;
        dnssec-lookaside auto;

        /* Path to ISC DLV key */
        bindkeys-file "/etc/named.iscdlv.key";

        managed-keys-directory "/var/named/dynamic";%(FORWARDERS)s
};

logging {
        channel default_debug {
                file "data/named.run";
                severity dynamic;
        };
};

zone "." IN {
        type hint;
        file "named.ca";
};

zone "%(INARPA)s" {
        type master;
        notify no;
        allow-query { any; };
        file "%(reversezone)s";
};

//Avoiding Namespace Collisions by explicitly defining resources.
"""

reverse_header = """;
; Generated Configuration
;
;
$TTL 3D
@       IN        SOA       %(gatewayname)s.%(domain)s. hostmaster.%(domain)s. (
                            %(DATE)s01         ; serial number
                            28800              ; 8H refresh, seconds
                            7200               ; 2H retry, seconds
                            2419200            ; 4W expire, seconds
                            86400 )            ; 1D minimum, seconds

                  NS        %(gatewayname)s.   ; Nameserver Address

"""

forward_template = """;
; Generated Configuration
;
;
$TTL 3D
@       IN      SOA    %(gatewayname)s.%(domain)s. hostmaster.%(domain)s. (
                       %(DATE)s01    ; serial number
                       28800              ; 8H refresh, seconds
                       7200               ; 2H retry, seconds
                       2419200            ; 4W expire, seconds
                       86400 )            ; 1D minimum, seconds

		NS	%(gatewayname)s.%(domain)s. ; Inet Address of nameserver

		A	%(ip)s
%(ident)s	IN	A	%(ip)s
"""

zone_template = """
zone "%(ident)s.%(domain)s" {type master; notify no; file "%(forward)s";};"""

###############################################################################
DATE = time.strftime("%Y%m%d",time.localtime())
class Server(object):
    DHCP = property(lambda s: dhcp_tempate % vars(s))
    REVERSE = property(lambda s: reverse_template % vars(s))
    ZONE = property(lambda s: zone_template % vars(s))
    def __init__(self, name, mac, ip, domain, gatewayname):
        self.reverse = '.'.join(reversed(ip.split('.')[-2:]))
        self.gatewayname = gatewayname
        self.forward = ''
        self.domain = domain
        self.ident = name
        self.DATE = DATE
        self.mac = mac
        self.ip = ip

    def write_forward_dns(self, directory):
        self.forward = os.path.join(
            directory, '%s.%s.zone' % (self.ident, self.domain))
        fd = open(self.forward, 'w')
        fd.write(forward_template % vars(self))
        fd.close()


class Parser(usage.Options):
    optParameters = sorted([
        ["netmask","","255.255.255.0","Network Mask."],
        ["gateway","","192.168.100.1","Router/Gateway Address."],
        ["gatewayname","","gateway","DNS entry for gateway"],
	["subnet","","192.168.100.0","Start of network range."],
        ["named","","/etc/named.conf","Location of named config."],
        ["dhcpd","","/etc/dhcp/dhcpd.conf","Location of dhcpd config."],
        ["nameservers","",None,"List of name servers for forwarding."],
	["domain","","example.com","Domain for Virtual Hosts."],
	["netvirt","","/etc/libvirt/qemu/networks/default.xml",
            "Location of default network."],
        ["forwardzonedir","","/var/named/virtual","Directory for Forward DNS Records."],
        ["reversezone","","/var/named/reverse.zone","Reverse DNS Records."],
        ["vmname","","vm","Base DNS of virtual machines."],
        ["virtbridge","","virbr0","Virtual Bridge Interface."],
    ])

    optFlags = [

    ]
    def __init__(self):
        usage.Options.__init__(self)
        self["GATEWAYMAC"] = '52:54:00:FE:A1:2F'
        self['DATE'] = DATE 
        self.parseOptions()

    def parseOptions(self):
        usage.Options.parseOptions(self)
        if not os.path.exists(self["forwardzonedir"]):
            os.makedirs(self["forwardzonedir"])

        Tb,Hb,SN,addrange = netbits(self["netmask"])
        self.PADDING = len(str(addrange))
        end = 1
        if (addrange - 1) <= 2**8:
            end = 3
        elif (addrange - 1) <= 2**16:
            end = 2
        self._makeForwarders()
        self["INARPA"] = ".".join(reversed(self["subnet"].split('.')[0:end]))
        self["INARPA"] += ".in-addr.arpa"
        self.IPSTART = dottedQuadToNum(self["subnet"])
        self.GATEWAY = dottedQuadToNum(self["gateway"])
        self.IPEND = self.IPSTART + addrange - 1
        self["BROADCAST"] = numToDottedQuad(self.IPEND)
        self["CIDR"] = "%s/%d" % (self["subnet"],Tb)

    def _makeForwarders(self):
        self["FORWARDERS"] = ""
        if not self["nameservers"]: return
        x = '; '.join(self["nameservers"].split(',')) + ';'
        self["FORWARDERS"] = "\n\n        forward first;\n"
        self["FORWARDERS"] += "        forwarders { %s };\n" % (x,)

    def opt_version(self):
        util.println("%s version: %s" % (APPNAME,VERSION))
        sys.exit(0)
    opt_version.__doc__ = "Display %s version and exit." % (APPNAME,)

    def __call__(self):
        count = -1
        #create network file for libvirtd
        open(self["netvirt"],'w').write(libvirt_network % self)
        #create named skeleton
        name_fd = open(self["named"],'w')
        name_fd.write(named_header % self)
        #prepare dhcpd.conf
        dhcp_fd = open(self["dhcpd"],'w')
        dhcp_fd.write(dhcp_header % self)
        #prepare the reverse dns file
        rvrs_fd = open(self["reversezone"],'w')
        rvrs_fd.write(reverse_header % self)
        while self.IPSTART < self.IPEND:
            self.IPSTART += 1
            if self.IPSTART == self.IPEND: break
            #skip the gateway address dhcpd entry
            if self.IPSTART == self.GATEWAY:
                x = Server(
                    self["gatewayname"], self["GATEWAYMAC"],
                    self["gateway"], self["domain"], self["gatewayname"]
                )
		x.write_forward_dns(self["forwardzonedir"])
                name_fd.write(x.ZONE)
                rvrs_fd.write(x.REVERSE)
                continue
            count += 1
            mac = MACADDR + count
            mac = str(hex(mac)).replace('0x','')
            mac = ':'.join(map(''.join, zip(*[iter(mac)]*2)))
            x = Server(
                makeName(count, padding=self.PADDING, base=self["vmname"]),
                mac, numToDottedQuad(self.IPSTART),
                self["domain"], self["gatewayname"]
            )
            x.write_forward_dns(self["forwardzonedir"])
            dhcp_fd.write(x.DHCP)
            name_fd.write(x.ZONE)
            rvrs_fd.write(x.REVERSE)
        dhcp_fd.close()
        name_fd.close()
        rvrs_fd.close()

if __name__ == '__main__':
    Parser()()
