#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License.  You may obtain a copy of
# the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations under
# the License.

""" 
  Extreme-Netiron Driver 

  This driver provides support for Netiron MLXe routers
"""
from netmiko import ConnectHandler
from napalm_base.base import NetworkDriver
from napalm_base.exceptions import ConnectionException, MergeConfigException, \
    ReplaceConfigException, SessionLockedException, CommandErrorException
import napalm_base.helpers

import os
import re
from shutil import copyfile

class NetironDriver(NetworkDriver):
    """Napalm Driver for Vendor Extreme/Netiron."""

    def __init__(self, hostname, username, password, timeout=60,
                 optional_args=None):

        if optional_args is None:
            optional_args = {}

        self.device = None
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.port = optional_args.get('port', 22)

    def open(self):
        try:
            # FIXME: Needs to be changed to extreme_netiron (?)
            self.device = ConnectHandler(device_type='brocade_netiron',
                                         ip=self.hostname,
                                         port=self.port,
                                         username=self.username,
                                         password=self.password,
                                         timeout=self.timeout,
                                         verbose=True)
        except Exception:
            raise ConnectionException("Cannot connect to switch: %s:%s" \
                                          % (self.hostname, self.port))

    def close(self):
        self.device.disconnect()
        return

    def cli(self, commands):
        cli_output = dict()

        if type(commands) is not list:
            raise TypeError('Please enter a valid list of commands!')

        for command in commands:
            output = self.device.send_command(command)
            if 'Invalid input' in output:
                raise ValueError(
                    'Unable to execute command "{}"'.format(command))
            cli_output.setdefault(command, {})
            cli_output[command] = output

        return cli_output

    def get_arp_table(self):

        arp_table = list()

        arp_cmd = 'show arp'
        output = self.device.send_command(arp_cmd)
        output = output.split('\n')
        output = output[7:]

        for line in output:
            fields = line.split()

            if len(fields) == 6:
                num, address, mac, typ, age, interface = fields
                try:
                    if age == 'None':
                        age = 0
                    age = float(age)
                except ValueError:
                    print(
                        "Unable to convert age value to float: {}".format(age)
                        )

                if "None" in mac:
                    mac = "00:00:00:00:00:00"
                else:
                    mac = napalm_base.helpers.mac(mac)

                entry = {
                    'interface': interface,
                    'mac': mac,
                    'ip': address,
                    'age': age
                }
                arp_table.append(entry)

        return arp_table

    def _parse_port_change(self, last_str):

		#(3 days 11:27:46 ago)	
        r1 = re.match("(\d+) days (\d+):(\d+):(\d+)", last_str)
        if r1:
        	days = int(r1.group(1))
        	hours = int(r1.group(2))
        	mins = int(r1.group(3))
        	secs = int(r1.group(4))

        	return float(secs + (mins*60) + (hours*60*60) + (days*24*60*60))
        else:
        	return (float(-1.0))

    def _get_interface_detail(self, port):

        command = "show interface ethernet {}".format(port)
        output = self.device.send_command(command)

        last_flap = re.search(r"\s+Port state change time: \S+\s+\d+\s+\S+\s+\((.*) ago\)", output).group(1)
        last_flap = self._parse_port_change(last_flap)
        if re.search(r"\s+No port name", output, re.MULTILINE):
            description = ""
        else:
            description = re.search(r"\s+Port name is (.*)", output, re.MULTILINE).group(1)
        mac = re.search(r"\s+Hardware is \S+, address is (\S+) (.+)", output).group(1)
        speed = re.search(r"\s+Configured speed (\d+)Gbit,.+", output).group(1)
        speed = int(speed)*1000

        return [last_flap, description, speed, mac]

    def _get_logical_interface_detail(self, port):

    	# replace lb keyword with loopback keyword
    	port.replace("lb","loopback")
        command = "show interface {}".format(port)
        output = self.device.send_command(command)

        last_flap = -1
        speed = -1
        if re.search(r"\s+No port name", output, re.MULTILINE):
            description = ""
        else:
            description = re.search(r"\s+Port name is (.*)", output, re.MULTILINE).group(1)
        match = re.search(r"\s+Hardware is Virtual Ethernet, address is (\S+) (.+)", output)
        if match:
        	mac = match.group(1)
        else:
        	mac = "N/A"

        return [last_flap, description, speed, mac]

    def get_interfaces(self):

        interface_list = {}

        iface_cmd = 'show interface brief wide'
        output = self.device.send_command(iface_cmd)
        output = output.split('\n')
        output = output[2:]

        for line in output:
            fields = line.split()

            if len(line) == 0:
                continue
            elif len(fields) >= 6:
                port, link, state, speed, tag, mac = fields[:6]
            else:
                raise ValueError(u"Unexpected Response from the device")

            if re.match("\d+/\d+", port):
                port_detail = self._get_interface_detail(port)

                state = state.lower()
                is_up = bool('forward' in state)

                link = link.lower()
                is_enabled = not bool('disabled' in link)
        
            elif re.match("(ve|lb)\d+", port):
                port_detail = self._get_logical_interface_detail(port)

            	link = link.lower()
            	is_enabled = not bool('down' in link)
            	is_up = is_enabled
            	
            else:
                continue

            interface_list[port] = {
                'is_up': is_up,
                'is_enabled': is_enabled,
                'description': unicode(port_detail[1]),
                'last_flapped': float(port_detail[0]),
                'speed': int(port_detail[2]),
                'mac_address': unicode(port_detail[3]),
            }
        return interface_list
 
    def get_interfaces_counters(self):

        cmd = "show statistics"
        lines = self.device.send_command(cmd)
        lines = lines.split('\n')

        counters = {}
        for line in lines:
            port_block = re.search('\s*PORT (\S+) Counters:.*', line)
            if port_block:
                interface = port_block.group(1)
                counters.setdefault(interface, {})
            elif len(line)==0:
                continue
            else:
                octets = re.search(r"\s+InOctets\s+(\d+)\s+OutOctets\s+(\d+)\.*", line)
                if octets:
                   counters[interface]['rx_octets'] =  int(octets.group(1))
                   counters[interface]['tx_octets'] =  int(octets.group(2))
                   continue

                packets = re.search(r"\s+InPkts\s+(\d+)\s+OutPkts\s+(\d+)\.*", line)
                if packets:
                   counters[interface]['rx_unicast_packets'] = int(packets.group(1))
                   counters[interface]['tx_unicast_packets'] = int(packets.group(2))
                   continue

                broadcast = re.search(r"\s+InBroadcastPkts\s+(\d+)\s+OutBroadcastPkts\s+(\d+)\.*", line)
                if broadcast:
                   counters[interface]['rx_broadcast_packets'] = int(broadcast.group(1))
                   counters[interface]['tx_broadcast_packets'] = int(broadcast.group(2))
                   continue

                multicast = re.search(r"\s+InMulticastPkts\s+(\d+)\s+OutMulticastPkts\s+(\d+)\.*", line)
                if multicast:
                   counters[interface]['rx_multicast_packets'] = int(multicast.group(1))
                   counters[interface]['tx_multicast_packets'] = int(multicast.group(2))
                   continue

                error = re.search(r"\s+InErrors\s+(\d+)\s+OutErrors\s+(\d+)\.*", line)
                if error:
                   counters[interface]['rx_errors'] = int(error.group(1))
                   counters[interface]['tx_errors'] = int(error.group(2))
                   continue

                discard = re.search(r"\s+InDiscards\s+(\d+)\s+OutDiscards\s+(\d+)\.*", line)
                if discard:
                   counters[interface]['rx_discards'] = int(discard.group(1))
                   counters[interface]['tx_discards'] = int(discard.group(2))

        return counters

    def get_mac_address_table(self):

        cmd = "show mac-address"
        lines = self.device.send_command(cmd)
        lines = lines.split('\n')

        mac_address_table = []
        lines = lines[5:]

        for line in lines:
            fields = line.split()

            if len(fields) == 4:
                mac_address, port, age, vlan = fields
            
                is_static = bool('Static' in age)
                mac_address = napalm_base.helpers.mac(mac_address)

                entry = {
                   'mac': mac_address,
                   'interface': unicode(port),
                   'vlan': int(vlan),
                   'active': bool(1),
                   'static': is_static,
                   'moves': None,
                   'last_move': None
                }
                mac_address_table.append(entry)
            
        return mac_address_table
	           
    def get_ntp_stats(self):

        output = self.device.send_command("show ntp associations")
        output = output.split("\n")

        ntp_stats = list()
        output = output[1:-1]

        for line in output:
            fields = line.split()
            if len(line) == 0:
                return {}

            if len(fields) == 9:
                remote, ref, st, when, poll, reach, delay, offset, disp = fields
                synch = "*" in remote

                match = re.search("(\d+\.\d+\.\d+\.\d+)", remote)
                ip = match.group(1)

                when = when if when != '-' else 0

                ntp_stats.append({
                    "remote": unicode(ip),
                    "referenceid": unicode(ref),
                    "synchronized": bool(synch),
                    "stratum": int(st),
                    "when": int(when),
                    "type": unicode("NA"),
                    "hostpoll": int(poll),
                    "reachability": int(reach),
                    "delay": float(delay),
                    "offset": float(offset),
                    "jitter": float(disp)
                })

        return ntp_stats

    def _lldp_detail_parser(self, interface):
        """ Parse a single detailed entry """

        command = "show lldp neighbors detail ports eth {}".format(interface)
        output = self.device.send_command(command)

        chassis_id = re.search(r"\s+\+ Chassis ID \(MAC address\): (\S+)", output).group(1)
        port_id = re.search(r"\s+\+ Port ID \(MAC address\): (\S+)", output, re.MULTILINE).group(1)
        system_name = re.search(r"\s+\+ System name\s+:\s+\"(.+)\"", output).group(1)
        port_description = re.search(r"\s+\+ Port description    :\s+\"(\S+)\"", output).group(1)
        system_capabilities = re.search(r"\s+\+ System capabilities :\s+(.+)", output).group(1)
        enabled_capabilities = re.search(r"\s+Enabled capabilities:\s+(.+)", output).group(1)
        remote_address = re.search(r"\s+\+ Management address \(IPv4\):\s+(.+)", output).group(1)

        return [port_id, port_description, chassis_id, system_name, 
            system_capabilities, enabled_capabilities, remote_address]

    def get_lldp_neighbors(self):

        lldp = {}
        command = 'show lldp neighbors'
        lines = self.device.send_command(command)
        lines = lines.split("\n")

        lines = lines[2:]

        for line in lines:
            fields = line.split()

            if len(fields) == 5:
                local_port, chassis, portid, portdesc, name = fields
                # Sys name name may be truncated, so get the complete name from the detailed output
                lldp_detail = self._lldp_detail_parser(local_port)
            
                entry = {
                   'port': unicode(lldp_detail[1]),
                   'hostname': unicode(lldp_detail[3])
                }
                lldp.setdefault(local_port, [])	
                lldp[local_port].append(entry)

        return lldp

    def get_lldp_neighbors_detail(self, interface=''):

        lldp = {}
        command = 'show lldp neighbors'
        lines = self.device.send_command(command)
        lines = lines.split("\n")

        lines = lines[2:]

        for line in lines:
            fields = line.split()

            if len(fields) == 5:
                local_port, chassis, portid, portdesc, name = fields

                lldp_detail = self._lldp_detail_parser(local_port)   
                entry = {
                    'parent_interface': u'N/A',
                    'remote_port': unicode(lldp_detail[0]),
                    'remote_port_description': unicode(lldp_detail[1]),
                    'remote_chassis_id': unicode(lldp_detail[2]),
                    'remote_system_name': unicode(lldp_detail[3]),
                    'remote_system_description': u'N/A',
                    'remote_system_capab': unicode(lldp_detail[4]),
                    'remote_system_enable_capab': unicode(lldp_detail[5])
                }

                if local_port == interface:
                    return {interface: lldp[local_port]}

                lldp.setdefault(local_port, [])	
                lldp[local_port].append(entry)

        return lldp

    def get_config(self, retrieve='all'):
        
        config = {
            'startup': '',
            'running': '',
            'candidate': unicode('')
        }

        if retrieve.lower() in ('running', 'all'):
            _cmd = 'show running-config'
            config['running'] = unicode(self.cli([_cmd]).get(_cmd))
        if retrieve.lower() in ('startup', 'all'):
            _cmd = 'show configuration'
            config['startup'] = unicode(self.cli([_cmd]).get(_cmd))
        return config

    def get_users(self):
        
        command = 'show users'
        lines = self.device.send_command(command)
        lines = lines.split("\n")

        lines = lines[2:]
        info = {}
        for line in lines:
            match = re.match("(\S+)\s+(\S+)\s+(\S+)\s+(\d+)", line)
            if match:
                user  = match.group(1)
                passw = match.group(2)
                level = match.group(4)

                info[user] = {
                   'level': int(level),
                   'password': passw,
                   'sshkeys': list()
                }

        return info

    def get_ntp_servers(self):

        command = "show running | begin ^ntp"
        lines = self.device.send_command(command)
        lines = lines.split("\n")

        ntp = {}
        for line in lines:

            if "!" in line:
    		   return ntp

            match = re.match("\s+server\s+(\S+)(.*)", line)
            if match:
               server = unicode(match.group(1))
               ntp[server] = {}

        return ntp

    def get_ntp_peers(self):

    	command = "show running | begin ^ntp"
    	lines = self.device.send_command(command)
    	lines = lines.split("\n")

        ntp = {}
    	for line in lines:
            if "!" in line:
    		   return ntp

            match = re.match("\s+peer\s+(\S+)(.*)", line)
            if match:
                peer = unicode(match.group(1))
                ntp[peer] = {}

    	return ntp

    def get_facts(self):

        command = 'show version'
        lines = self.device.send_command(command)
        for line in lines.splitlines():
            r1 = re.match(r'^Chassis:\s+(.*)\s+\(Serial #:\s+(\S+),(.*)', line)
            if r1:
                model = r1.group(1)
                serial = r1.group(2)

            r2 = re.match(r'^IronWare : Version\s+(\S+)\s+Copyright \(c\)\s+(.*)', line)
            if r2:
                version = r2.group(1)
                vendor = r2.group(2)

        command = 'show uptime'
        lines = self.device.send_command(command)
        for line in lines.splitlines():
            # Get the uptime from the Active MP module
            r1 = re.match(r'\s+Active MP(.*)Uptime\s+(\d+)\s+days'
                          r'\s+(\d+)\s+hours'
                          r'\s+(\d+)\s+minutes'
                          r'\s+(\d+)\s+seconds',line)
            if r1:
                days = int(r1.group(2))
                hours = int(r1.group(3))
                minutes = int(r1.group(4))
                seconds = int(r1.group(5))
                uptime = seconds + minutes*60 + hours*3600 + days*86400

        command = 'show running-config | include ^hostname'
        lines = self.device.send_command(command)
        for line in lines.splitlines():
            r1 = re.match(r'^hostname (\S+)', line)
            if r1:
                hostname = r1.group(1)
                
        facts = {
            'uptime': uptime,
            'vendor': unicode(vendor),
            'model': unicode(model),
            'hostname': unicode(hostname),
            # FIXME: fqdn
            'fqdn': unicode("Unknown"),
            'os_version': unicode(version),
            'serial_number': unicode(serial),
            'interface_list': []
        }

        iface = 'show interface brief wide'
        output = self.device.send_command(iface)
        output = output.split('\n')
        output = output[2:]

        for line in output:
            fields = line.split()

            if len(line) == 0:
                continue
            elif len(fields) >= 6:
                port, link, state, speed, tag, mac = fields[:6]

                r1 = re.match(r'^(\d+)/(\d+)', port)
                if r1:
                    port = 'e' + port
                    facts['interface_list'].append(port)
                elif re.match(r'^mgmt1', port):
                    facts['interface_list'].append(port)
                elif re.match(r'^ve(\d+)', port):
                    facts['interface_list'].append(port)
                elif re.match(r'^lb(\d+)', port):
                    facts['interface_list'].append(port)

        return facts
