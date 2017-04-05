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

""" Extreme-Netiron Driver 

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
        #self.device.disconnect()
        return

    def cli(self, commands=None):
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

    def send_command(self, cmd):
        output = self.device.send_command(cmd)
        if 'Invalid input' in output:
            raise ValueError('Unable to execute command "{}"'.format(cmd))
        return output

    def get_arp_table(self):

        arp_table = []

        arp_cmd = 'show arp'
        output = self.device.send_command(arp_cmd)
        output = output.split('\n')
        output = output[7:]

        for line in output:
            fields = line.split()

            if len(fields) == 0:
                return {}
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
            else:
                raise ValueError(
                    "Unexpected output from: {}".format(line.split()))

        return arp_table

    def get_vlan_table(self):
        """ FIXME: not officially supported """

        vlan_table = []

        vlan_cmd = 'show vlan'
        output = self.device.send_command(vlan_cmd)
        output = output.split('\n')

        for line in output:
            if len(line) == 0:
                continue

            r1 = re.match("^PORT-VLAN\s+(\d+), Name\s+(\S+),\s+(.*)", line)
            if r1:
                entry = {
                    'vlan': r1.group(1),
                    'name': r1.group(2)
                }
                vlan_table.append(entry)

        return vlan_table

    def get_interfaces_ip(self):
        
        interface_list = {}

        iface_cmd = 'show ip interface'
        output = self.device.send_command(iface_cmd)
        output = output.split('\n')
        output = output[2:]

        for line in output:
            fields = line.split()

            if len(fields) == 8:
                interface_type, interface, ip_address, status, method, status2, protocol, vrf = fields
            else:
                raise ValueError(u"Unexpected Response from the device")

            protocol = protocol.lower()
            is_up = bool('up' in protocol)

            status = status.lower()
            if 'admin' in status:
                is_enabled = False
            else:
                is_enabled = True

            interface_list[interface_type + interface] = {
                'is_up': is_up,
                'is_enabled': is_enabled,
                'ip_address': ip_address,
                'vrf': vrf
            }
        
        return interface_list

    def _get_interface_detail(self, port):

        command = "show interface ethernet {}".format(port)
        output = self.send_command(command)

        # Port state change time: Jan  5 11:06:13  (88 days 04:42:52 ago)
        # FIXME: Convert string into int secs
        last_flap = re.search(r"\s+Port state change time: (.*)", output).group(1)
        if re.search(r"\s+No port name", output, re.MULTILINE):
            description = "NA"
        else:
            description = re.search(r"\s+Port name is (.*)", output, re.MULTILINE).group(1)
        # FIXME TBC: Configured speed or hardware speed
        # FIXME: Convert speed in int Mbit
        speed, mac = re.search(r"\s+Hardware is (\S+), address is (\S+) (.+)", output).group(1,2)

        return [last_flap, description, speed, mac]

    def get_interfaces(self):

        # FIXME: Only physical interfaces (?)
        interface_list = {}

        iface_cmd = 'show interface brief wide'
        output = self.device.send_command(iface_cmd)
        output = output.split('\n')
        output = output[2:]

        for line in output:
            fields = line.split()

            print(fields)
            if len(line) == 0:
                continue
            elif len(fields) == 6:
                port, link, state, speed, tag, mac = fields
            elif len(fields) >= 7:
                port, link, state, speed, tag, mac = fields[:6]
            else:
                raise ValueError(u"Unexpected Response from the device")

            if re.match("\d+/\d+", port):
                port_detail = self._get_interface_detail(port)
            else:
                continue

            state = state.lower()
            is_up = bool('up' in state)

            link = link.lower()
            if 'disable' in link:
                is_enabled = False
            else:
                is_enabled = True

            interface_list[port] = {
                'is_up': is_up,
                'is_enabled': is_enabled,
                'description': port_detail[1],
                'last_flapped': port_detail[0],
                'speed': port_detail[2],
                'mac_address': port_detail[3],
            }
        return interface_list
 
    def get_interfaces_counters(self):

        # FIXME: Missing counters, according to http://napalm.readthedocs.io/en/latest/base.html
        cmd = "show statistics brief"
        lines = self.device.send_command(cmd)
        lines = lines.split('\n')

        counters_table = []
        lines = lines[3:]

        for line in lines:
            fields = line.split()

            if len(line) == 0:
                return {}
            if len(fields) == 7:
                interface, pkts_rx, pkts_tx, col_rx, col_tx, err_rx, err_tx = fields
                entry = {
                    'interface': interface,
                    'pkts_rx': pkts_rx,
                    'pkts_tx': pkts_tx,
                    'col_rx': col_rx,
                    'col_tx': col_tx,
                    'err_rx': err_rx,
                    'err_tx': err_tx
                }
                counters_table.append(entry)

            else:
                raise ValueError(
                    "Unexpected output from: {}".format(line.split()))

        return counters_table

    def get_mac_address_table(self):

        cmd = "show mac-address"
        lines = self.device.send_command(cmd)
        lines = lines.split('\n')


        mac_address_table = []
        lines = lines[5:]

        for line in lines:
            fields = line.split()

            if len(line) == 0:
                return {}
            if len(fields) == 4:
                mac_address, port, age, vlan = fields
            else:
                raise ValueError(
                    "Unexpected output from: {}".format(line.split()))
            
            is_static = bool('Static' in age)
            mac_address = napalm_base.helpers.mac(mac_address)

            entry = {
               'mac': mac_address,
               'interface1': port,
               'vlan': vlan,
               'active': None,
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
                    "remote": ip,
                    "referenceid": ref,
                    "synchronized": bool(synch),
                    "stratum": int(st),
                    "when": when,
                    "type": None,
                    "poll": int(poll),
                    "reachability": int(reach),
                    "delay": float(delay),
                    "offset": float(offset),
                    "jitter": float(disp)
                })

        return ntp_stats

    def _lldp_detail_parser(self, interface):
        """ Parse a single detailed entry """

        command = "show lldp neighbors detail ports eth {}".format(interface)
        output = self.send_command(command)

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
        lines = self.send_command(command)
        lines = lines.split("\n")

        lines = lines[2:]

        for line in lines:
            fields = line.split()

            if len(fields) == 5:
                local_port, chassis, portid, portdesc, name = fields
                # Systame name may be truncated, so get the complete name from the detailed output
                lldp_detail = self._lldp_detail_parser(local_port)
            
                entry = {
                   'port': lldp_detail[1], 
                   'hostname': lldp_detail[3]
                }
                lldp[local_port] = entry

        return lldp

    def get_lldp_neighbors_detail(self, interface=''):

        lldp = {}
        command = 'show lldp neighbors'
        lines = self.send_command(command)
        lines = lines.split("\n")

        lines = lines[2:]

        for line in lines:
            fields = line.split()

            if len(fields) == 5:
                local_port, chassis, portid, portdesc, name = fields

                lldp_detail = self._lldp_detail_parser(local_port)   
                lldp[local_port] = {
                    'parent_interface': u'N/A',
                    'remote_port': lldp_detail[0],
                    'remote_port_description': lldp_detail[1],
                    'remote_chassis_id': lldp_detail[2],
                    'remote_system_name': lldp_detail[3],
                    'remote_system_description': u'N/A',
                    'remote_system_capab': lldp_detail[4],
                    'remote_system_enabled_capab': lldp_detail[5]
                }
                if local_port == interface:
                    return {interface: lldp[local_port]}

        return lldp

    def get_config(self, retrieve='all'):
        config = {
            'startup': '',
            'running': '',
            'candidate': ''
        }  # default values

        if retrieve.lower() in ('running', 'all'):
            _cmd = 'show running-config'
            config['running'] = self.cli([_cmd]).get(_cmd)
        if retrieve.lower() in ('startup', 'all'):
            _cmd = 'show configuration'
            config['startup'] = self.cli([_cmd]).get(_cmd)
        return config
