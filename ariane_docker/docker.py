# Ariane Docker plugin
# Docker tooling from docker-py to Ariane server
#
# Copyright (C) 2016 echinopsii
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import copy
from ipaddress import IPv4Network
import logging
import os
import pprint
import subprocess
import tempfile
from sys import platform as _platform
from ariane_procos.system import MapSocket, NetworkInterfaceCard
from nsenter import Namespace

__author__ = 'mffrench'

LOGGER = logging.getLogger(__name__)


class DockerImage(object):
    pass


class DockerNetwork(object):
    def __init__(self, bridge_name=None, subnet_id=None, subnet=None, nic_id=None, nic=None,
                 nid=None, driver=None, ipam=None, name=None, options=None, scope=None, containers_network=None):
        self.subnet_id = subnet_id
        self.subnet = subnet
        self.nic_id = nic_id
        self.nic = nic

        self.nid = nid
        self.driver = driver
        self.IPAM = ipam
        self.name = name
        self.bridge_name = bridge_name
        self.options = options
        self.scope = scope
        self.containers_network = containers_network

    def __eq__(self, other):
        return self.nid == other.nid

    def to_json(self):
        # LOGGER.debug("DockerNetwork.to_json")
        json_obj = {
            'nid': self.nid,
            'driver': self.driver,
            'IPAM': self.IPAM,
            'name': self.name,
            'bridge_name': self.bridge_name,
            'options': self.options,
            'scope': self.scope,
            'containers_network': self.containers_network
        }
        return json_obj

    @staticmethod
    def from_json(json_obj):
        # LOGGER.debug("DockerNetwork.from_json")
        return DockerNetwork(
            nid=json_obj['nid'] if json_obj['nid'] else None,
            driver=json_obj['driver'] if json_obj['driver'] else None,
            ipam=json_obj['IPAM'] if json_obj['IPAM'] else None,
            name=json_obj['name'] if json_obj['name'] else None,
            bridge_name=json_obj['bridge_name'] if json_obj['bridge_name'] else None,
            options=json_obj['options'] if json_obj['options'] else None,
            scope=json_obj['scope'] if json_obj['scope'] else None,
            containers_network=json_obj['containers_network'] if json_obj['containers_network'] else None
        )


class DockerContainerProcess(object):
    def __init__(self, pid=None, mdpid=None, mdp=None, mospid=None, mosp=None, mcid=None, mc=None,
                 map_sockets=None, last_map_sockets=None):
        self.pid = pid

        self.mdpid = mdpid    # mapping docker process node id
        self.mdp = mdp
        self.mospid = mospid  # mapping os process node id
        self.mosp = mosp
        self.mcid = mcid      # mapping container id (parent)
        self.mc = mc

        self.map_sockets = map_sockets if map_sockets is not None else []
        self.last_map_sockets = last_map_sockets if last_map_sockets is not None else []
        self.new_map_sockets = []

    def __str__(self):
        return "{pid: " + str(self.pid) + " ,mdpid: " + str(self.mdpid) + \
               ", mospid: " + str(self.mospid) + ", mcid: " + str(self.mcid) + "}"

    __repr__ = __str__

    def __eq__(self, other):
        return self.pid == other.pid

    def to_json(self):
        # LOGGER.debug("DockerContainerProcess.to_json")
        map_socket_2_json = []
        for map_socket in self.map_sockets:
            map_socket_2_json.append(map_socket.to_json())
        last_map_socket_2_json = []
        for last_map_socket in self.last_map_sockets:
            last_map_socket_2_json.append(last_map_socket.to_json())
        json_obj = {
            'pid': self.pid,
            'mdpid': self.mdpid,
            'mospid': self.mospid,
            'mcid': self.mcid,
            'map_sockets': map_socket_2_json,
            'last_map_sockets': last_map_socket_2_json
        }
        return json_obj

    @staticmethod
    def from_json(json_obj):
        # LOGGER.debug("DockerContainerProcess.from_json")
        map_sockets_json = json_obj['map_sockets'] if json_obj['map_sockets'] else []
        map_sockets = []
        for map_socket_json in map_sockets_json:
            map_sockets.append(MapSocket.from_json(map_socket_json))
        last_map_sockets_json = json_obj['last_map_sockets'] if json_obj['last_map_sockets'] else []
        last_map_sockets = []
        for last_map_socket_json in last_map_sockets_json:
            last_map_sockets.append(MapSocket.from_json(last_map_socket_json))
        return DockerContainerProcess(
            pid=json_obj['pid'] if json_obj['pid'] else None,
            mdpid=json_obj['mdpid'] if json_obj['mdpid'] else None,
            mospid=json_obj['mospid'] if json_obj['mospid'] else None,
            mcid=json_obj['mcid'] if json_obj['mcid'] else None,
            map_sockets=map_sockets,
            last_map_sockets=last_map_sockets
        )


class DockerContainer(object):

    ariane_ost_name = "ARIANE_OS_TYPE_NAME"
    ariane_ost_arc = "ARIANE_OS_TYPE_ARCHITECTURE"
    ariane_ost_scmp_name = "ARIANE_OS_TYPE_SUPPORTING_COMPANY_NAME"
    ariane_ost_scmp_desc = "ARIANE_OS_TYPE_SUPPORTING_COMPANY_DESCRIPTION"

    ariane_team_name = "ARIANE_TEAM_NAME"
    ariane_team_cc = "ARIANE_TEAM_COLOR_CODE"
    ariane_team_desc = "ARIANE_TEAM_DESCRIPTION"

    ariane_environment_name = "ARIANE_ENV_NAME"
    ariane_environment_cc = "ARIANE_ENV_COLOR_CODE"
    ariane_environment_desc = "ARIANE_ENV_DESCRIPTION"

    docker_props_config_cmd = "docker_cmd"
    docker_props_config_entrypoint = "docker_entrypoint"
    docker_props_config_env = "docker_env"
    docker_props_config_exposed_ports = "docker_exposed_ports"
    docker_props_config_hostname = "docker_hostname"
    docker_props_config_image = "docker_image"
    docker_props_driver = "docker_driver"
    docker_props_host_config_port_binding = "docker_ports_binding"

    def __init__(self, dcontainer_id=None, mcontainer_id=None, mcontainer=None, osi_id=None, osi=None,
                 ost_id=None, ost=None, environment_id=None, environment=None, team_id=None, team=None,
                 name=None, domain=None, fqdn=None, nsenter_pid=None, details=None,
                 processs=None, last_processs=None, last_nics=None, nics=None):
        LOGGER.debug(pprint.pformat(details))
        self.did = dcontainer_id
        self.name = name
        self.domain = domain
        self.fqdn = fqdn
        self.nsented_pid = nsenter_pid
        self.details = details

        self.mid = mcontainer_id
        self.mcontainer = mcontainer
        self.oid = osi_id
        self.osi = osi
        self.ostid = ost_id
        self.ost = ost
        self.eid = environment_id
        self.environment = environment
        self.tid = team_id
        self.team = team

        self.processs = processs if processs is not None else []
        self.last_processs = last_processs if last_processs is not None else []
        self.new_processs = []

        self.last_nics = last_nics if last_nics is not None else []
        self.nics = nics if nics is not None else []

    def __eq__(self, other):
        return self.did == other.did

    def extract_properties(self):
        pass

    def extract_os_type_from_env_vars(self):
        LOGGER.debug("DockerContainer.extract_os_type_from_env_vars")
        ret = None
        if self.details is not None and self.details['Config'] and self.details['Config']['Env']:
            env_vars = self.details['Config']['Env']
            for vars_ in env_vars:
                if vars_.startswith(DockerContainer.ariane_ost_name):
                    if ret is None:
                        ret = {}
                    ret[DockerContainer.ariane_ost_name] = vars_.split('=')[1]
                if vars_.startswith(DockerContainer.ariane_ost_arc):
                    if ret is None:
                        ret = {}
                    ret[DockerContainer.ariane_ost_arc] = vars_.split('=')[1]
                if vars_.startswith(DockerContainer.ariane_ost_scmp_name):
                    if ret is None:
                        ret = {}
                    ret[DockerContainer.ariane_ost_scmp_name] = vars_.split('=')[1]
                if vars_.startswith(DockerContainer.ariane_ost_scmp_desc):
                    if ret is None:
                        ret = {}
                    ret[DockerContainer.ariane_ost_scmp_desc] = vars_.split('=')[1]
        return ret

    def extract_environment_from_env_vars(self):
        LOGGER.debug("DockerContainer.extract_environment_from_env_vars")
        ret = None
        if self.details is not None and self.details['Config'] and self.details['Config']['Env']:
            env_vars = self.details['Config']['Env']
            for vars_ in env_vars:
                if vars_.startswith(DockerContainer.ariane_environment_name):
                    if ret is None:
                        ret = {}
                    ret[DockerContainer.ariane_environment_name] = vars_.split('=')[1]
                if vars_.startswith(DockerContainer.ariane_environment_cc):
                    if ret is None:
                        ret = {}
                    ret[DockerContainer.ariane_environment_cc] = vars_.split('=')[1]
                if vars_.startswith(DockerContainer.ariane_environment_desc):
                    if ret is None:
                        ret = {}
                    ret[DockerContainer.ariane_environment_desc] = vars_.split('=')[1]
        return ret

    def extract_team_from_env_vars(self):
        LOGGER.debug("DockerContainer.extract_team_from_env_vars")
        ret = None
        if self.details is not None and self.details['Config'] and self.details['Config']['Env']:
            env_vars = self.details['Config']['Env']
            for vars_ in env_vars:
                if vars_.startswith(DockerContainer.ariane_team_name):
                    if ret is None:
                        ret = {}
                    ret[DockerContainer.ariane_team_name] = vars_.split('=')[1]
                if vars_.startswith(DockerContainer.ariane_team_cc):
                    if ret is None:
                        ret = {}
                    ret[DockerContainer.ariane_team_cc] = vars_.split('=')[1]
                if vars_.startswith(DockerContainer.ariane_team_desc):
                    if ret is None:
                        ret = {}
                    ret[DockerContainer.ariane_team_desc] = vars_.split('=')[1]
        return ret

    def to_json(self):
        # LOGGER.debug("DockerContainer.to_json")
        processs_2_json = []
        for process in self.processs:
            processs_2_json.append(process.to_json())
        last_processs_2_json = []
        for last_process in self.last_processs:
            last_processs_2_json.append(last_process.to_json())
        nics_2_json = []
        for nic in self.nics:
            nics_2_json.append(nic.to_json())
        last_nics_2_json = []
        for last_nic in self.last_nics:
            last_nics_2_json.append(last_nic.to_json())
        json_obj = {
            'did': self.did,
            'name': self.name,
            'domain': self.domain,
            'fqdn': self.fqdn,
            'details': self.details,
            'nsenter_pid': self.nsented_pid,
            'mid': self.mid,
            'oid': self.oid,
            'ostid': self.ostid,
            'eid': self.eid,
            'tid': self.tid,
            'processs': processs_2_json,
            'last_processs': last_processs_2_json,
            'nics': nics_2_json,
            'last_nics': last_nics_2_json
        }
        return json_obj

    @staticmethod
    def from_json(json_obj):
        # LOGGER.debug("DockerContainer.from_json")
        processs_json = json_obj['processs'] if json_obj['processs'] else []
        processs = []
        for process_json in processs_json:
            processs.append(DockerContainerProcess.from_json(process_json))
        last_processs_json = json_obj['last_processs'] if json_obj['last_processs'] else []
        last_processs = []
        for last_process_json in last_processs_json:
            last_processs.append(DockerContainerProcess.from_json(last_process_json))
        nics_json = json_obj['nics'] if json_obj['nics'] else []
        nics = []
        for nic_json in nics_json:
            nics.append(NetworkInterfaceCard.from_json(nic_json))
        last_nics_json = json_obj['last_nics'] if json_obj['last_nics'] else []
        last_nics = []
        for last_nic_json in last_nics_json:
            last_nics.append(NetworkInterfaceCard.from_json(last_nic_json))
        return DockerContainer(
            dcontainer_id=json_obj['did'] if json_obj['did'] else None,
            mcontainer_id=json_obj['mid'] if json_obj['mid'] else None,
            osi_id=json_obj['oid'] if json_obj['oid'] else None,
            ost_id=json_obj['ostid'] if json_obj['ostid'] else None,
            environment_id=json_obj['eid'] if json_obj['eid'] else None,
            team_id=json_obj['tid'] if json_obj['tid'] else None,
            name=json_obj['name'] if json_obj['name'] else None,
            domain=json_obj['domain'] if json_obj['domain'] else None,
            fqdn=json_obj['fqdn'] if json_obj['fqdn'] else None,
            details=json_obj['details'] if json_obj['details'] else None,
            nsenter_pid=json_obj['nsenter_pid'] if json_obj['nsenter_pid'] else None,
            processs=processs,
            last_processs=last_processs,
            nics=nics,
            last_nics=last_nics
        )

    def ethtool(self, iptable_nic):
        LOGGER.debug("DockerContainer.ethtool")
        if os.getuid() != 0:
            LOGGER.warning("You need to have root privileges to sniff containers namespace.")
        elif iptable_nic is None or 'name' not in iptable_nic or iptable_nic['name'] is None:
            LOGGER.error("nic name not provided on ethtool input.")
        else:
            if _platform == "linux" or _platform == "linux2":
                with Namespace(self.nsented_pid, 'net'):
                    bytes_ = subprocess.check_output(['ethtool', iptable_nic['name']])
                tmpfilename = tempfile.gettempdir() + os.sep + self.did + '.tmp'
                with open(tmpfilename, 'wb') as tmpfile:
                    tmpfile.write(bytes_)
                    tmpfile.close()
                with open(tmpfilename, 'r') as tmpfile:
                    text = tmpfile.readlines()
                    tmpfile.close()
                os.remove(tmpfilename)
            for line in text:
                if "Duplex" in line:
                    iptable_nic['duplex'] = line.split('Duplex: ')[1].replace('\n', '')
                elif "Speed" in line:
                    iptable_nic['speed'] = line.split('Speed: ')[1].split('Mb/s')[0]
        return iptable_nic

    def ipaddr(self):
        LOGGER.debug("DockerContainer.ipaddr")
        ret = []
        if os.getuid() != 0:
            LOGGER.warning("You need to have root privileges to sniff containers namespace.")
        else:
            text = None
            if _platform == "linux" or _platform == "linux2":
                with Namespace(self.nsented_pid, 'net'):
                    bytes_ = subprocess.check_output(['ip', 'addr', 'show'])
                tmpfilename = tempfile.gettempdir() + os.sep + self.did + '.tmp'
                with open(tmpfilename, 'wb') as tmpfile:
                    tmpfile.write(bytes_)
                    tmpfile.close()
                with open(tmpfilename, 'r') as tmpfile:
                    text = tmpfile.readlines()
                    tmpfile.close()
                os.remove(tmpfilename)

            current_card = None
            if text is not None:
                for line in text:
                    if ": <" in line and ("UP" in line or "UNKNOWN" in line):
                        card_name = line.split(":")[1].split(": <")[0].replace(' ', '')
                        if '@' in card_name:
                            card_name = card_name.split('@')[0]
                        if current_card is None:
                            current_card = {'name': card_name}
                        else:
                            ret.append(current_card)
                            current_card = {'name': card_name}
                        if "MULTICAST" in line:
                            current_card['multicast'] = True
                        else:
                            current_card['multicast'] = False
                        if "mtu" in line:
                            current_card['mtu'] = line.split("mtu")[1].split(" ")[1]

                    if "inet " in line and current_card is not None:
                        current_card['ipv4_addr'] = line.split("inet ")[1].split("/")[0]
                        z_bytes = 32 - int(line.split("/")[1].split(" ")[0])
                        if z_bytes < 8:
                            mask = "255.255.255." + str(256 - (1 << z_bytes))
                        elif z_bytes < 16:
                            mask = "255.255." + str(256 - int(1 << z_bytes - 8)) + ".0"
                        elif z_bytes < 24:
                            mask = "255." + str(256 - (1 << z_bytes - 16)) + ".0.0"
                        else:
                            mask = str(256 - (1 << z_bytes - 24)) + ".0.0.0"
                        current_card['ipv4_mask'] = mask

                    if "link" in line and "brd" in line:
                        current_card['mac_addr'] = line.split("brd")[0].split("link")[1].split(" ")[1]
                ret.append(current_card)
            return ret

    def netstat(self):
        LOGGER.debug("DockerContainer.netstat")
        ret = []
        if os.geteuid() != 0:
            LOGGER.warning("You need to have root privileges to sniff containers namespace.")
        else:
            if _platform == "linux" or _platform == "linux2":
                with Namespace(self.nsented_pid, 'net'):
                    bytes_ = subprocess.check_output(['netstat', '-a', '-p', '-n'])
                tmpfilename = tempfile.gettempdir() + os.sep + self.did + '.tmp'
                with open(tmpfilename, 'wb') as tmpfile:
                    tmpfile.write(bytes_)
                    tmpfile.close()
                with open(tmpfilename, 'r') as tmpfile:
                    text = tmpfile.readlines()
                    tmpfile.close()
                os.remove(tmpfilename)

                for line in text:
                    if line.startswith('tcp') or line.startswith('tcp6') or \
                       line.startswith('udp') or line.startswith('udp6'):
                        fields = line.strip().split()
                        protocol = fields[0]
                        source_ep = fields[3]
                        if protocol is 'tcp' or protocol is 'udp':
                            source_ip = source_ep.split(':')[0]
                            source_port = source_ep.split(':')[1]
                        else:
                            split = source_ep.split(':')
                            split_array_length = split.__len__()
                            source_port = split[split_array_length-1]
                            source_ip = source_ep.split(':'+source_port)[0]

                        if fields.__len__() > 6:
                            state = fields[5]
                            pid = fields[6].split('/')[0]
                        else:
                            state = 'NONE'
                            pid = fields[5].split('/')[0]

                        if state != 'LISTEN' and state != 'CLOSE' and state != 'NONE':
                            target_ep = fields[4]
                            if protocol is 'tcp' or protocol is 'udp':
                                target_ip = target_ep.split(':')[0]
                                target_port = target_ep.split(':')[1]
                            else:
                                split = target_ep.split(':')
                                split_array_length = split.__len__()
                                target_port = split[split_array_length-1]
                                target_ip = target_ep.split(':'+target_port)[0]
                        else:
                            target_ip = None
                            target_port = None

                        if protocol == 'tcp' or protocol == 'udp':
                            family = 'AF_INET'
                        else:
                            family = 'AF_INET6'

                        if protocol == 'tcp' or protocol == 'tcp6':
                            type_ = 'SOCK_STREAM'
                        else:
                            type_ = 'SOCK_DGRAM'

                        ret.append({
                            'pid': pid,
                            'socket': MapSocket(source_ip=source_ip, source_port=source_port,
                                                destination_ip=target_ip, destination_port=target_port,
                                                status=state, family=family, rtype=type_)
                        })
            else:
                LOGGER.warning("Containers namespace sniff enabled on Linux only.")
        return ret

    def is_in_container_destination(self, mapping_socket):
        destination_in_container = False
        if mapping_socket.family == "AF_INET6":
            for nic in self.nics:
                if nic.ipv6_address == mapping_socket.destination_ip:
                    destination_in_container = True
                    break
        if not destination_in_container:
            for nic in self.nics:
                if nic.ipv4_address == mapping_socket.destination_ip:
                    destination_in_container = True
                    break
        return destination_in_container

    def is_local_destination(self, mapping_socket):
        destination_is_local = False
        if mapping_socket.destination_ip is not None and mapping_socket.family == "AF_INET":
            for nic in self.nics:
                if NetworkInterfaceCard.ip_is_in_subnet(mapping_socket.destination_ip,
                                                        nic.ipv4_subnet_addr, nic.ipv4_subnet_mask):
                    destination_is_local = True
                    break
        elif mapping_socket.destination_ip is not None and mapping_socket.family == "AF_INET6":
            destination_ipv4 = MapSocket.ipv6_2_ipv4(mapping_socket.destination_ip)
            if destination_ipv4 != mapping_socket.destination_ip:
                for nic in self.nics:
                    if NetworkInterfaceCard.ip_is_in_subnet(destination_ipv4,
                                                            nic.ipv4_subnet_addr, nic.ipv4_subnet_mask):
                        destination_is_local = True
                        break
            else:
                # TODO: check is ipv6 in subnet ?
                for nic in self.nics:
                    if nic.ipv6_address is not None and mapping_socket.destination_ip == nic.ipv6_address:
                        destination_is_local = True
                        break
                    elif NetworkInterfaceCard.ip_is_in_subnet(mapping_socket.destination_ip,
                                                              nic.ipv4_subnet_addr, nic.ipv4_subnet_mask):
                        destination_is_local = True
                        break
        elif mapping_socket.family == "AF_UNIX":
            destination_is_local = True

        return destination_is_local

    def update(self, cli):
        LOGGER.debug("DockerContainer.update")
        self.last_processs = copy.deepcopy(self.processs)
        self.last_nics = copy.deepcopy(self.nics)
        self.sniff(cli)
        LOGGER.debug("DockerContainer.update - last_processs: " + str(self.last_processs))
        LOGGER.debug("DockerContainer.update - processs: " + str(self.processs))

    def sniff(self, cli):
        LOGGER.debug("DockerContainer.sniff")
        self.processs = []
        self.new_processs = []
        self.nics = []

        c_netstat = self.netstat()
        c_ipnics = []
        for ipaddr in self.ipaddr():
            LOGGER.debug(str(ipaddr))
            c_ipnics.append(self.ethtool(ipaddr))
        c_top = cli.top(self.did)
        top_processes = c_top['Processes'] if 'Processes' in c_top and c_top['Processes'] is not None else []

        if top_processes is None or top_processes.__len__() == 0:
            # TODO: seems to be a docker python cli bug here
            top_processes = []
            LOGGER.warning("No process found for container [" + self.did + "]" + self.name + " !?")
            LOGGER.warning(pprint.pformat(c_top))

        for processTop in top_processes:
            a_process = DockerContainerProcess(pid=processTop[1])
            if a_process in self.last_processs:
                for last_process in self.last_processs:
                    if last_process == a_process:
                        if last_process.mdpid is not None:
                            a_process.mdpid = last_process.mdpid
                        if last_process.mospid is not None:
                            a_process.mospid = last_process.mospid
                        if last_process.mcid is not None:
                            a_process.mcid = last_process.mcid
                        a_process.last_map_sockets = copy.deepcopy(last_process.map_sockets)
            else:
                self.new_processs.append(a_process)
            self.processs.append(a_process)

            for pid_socket in c_netstat:
                if pid_socket['pid'] == a_process.pid:
                    proc_sock = pid_socket['socket']
                    a_process.map_sockets.append(proc_sock)
                    if proc_sock not in a_process.last_map_sockets:
                        a_process.new_map_sockets.append(proc_sock)

            for map_socket in a_process.last_map_sockets:
                if map_socket not in a_process.new_map_sockets and \
                   map_socket.destination_node_id is None and \
                   map_socket.destination_ip is not None and map_socket.destination_port is not None:
                    LOGGER.debug('Will complete following map_socket this round : ' + map_socket.source_ip + ":" +
                                 str(map_socket.source_port))
                    a_process.new_map_sockets.append(map_socket)

        for ip_nic in c_ipnics:
            if 'ipv4_addr' in ip_nic and 'ipv4_mask' in ip_nic:
                ipv4_snet_address = \
                    str(IPv4Network(ip_nic['ipv4_addr'] + '/' + ip_nic['ipv4_mask'], strict=False).network_address)
            if self.fqdn is None:
                if 'Config' in self.details:
                    self.fqdn = self.details['Config']['Hostname'] + '.' + self.domain
                else:
                    self.fqdn = self.name + '.' + self.domain

            nic = NetworkInterfaceCard(
                name=ip_nic['name'] if 'name' in ip_nic else '',
                ipv4_address=ip_nic['ipv4_addr'] if 'ipv4_addr' in ip_nic else '',
                ipv4_fqdn=ip_nic['name'] + '.' + self.fqdn if 'name' in ip_nic else self.fqdn,
                ipv4_subnet_addr=ipv4_snet_address if ipv4_snet_address is not None else '',
                ipv4_subnet_mask=ip_nic['ipv4_mask'] if 'ipv4_mask' in ip_nic else '',
                mtu=ip_nic['mtu'] if 'mtu' in ip_nic else '',
                mac_address=ip_nic['mac_addr'] if 'mac_addr' in ip_nic else '',
                duplex=ip_nic['duplex'].upper() if 'duplex' in ip_nic else '',
                speed=ip_nic['speed'] if 'speed' in ip_nic else ''
            )
            self.nics.append(nic)


class DockerHost(object):
    def __init__(self, host_container_id=None, host_osi_id=None, host_lra_id=None,
                 hostname=None, info=None, containers=None, last_containers=None,
                 networks=None, last_networks=None):
        self.hostname = hostname
        self.info = info

        self.host_container_id = host_container_id
        self.osi_id = host_osi_id
        self.lra_id = host_lra_id

        self.containers = containers if containers is not None else []
        self.last_containers = last_containers if last_containers is not None else []
        self.new_containers = []

        self.networks = networks if networks is not None else []
        self.last_networks = last_networks if last_networks is not None else []
        self.new_networks = []

    def __eq__(self, other):
        return self.hostname == other.hostname

    def __str__(self):
        return 'docker@' + self.hostname

    __repr__ = __str__

    def need_directories_refresh(self):
        pass

    def to_json(self):
        # LOGGER.debug("DockerHost.to_json")
        containers_2_json = []
        for container in self.containers:
            containers_2_json.append(container.to_json())
        last_containers_2_json = []
        for last_container in self.last_containers:
            last_containers_2_json.append(last_container.to_json())
        networks_2_json = []
        for network in self.networks:
            networks_2_json.append(network.to_json())
        last_networks_2_json = []
        for last_network in self.last_networks:
            last_networks_2_json.append(last_network.to_json())
        json_obj = {
            'host_container_id': self.host_container_id,
            'host_osi_id': self.osi_id,
            'host_lra_id': self.lra_id,
            'hostname': self.hostname,
            'info': self.info,
            'osi_id': self.osi_id,
            'lra_id': self.lra_id,
            'containers': containers_2_json,
            'last_containers': last_containers_2_json,
            'networks': networks_2_json,
            'last_networks': last_networks_2_json,
        }
        return json_obj

    @staticmethod
    def from_json(json_obj):
        # LOGGER.debug("DockerHost.from_json")
        containers_json = json_obj['containers'] if json_obj['containers'] else []
        containers = []
        for container_json in containers_json:
            containers.append(DockerContainer.from_json(container_json))
        last_containers_json = json_obj['last_containers'] if json_obj['last_containers'] else []
        last_containers = []
        for last_container_json in last_containers_json:
            last_containers.append(DockerContainer.from_json(last_container_json))

        networks_json = json_obj['networks'] if json_obj['networks'] else []
        networks = []
        for network_json in networks_json:
            networks.append(DockerNetwork.from_json(network_json))
        last_networks_json = json_obj['last_networks'] if json_obj['last_networks'] else []
        last_networks = []
        for last_network_json in last_networks_json:
            last_networks.append(DockerNetwork.from_json(last_network_json))

        return DockerHost(
            host_container_id=json_obj['host_container_id'] if 'host_container_id' in json_obj and json_obj['host_container_id'] else None,
            host_osi_id=json_obj['host_osi_id'] if 'host_osi_id' in json_obj and json_obj['host_osi_id'] else None,
            host_lra_id=json_obj['host_lra_id'] if 'host_lra_id' in json_obj and json_obj['host_lra_id'] else None,
            hostname=json_obj['hostname'] if 'hostname' in json_obj and json_obj['hostname'] else None,
            info=json_obj['info'] if 'info' in json_obj and json_obj['info'] else None,
            containers=containers,
            last_containers=last_containers,
            networks=networks,
            last_networks=last_networks
        )

    def update(self, cli):
        LOGGER.debug("DockerHost.update")
        self.last_containers = copy.deepcopy(self.containers)
        self.last_networks = copy.deepcopy(self.networks)
        self.sniff(cli)

    def sniff(self, cli):
        LOGGER.debug("DockerHost.sniff")
        self.containers = []
        self.networks = []
        self.new_containers = []
        self.new_networks = []

        if self.info is None:
            self.info = cli.info()
            self.hostname = self.info['Name']

        for network in cli.networks():
            bridge_name = \
                network['Options']['com.docker.network.bridge.name'] if 'com.docker.network.bridge.name' in network['Options'] is not None else None

            docker_network = DockerNetwork(
                bridge_name=bridge_name,
                nid=network['Id'],
                driver=network['Driver'],
                name=network['Name'],
                ipam=network['IPAM'],
                options=network['Options'],
                scope=network['Scope'],
                containers_network=network['Containers']
            )
            if docker_network in self.last_networks:
                for last_network in self.last_networks:
                    if last_network == docker_network:
                        if last_network.subnet_id is not None:
                            docker_network.subnet_id = last_network.subnet_id
                        if last_network.nic_id is not None:
                            docker_network.nic_id = last_network.nic_id
            else:
                self.new_networks.append(docker_network)
            self.networks.append(docker_network)

        for container_dict in cli.containers():
            c_did = container_dict['Id']
            c_inspect = cli.inspect_container(c_did)
            c_name = c_inspect['Name'].split('/')[1]
            c_nsenterpid = c_inspect['State']['Pid']

            docker_container = DockerContainer(dcontainer_id=c_did, name=c_name, domain=self.hostname,
                                               nsenter_pid=c_nsenterpid, details=c_inspect)

            if docker_container in self.last_containers:
                for last_container in self.last_containers:
                    if last_container == docker_container:
                        if last_container.mid is not None:
                            docker_container.mid = last_container.mid
                        if last_container.eid is not None:
                            docker_container.eid = last_container.eid
                        if last_container.tid is not None:
                            docker_container.tid = last_container.tid
                        if last_container.oid is not None:
                            docker_container.oid = last_container.oid
                        else:
                            name = docker_container.name
                            LOGGER.debug('container not saved on DB on previous round: ' + name)
                            self.new_containers.append(docker_container)
                        docker_container.processs = copy.deepcopy(last_container.processs)
                        break

            else:
                self.new_containers.append(docker_container)

            self.containers.append(docker_container)
            docker_container.update(cli)
