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
import logging
import os
import subprocess
import tempfile
from sys import platform as _platform
from ariane_procos.system import MapSocket
from nsenter import Namespace

__author__ = 'mffrench'

LOGGER = logging.getLogger(__name__)

class DockerImage(object):
    pass

class DockerNetwork(object):
    def __init__(self, nid=None, driver=None, IPAM=None, name=None, bridge_name=None,
                 nic=None, options=None, scope=None, containers_network=None):
        self.nid = nid
        self.driver = driver
        self.IPAM = IPAM
        self.name = name
        self.bridge_name = bridge_name
        self.options = options
        self.scope = scope
        self.containers_network = containers_network
        self.nic = nic

    def __eq__(self, other):
        return self.nid == other.nid

    def to_json(self):
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
        return DockerNetwork(
            nid=json_obj['nid'] if json_obj['nid'] else None,
            driver=json_obj['driver'] if json_obj['driver'] else None,
            IPAM=json_obj['IPAM'] if json_obj['IPAM'] else None,
            name=json_obj['name'] if json_obj['name'] else None,
            bridge_name=json_obj['bridge_name'] if json_obj['bridge_name'] else None,
            nic=json_obj['nic'] if json_obj['nic'] else None,
            options=json_obj['options'] if json_obj['options'] else None,
            scope=json_obj['scope'] if json_obj['scope'] else None,
            containers_network=json_obj['containers_network'] if json_obj['containers_network'] else None
        )

class DockerContainerProcess(object):
    def __init__(self, pid=None, mdpid=None, mospid=None, mcmid=None, cdid=None,
                 map_sockets=None, last_map_sockets=None):
        self.pid = pid

        self.mdpid = mdpid
        self.mospid = mospid
        self.cmid = mcmid
        self.cdid = cdid

        self.map_sockets = map_sockets if map_sockets is not None else []
        self.last_map_sockets = last_map_sockets if last_map_sockets is not None else []
        self.new_map_sockets = []
        self.dead_map_sockets = []

    def __eq__(self, other):
        return self.pid == other.pid

    def to_json(self):
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
            'cmid': self.cmid,
            'cdid': self.cdid,
            'map_sockets': map_socket_2_json,
            'last_map_sockets': last_map_socket_2_json
        }
        return json_obj

    @staticmethod
    def from_json(json_obj):
        map_sockets_json = json_obj['map_sockets'] if json_obj['map_sockets'] else []
        map_sockets = []
        for map_socket_json in map_sockets_json:
            map_sockets.append(MapSocket.to_json(map_socket_json))
            map_sockets_json = json_obj['map_sockets']
        last_map_sockets_json = json_obj['last_map_sockets'] if json_obj['last_map_sockets'] else []
        last_map_sockets = []
        for last_map_socket_json in last_map_sockets_json:
            last_map_sockets.append(MapSocket.to_json(last_map_socket_json))
        return DockerContainerProcess(
            pid=json_obj['pid'] if json_obj['pid'] else None,
            mdpid=json_obj['mdpid'] if json_obj['mdpid'] else None,
            mospid=json_obj['mospid'] if json_obj['modpid'] else None,
            mcmid=json_obj['cmid'] if json_obj['cmid'] else None,
            cdid=json_obj['cdid'] if json_obj['cdid'] else None,
            map_sockets=map_sockets,
            last_map_sockets=last_map_sockets
        )

class DockerContainer(object):
    def __init__(self, dcontainer_id=None, mcontainer_id=None, osi_id=None, environment_id=None, team_id=None,
                 name=None, nsenter_pid=None, details=None, processs=None, last_processs=None):
        #cli.containers()
        #cli.inspect_container(did)
        #cli.top(did)
        #nsenter subprocess 'netstat -i'
        self.did = dcontainer_id
        self.name = name
        self.nsented_pid = nsenter_pid
        self.details = details

        self.mid = mcontainer_id
        self.oid = osi_id
        self.eid = environment_id
        self.tid = team_id

        self.processs = processs if processs is not None else []
        self.last_processs = last_processs if last_processs is not None else []
        self.new_processs = []

    def __eq__(self, other):
        return self.did == other.did

    def to_json(self):
        processs_2_json = []
        for process in self.processs:
            processs_2_json.append(process.to_json())
        last_processs_2_json = []
        for last_process in self.last_processs:
            last_processs_2_json.append(last_process.to_json())
        json_obj = {
            'did': self.did,
            'name': self.name,
            'details': self.details,
            'nsenter_pid': self.nsented_pid,
            'mid': self.mid,
            'oid': self.oid,
            'eid': self.eid,
            'tid': self.tid,
            'processs': processs_2_json,
            'last_processs': last_processs_2_json
        }
        return json_obj

    @staticmethod
    def from_json(json_obj):
        processs_json = json_obj['processs'] if json_obj['processs'] else[]
        processs = []
        for process_json in processs_json:
            processs.append(DockerContainerProcess.from_json(process_json))
        last_processs_json = json_obj['last_processs'] if json_obj['last_processs'] else[]
        last_processs = []
        for last_process_json in last_processs_json:
            last_processs.append(DockerContainerProcess.from_json(last_process_json))
        return DockerContainer(
            dcontainer_id=json_obj['did'] if json_obj['did'] else None,
            mcontainer_id=json_obj['mid'] if json_obj['mid'] else None,
            osi_id=json_obj['oid'] if json_obj['oid'] else None,
            environment_id=json_obj['eid'] if json_obj['eid'] else None,
            team_id=json_obj['tid'] if json_obj['tid'] else None,
            name=json_obj['name'] if json_obj['name'] else None,
            details=json_obj['details'] if json_obj['details'] else None,
            nsenter_pid=json_obj['nsenter_pid'] if json_obj['nsenter_pid'] else None,
            processs=processs,
            last_processs=last_processs
        )

    def netstat(self):
        ret = []
        if os.geteuid() != 0:
            LOGGER.warning("You need to have root privileges to sniff containers namespace.")
        else:
            if _platform == "linux" or _platform == "linux2":
                with Namespace(self.nsented_pid, 'net'):
                    bytes = subprocess.check_output(['netstat', '-a', '-p', '-n'])
                tmpfilename = tempfile.gettempdir() + os.sep + self.did + '.tmp'
                with open(tmpfilename, 'wb') as tmpfile:
                    tmpfile.write(bytes)
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
                        state = fields[5]
                        if state is not 'LISTEN' and state is not 'CLOSE' and state is not 'NONE':
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
                        if protocol is 'tcp' or protocol is 'udp':
                            family = 'AF_INET'
                        else:
                            family = 'AF_INET6'
                        if protocol is 'tcp' or protocol is 'tcp6':
                            type = 'SOCK_STREAM'
                        else:
                            type = 'SOCK_DGRAM'
                        pid = fields[6].split('/')[0]
                        ret.append({
                            'pid': pid,
                            'socket': MapSocket(source_ip=source_ip, source_port=source_port,
                                                destination_ip=target_ip, destination_port=target_port,
                                                status=state, family=family, rtype=type)
                        })
            else:
                LOGGER.warning("Containers namespace sniff enabled on Linux only.")

        return ret

    def update(self, cli):
        self.last_processs = copy.deepcopy(self.processs)
        self.sniff(cli)

    def sniff(self, cli):
        self.processs = []
        self.new_processs = []

        c_netstat =  self.netstat()
        c_top = cli.top(self.did)

        for processTop in c_top['Processes']:
            a_process = DockerContainerProcess(pid=processTop[1])
            for pid_socket in c_netstat:
                if pid_socket['pid'] == a_process.pid:
                    a_process.map_sockets.append(pid_socket['socket'])
            if a_process in self.last_processs:
                pass
            else:
                self.new_processs.append(a_process)
            self.processs.append(a_process)


class DockerHost(object):
    def __init__(self, host_container_id=None, host_osi_id=None, host_environment_id=None, host_team_id=None,
                 hostname=None, info=None, containers=None, last_containers=None, networks=None, last_networks=None):
        self.hostname = hostname
        self.info = info

        self.host_container_id = host_container_id
        self.osi_id = host_osi_id
        self.environment_id = host_environment_id
        self.team_id = host_team_id

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

    def need_directories_refresh(self):
        pass

    def to_json(self):
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
            'hostname': self.hostname,
            'info': self.info,
            'osi_id': self.osi_id,
            'environment_id': self.environment_id,
            'team_id': self.team_id,
            'containers': containers_2_json,
            'last_containers': last_containers_2_json,
            'networks': networks_2_json,
            'last_networks': last_networks_2_json,
        }
        return json_obj

    @staticmethod
    def from_json(json_obj):
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
            host_container_id=json_obj['host_container_id'] if json_obj['host_container_id'] else None,
            host_osi_id=json_obj['host_osi_id'] if json_obj['host_osi_id'] else None,
            host_environment_id=json_obj['host_environment_id'] if json_obj['host_environment_id'] else None,
            host_team_id=json_obj['host_team_id'] if json_obj['host_team_id'] else None,
            hostname=json_obj['hostname'] if json_obj['hostname'] else None,
            info=json_obj['info'] if json_obj['info'] else None,
            containers=containers,
            last_containers=last_containers,
            networks=networks,
            last_networks=last_networks
        )

    def update(self, cli):
        self.last_containers = copy.deepcopy(self.containers)
        self.last_networks = copy.deepcopy(self.networks)
        self.sniff(cli)

    def sniff(self, cli):
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
                nid=network['Id'],
                driver=network['Driver'],
                name=network['Name'],
                IPAM=network['IPAM'],
                options=network['Options'],
                bridge_name=bridge_name,
                scope=network['Scope'],
                containers_network=network['Containers']
            )
            if docker_network in self.last_networks:
                #TODO
                pass
            else:
                self.new_networks.append(docker_network)
            self.networks.append(docker_network)

        for container_dict in cli.containers():
            c_did = container_dict['Id']
            c_inspect = cli.inspect_container(c_did)
            c_name = c_inspect['Name'].split('/')[1]
            c_nsenterpid = c_inspect['State']['Pid']

            docker_container = DockerContainer(dcontainer_id=c_did, name=c_name, nsenter_pid=c_nsenterpid,
                                               details=c_inspect)

            if docker_container in self.last_containers:
                for last_container in self.last_containers:
                    if last_container == docker_container:
                        if last_container.mid is not None:
                            docker_container.mid = last_container.mid
                            docker_container.oid = last_container.oid
                            docker_container.eid = last_container.eid
                            docker_container.tid = last_container.tid
                        else:
                            name = docker_container.did
                            LOGGER.debug('container not saved on DB on previous round: ' + name)
                            self.new_containers.append(docker_container)
                        docker_container.processs = copy.deepcopy(last_container.processs)
                        break

            else:
                self.new_containers.append(docker_container)

            self.containers.append(docker_container)
            docker_container.update(cli)
