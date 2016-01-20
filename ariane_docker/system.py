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

__author__ = 'mffrench'

LOGGER = logging.getLogger(__name__)

class DockerContainerNSenter(object):
    def __init__(self):
        pass

    def netstat(self):
        #parse function here
        pass

class DockerImage(object):
    pass

class DockerNetwork(object):
    def __init__(self, nid=None, driver=None, IPAM=None, name=None, options=None, scope=None,
                 containers_network=None):
        self.nid = nid
        self.driver = driver
        self.IPAM = IPAM
        self.name = name
        self.options = options
        self.scope = scope
        self.containers_network=containers_network

class DockerContainerProcess(object):
    def __init__(self, pid=None, mdpid=None, mospid=None, mcmid=None, cdid=None):
        self.pid = pid
        self.mdpid = mdpid
        self.mospid = mospid
        self.cmid = mcmid
        self.cdid = cdid

class DockerContainer(object):
    def __init__(self, dcontainer_id=None, mcontainer_id=None, osi_id=None, environment_id=None, team_id=None,
                 nsenter_pid=None, details=None, top=None):
        #cli.containers()
        #cli.inspect_container(did)
        #cli.top(did)
        #nsenter subprocess 'netstat -i'
        self.did = dcontainer_id
        self.nsented_pid = nsenter_pid
        self.details = details
        self.top = top

        self.mid = mcontainer_id
        self.oid = osi_id
        self.eid = environment_id
        self.tid = team_id

    def __eq__(self, other):
        return self.did == other.did

class DockerHost(object):
    def __init__(self, docker_cli,
                 host_container_id=None, host_osi_id=None, host_environment_id=None, host_team_id=None,
                 hostname=None, info=None, containers=None, last_containers=None, networks=None, last_networks=None):
        self.cli = docker_cli
        self.host_container_id = host_container_id
        self.hostname = hostname
        self.info = info

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

    def docker_host_2_json(self):
        pass

    @staticmethod
    def json_2_docker_host(json_obj):
        pass

    def update(self):
        self.last_containers = copy.deepcopy(self.containers)
        self.last_networks = copy.deepcopy(self.networks)
        self.sniff()

    def sniff(self):
        self.containers = []
        self.networks = []
        self.new_containers = []
        self.new_networks = []

        if self.info is None:
            self.info = self.cli.info()
            self.hostname = self.info['Name']

        for container_dict in self.cli.containers():
            c_did = container_dict['Id']
            c_inspect = self.cli.inspect_container(c_did)
            c_top = self.cli.top(c_did)
            c_nsenterpid = c_inspect['State']['Pid']
            pass

