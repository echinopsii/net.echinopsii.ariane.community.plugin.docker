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
                 details=None, top=None):
        #cli.containers()
        #cli.inspect_container(did)
        #cli.top(did)
        #nsenter subprocess 'netstat -i'
        self.did = dcontainer_id
        self.mid = mcontainer_id
        self.oid = osi_id
        self.eid = environment_id
        self.tid = team_id
        self.details = None
        self.top = None

class DockerHost(object):
    def __init__(self, host_container_id=None, host_osi_id=None, host_environment_id=None, host_team_id=None,
                 hostname=None):
        self.host_container_id = host_container_id
        self.osi_id = host_osi_id
        self.environment_id = host_environment_id
        self.team_id = host_team_id
        self.hostname = hostname if hostname is not None else "" #TODO cli.info().Name

    def __eq__(self, other):
        pass

    def __str__(self):
        pass

    def need_directories_refresh(self):
        pass

    def docker_host_2_json(self):
        pass

    @staticmethod
    def json_2_docker_host(json_obj):
        pass

    def update(self):
        pass

    def sniff(self):
        pass
