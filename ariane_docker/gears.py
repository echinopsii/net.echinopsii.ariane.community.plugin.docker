# Ariane Docker plugin
# Docker gears
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
import socket
import threading
import traceback
from ariane_clip3.directory import OSInstanceService, RoutingAreaService
from ariane_clip3.injector import InjectorGearSkeleton
import time
import sys
from components import DockerComponent

__author__ = 'mffrench'

LOGGER = logging.getLogger(__name__)


class DirectoryGear(InjectorGearSkeleton):
    def __init__(self):
        super(DirectoryGear, self).__init__(
            gear_id='ariane.community.plugin.docker.gears.cache.directory_gear@' + str(DockerHostGear.hostname),
            gear_name='docker_directory_gear@' + str(DockerHostGear.hostname),
            gear_description='Ariane Docker directory gear for ' + str(DockerHostGear.hostname),
            gear_admin_queue='ariane.community.plugin.docker.gears.cache.directory_gear@' +
                             str(DockerHostGear.hostname),
            running=False
        )
        self.update_count = 0

    def on_start(self):
        self.running = True
        self.cache(running=self.running)

    def on_stop(self):
        if self.running:
            self.running = False
            self.cache(running=self.running)

    def gear_start(self):
        LOGGER.warn('docker_directory_gear@' + str(DockerHostGear.hostname) + ' has been started.')
        self.on_start()

    def gear_stop(self):
        if self.running:
            LOGGER.warn('docker_directory_gear@' + str(DockerHostGear.hostname) + ' has been stopped.')
            self.running = False
            self.cache(running=self.running)

    @staticmethod
    def sync_docker_host_osi(cached_docker_host):
        if cached_docker_host.osi_id is not None:
            DockerHostGear.docker_host_osi = OSInstanceService.find_os_instance(osi_id=cached_docker_host.osi_id)
            if DockerHostGear.docker_host_osi.name != DockerHostGear.hostname:
                DockerHostGear.docker_host_osi = None
                cached_docker_host.osi_id = None

        if DockerHostGear.docker_host_osi is None:
            DockerHostGear.docker_host_osi = OSInstanceService.find_os_instance(osi_name=DockerHostGear.hostname)
            if DockerHostGear.docker_host_osi is None:
                LOGGER.error('Docker host ' + str(DockerHostGear.hostname) +
                             ' OS instance not found in Ariane directory')
                LOGGER.error('Did you run Ariane ProcOS on this host first ? Stopping ...')
                sys.exit(-1)
            cached_docker_host.osi_id = DockerHostGear.docker_host_osi.id

    @staticmethod
    def sync_docker_host_lra(cached_docker_host):
        if cached_docker_host.lra_id is not None:
            DockerHostGear.docker_host_lra = RoutingAreaService.find_routing_area(ra_id=cached_docker_host.lra_id)
            if DockerHostGear.docker_host_lra.name != DockerHostGear.hostname + '.local':
                DockerHostGear.docker_host_lra = None
                cached_docker_host.lra_id = None

        if DockerHostGear.docker_host_lra is None:
            DockerHostGear.docker_host_lra = RoutingAreaService.find_routing_area(
                ra_name=DockerHostGear.hostname + '.local'
            )
            if DockerHostGear.docker_host_lra is None:
                LOGGER.error('Docker host ' + str(DockerHostGear.hostname) +
                             ' local routing area not found in Ariane directory')
                LOGGER.error('Did you run Ariane ProcOS on this host first ? Stopping ...')
                sys.exit(-1)
            cached_docker_host.lra_id = DockerHostGear.docker_host_lra.id

    def init_ariane_directories(self, component):
        docker_host = component.docker_host.get()
        self.sync_docker_host_osi(docker_host)
        self.sync_docker_host_lra(docker_host)

    def update_ariane_directories(self, docker_host):
        # insert new container ref on directories
        # insert new networks ref on directories
        pass

    def synchronize_with_ariane_directories(self, component):
        if self.running:
            docker_host = component.docker_host.get()
            self.update_ariane_directories(docker_host)
            self.update_count += 1
        else:
            LOGGER.warn("Synchronization requested but procos_directory_gear@" + str(DockerHostGear.hostname) +
                        " is not running.")


class MappingGear(InjectorGearSkeleton):
    def __init__(self):
        pass

    def on_start(self):
        pass

    def on_stop(self):
        pass

    def gear_start(self):
        pass

    def gear_stop(self):
        pass

    def synchronize_with_ariane_mapping(self, component):
        pass


class DockerHostGear(InjectorGearSkeleton):
    #static reference on commons var
    config = None
    hostname = None

    docker_host_osi = None
    docker_host_lra = None

    def __init__(self, config, cli):
        DockerHostGear.hostname = socket.gethostname()
        DockerHostGear.config = config
        super(DockerHostGear, self).__init__(
            gear_id='ariane.community.plugin.docker.gears.cache.docker_host_gear@'+str(DockerHostGear.hostname),
            gear_name='docker_host_gear@'+str(DockerHostGear.hostname),
            gear_description='Ariane Docker Host gear for '+str(DockerHostGear.hostname),
            gear_admin_queue='ariane.community.plugin.docker.gears.cache.docker_host_gear@'+str(DockerHostGear.hostname),
            running=False
        )
        self.sleeping_period = config.sleeping_period
        self.service = None
        self.service_name = 'docker_host@'+str(DockerHostGear.hostname)+' gear'
        self.component = DockerComponent.start(
            attached_gear_id=self.gear_id(),
            hostname=DockerHostGear.hostname,
            docker_cli=cli,
            docker_gear_actor_ref=self.actor_ref
        ).proxy()
        self.directory_gear = DirectoryGear.start().proxy()
        self.mapping_gear = MappingGear.start().proxy()

    def synchronize_with_ariane_dbs(self):
        LOGGER.info("Synchonize with Ariane DBs...")
        self.directory_gear.synchronize_with_ariane_directories(self.component)
        self.mapping_gear.synchronize_with_ariane_mapping(self.component)

    def run(self):
        if self.sleeping_period is not None and self.sleeping_period > 0:
            while self.running:
                time.sleep(self.sleeping_period)
                if self.running:
                    self.component.sniff().get()

    def on_start(self):
        self.cache(running=self.running)
        LOGGER.warn("Initializing...")
        self.directory_gear.init_ariane_directories(self.component).get()
        self.component.sniff(synchronize_with_ariane_dbs=False).get()
        LOGGER.info("Synchonize with Ariane DBs...")
        self.directory_gear.synchronize_with_ariane_directories(self.component).get()
        self.mapping_gear.synchronize_with_ariane_mapping(self.component).get()
        LOGGER.warn("Initialization done.")
        self.running = True
        self.cache(running=self.running)
        self.service = threading.Thread(target=self.run, name=self.service_name)
        self.service.start()

    def on_stop(self):
        try:
            if self.running:
                self.running = False
                self.cache(running=self.running)
            self.service = None
            self.component.stop().get()
            self.directory_gear.stop().get()
            self.mapping_gear.stop().get()
            self.cached_gear_actor.remove().get()
        except Exception as e:
            LOGGER.error(e.__str__())
            LOGGER.error(traceback.format_exc())

    def gear_start(self):
        if self.service is not None:
            LOGGER.warn('docker_host_gear@'+str(DockerHostGear.hostname)+' has been started')
            self.running = True
            self.service = threading.Thread(target=self.run, name=self.service_name)
            self.service.start()
            self.cache(running=self.running)
        else:
            LOGGER.warn('docker_host_gear@'+str(DockerHostGear.hostname)+' has been restarted')
            self.on_start()

    def gear_stop(self):
        if self.running:
            LOGGER.warn('docker_host_gear@'+str(DockerHostGear.hostname)+' has been stopped')
            self.running = False
            self.cache(running=self.running)
