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
from ariane_clip3.injector import InjectorGearSkeleton
from components import DockerComponent

__author__ = 'mffrench'

LOGGER = logging.getLogger(__name__)


class DirectoryGear(InjectorGearSkeleton):
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

    def init_ariane_directories(self, component):
        pass

    def update_ariane_directories(self, docker):
        pass

    def synchronize_with_ariane_directories(self, component):
        pass


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


class DockerGear(InjectorGearSkeleton):
    #static reference on commons var
    config = None
    hostname = None

    def __init__(self, config):
        DockerGear.hostname = socket.gethostname()
        DockerGear.config = config
        super(DockerGear, self).__init__(
            gear_id='ariane.community.plugin.docker.gears.cache.docker_gear@'+str(DockerGear.hostname),
            gear_name='docker_gear@'+str(DockerGear.hostname),
            gear_description='Ariane Docker gear for '+str(DockerGear.hostname),
            gear_admin_queue='ariane.community.plugin.docker.gears.cache.docker_gear@'+str(DockerGear.hostname),
            running=False
        )
        self.sleeping_period = config.sleeping_period
        self.service = None
        self.service_name = 'docker@'+str(DockerGear.hostname)+' gear'
        self.component = DockerComponent.start(
            attached_gear_id=self.gear_id(),
            hostname=DockerGear.hostname,
            docker_gear_actor_ref=self.actor_ref
        ).proxy()
        self.directory_gear = DirectoryGear.start().proxy()
        self.mapping_gear = MappingGear.start().proxy()

    def run(self):
        pass

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
            LOGGER.warn('docker_gear@'+str(DockerGear.hostname)+' has been started')
            self.running = True
            self.service = threading.Thread(target=self.run, name=self.service_name)
            self.service.start()
            self.cache(running=self.running)
        else:
            LOGGER.warn('docker_gear@'+str(DockerGear.hostname)+' has been restarted')
            self.on_start()

    def gear_stop(self):
        if self.running:
            LOGGER.warn('docker_gear@'+str(DockerGear.hostname)+' has been stopped')
            self.running = False
            self.cache(running=self.running)
