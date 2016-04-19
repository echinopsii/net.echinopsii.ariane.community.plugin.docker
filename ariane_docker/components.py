# Ariane Docker plugin
# Docker component
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
import datetime
import json
import logging
#import pprint
import socket
import traceback
from ariane_clip3.domino import DominoReceptor
from ariane_clip3.injector import InjectorComponentSkeleton, InjectorCachedComponent
import time
from ariane_docker.docker import DockerHost

__author__ = 'mffrench'


LOGGER = logging.getLogger(__name__)

class DockerComponent(InjectorComponentSkeleton):

    def __init__(self, attached_gear_id=None, hostname=socket.gethostname(),
                 docker_cli=None, docker_gear_actor_ref=None):
        LOGGER.debug("DockerComponent.__init__")
        self.hostname = hostname
        self.docker_gear_actor_ref = docker_gear_actor_ref
        self.cli = docker_cli
        super(DockerComponent, self).__init__(
            component_id=
            'ariane.community.plugin.docker.components.cache.docker_component@' + self.hostname,
            component_name='docker_component@' + self.hostname,
            component_type="Docker injector",
            component_admin_queue=
            'ariane.community.plugin.docker.components.cache.docker_component@' + self.hostname,
            refreshing=False, next_action=InjectorCachedComponent.action_create,
            json_last_refresh=datetime.datetime.now(),
            attached_gear_id=attached_gear_id
        )
        cached_blob = self.component_cache_actor.blob.get()
        if cached_blob is not None and cached_blob:
            #LOGGER.debug("------------------------------------------------------------------")
            #LOGGER.debug("Cached blob is :\n" + pprint.pformat(cached_blob))
            #LOGGER.debug("------------------------------------------------------------------")
            self.docker_host = DockerHost.from_json(cached_blob)
        else:
            self.docker_host = DockerHost()
            self.docker_host.sniff(self.cli)
        self.version = 0
        self.domino_receptor = None

    def on_start(self):
        LOGGER.debug("DockerComponent.on_start")
        args_driver = {'type': 'Z0MQ'}
        args_receptor = {
            'topic': "domino_directory",
            'treatment_callback': self.sniff_on_procos_event,
            'subscriber_name': "Ariane Docker Plugin Component"
        }
        self.domino_receptor = DominoReceptor(args_driver, args_receptor)

    def on_stop(self):
        LOGGER.debug("DockerComponent.on_stop")
        self.domino_receptor.stop()

    def data_blob(self):
        LOGGER.debug("DockerComponent.data_blob")
        data_blob = self.docker_host.to_json()
        #LOGGER.debug("------------------------------------------------------------------")
        #LOGGER.debug("Cached blob is :\n" + pprint.pformat(data_blob))
        #LOGGER.debug("------------------------------------------------------------------")
        return json.dumps(data_blob)

    def sniff_on_procos_event(self, msg):
        LOGGER.debug("DockerComponent.sniff_on_procos_event")
        LOGGER.debug("DockerComponent.sniff_on_procos_event - Message received : " + msg)
        if self.docker_gear_actor_ref.proxy().is_initialized().get():
            self.sniff()
        else:
            LOGGER.info("DockerComponent.sniff_on_procos_event - ignore component sniff order from ProcOS "
                        "and wait docker ariane initialization...")

    def sniff(self, synchronize_with_ariane_dbs=True):
        try:
            LOGGER.info("DockerComponent.sniff")
            self.cache(refreshing=True, next_action=InjectorCachedComponent.action_update, data_blob=self.data_blob())
            self.docker_host.update(self.cli)
            self.cache(refreshing=False, next_action=InjectorCachedComponent.action_update, data_blob=self.data_blob())
            self.version += 1
            if synchronize_with_ariane_dbs and self.docker_gear_actor_ref is not None:
                self.docker_gear_actor_ref.proxy().synchronize_with_ariane_dbs()
        except Exception as e:
            LOGGER.error(e.__str__())
            LOGGER.error(traceback.format_exc())
