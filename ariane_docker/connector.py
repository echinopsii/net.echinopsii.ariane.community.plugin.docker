# Ariane Docker plugin
# Connectors to Ariane server and Docker Daemon
#
# Copyright (C) 2015 echinopsii
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
import os
import socket
import traceback
from ariane_clip3.driver_factory import DriverFactory
from docker import Client
from ariane_clip3.injector import InjectorService, InjectorUITreeEntity, InjectorUITreeService, \
    InjectorCachedComponentService, InjectorCachedGearService
from ariane_clip3.mapping import MappingService, ContainerService, SessionService
from ariane_clip3.directory import DirectoryService, LocationService

__author__ = 'mffrench'

LOGGER = logging.getLogger(__name__)


class DockerConnector(object):

    def __init__(self, docker_config):
        self.ready = False
        self.cli = Client(base_url=docker_config.docker_client_url)
        no_error = True
        try:
            self.cli.info()
        except Exception as e:
            LOGGER.error("Problem while initializing docker connector on following url : " +
                         docker_config.docker_client_url)
            LOGGER.error(e.__str__())
            no_error = False

        if no_error:
            self.ready = True


class ArianeConnector(object):

    def __init__(self, docker_config):
        self.ready = False
        rest_args = {
            'type': 'REST',
            'base_url': docker_config.rest_base_url,
            'user': docker_config.rest_user,
            'password': docker_config.rest_password
        }
        client_properties = {
            'product': 'Ariane',
            'information': 'Ariane Plugin Docker - Map your Docker containers interaction and more ...',
            'ariane.pgurl': 'ssh://' + socket.gethostname() + "/$[/usr/local/bin/adocker {start|stop}]",
            'ariane.osi': socket.gethostname(),
            'ariane.otm': 'AROps',
            'ariane.app': 'Ariane Plugin Docker',
            'ariane.cmp': 'echinopsii',
            'ariane.pid':  os.getpid()
        }
        nats_args = {
            'type': DriverFactory.DRIVER_NATS,
            'user': docker_config.nats_user,
            'password': docker_config.nats_password,
            'host': docker_config.nats_host,
            'port': docker_config.nats_port,
            'rpc_timeout': docker_config.rpc_timeout,
            'rpc_retry': docker_config.rpc_retry,
            'client_properties': client_properties
        }
        rbmq_args = {
            'type': 'RBMQ',
            'user': docker_config.rbmq_user,
            'password': docker_config.rbmq_password,
            'host': docker_config.rbmq_host,
            'port': docker_config.rbmq_port,
            'vhost': docker_config.rbmq_vhost,
            'rpc_timeout': docker_config.rpc_timeout,
            'rpc_retry': docker_config.rpc_retry,
            'client_properties': client_properties
        }
        self.gears_registry_cache_id = 'ariane.community.plugin.docker.gears.cache'
        docker_gears_registry_conf = {
            'registry.name': 'Ariane Docker Plugin Gears Registry',
            'registry.cache.id': self.gears_registry_cache_id,
            'registry.cache.name': 'Ariane Docker Plugin Gears Cache',
            'cache.mgr.name': 'ARIANE_PLUGIN_DOCKER_GEARS_CACHE_MGR'
        }
        self.components_registry_cache_id = 'ariane.community.plugin.docker.components.cache'
        docker_components_registry_conf = {
            'registry.name': 'Ariane Docker Plugin Components Registry',
            'registry.cache.id': self.components_registry_cache_id,
            'registry.cache.name': 'Ariane Docker Plugin Components Cache',
            'cache.mgr.name': 'ARIANE_PLUGIN_DOCKER_COMPONENTS_CACHE_MGR'
        }

        no_error = True
        DirectoryService(rest_args)
        # Test Directory Service
        try:
            LocationService.get_locations()
        except Exception as e:
            LOGGER.error("Problem while initializing Ariane directory service.")
            LOGGER.error(e.__str__())
            no_error = False

        if no_error:
            if docker_config.mapping_driver_type == DriverFactory.DRIVER_RBMQ:
                LOGGER.info("Starting Mapping Service through RabbitMQ")
                MappingService(rbmq_args)
            elif docker_config.mapping_driver_type == DriverFactory.DRIVER_NATS:
                LOGGER.info("Starting Mapping Service through NATS")
                MappingService(nats_args)
            else:
                LOGGER.info("Starting Mapping Service through REST")
                MappingService(rest_args)
            # Open session and Test Mapping Service
            try:
                SessionService.open_session("ArianeDocker_test" + socket.gethostname())
                SessionService.close_session()
            except Exception as e:
                LOGGER.error("Problem while initializing Ariane mapping service.")
                LOGGER.error(e.__str__())
                no_error = False

        if no_error:
            try:
                if docker_config.injector_driver_type == DriverFactory.DRIVER_RBMQ:
                    LOGGER.info("Starting Injector Service through RabbitMQ")
                    self.injector_service = InjectorService(
                        driver_args=rbmq_args, gears_registry_args=docker_gears_registry_conf,
                        components_registry_args=docker_components_registry_conf
                    )
                elif docker_config.injector_driver_type == DriverFactory.DRIVER_NATS:
                    LOGGER.info("Starting Injector Service through NATS")
                    self.injector_service = InjectorService(
                        driver_args=nats_args, gears_registry_args=docker_gears_registry_conf,
                        components_registry_args=docker_components_registry_conf
                    )
            except Exception as e:
                LOGGER.error("Problem while initializing Ariane injector service.")
                LOGGER.error(e.__str__())
                no_error = False

        if no_error:
            # Register UI entity if needed (and so test)
            self.injector_ui_mapping_entity = InjectorUITreeService.find_ui_tree_entity('mappingDir')
            if self.injector_ui_mapping_entity is None:
                self.injector_ui_mapping_entity = InjectorUITreeEntity(uitid="mappingDir", value="Mapping",
                                                                       uitype=InjectorUITreeEntity.entity_dir_type)
                self.injector_ui_mapping_entity.save()
            self.injector_ui_system_entity = InjectorUITreeEntity(uitid="systemDir", value="System",
                                                                  uitype=InjectorUITreeEntity.entity_dir_type,
                                                                  context_address="", description="",
                                                                  parent_id=self.injector_ui_mapping_entity.id,
                                                                  display_roles=["sysreviewer"],
                                                                  display_permissions=["injMapSysDocker:display"])
            self.injector_ui_system_entity.save()
            self.injector_ui_procos_entity = InjectorUITreeEntity(uitid="docker", value="Docker",
                                                                  uitype=InjectorUITreeEntity.entity_leaf_type,
                                                                  context_address=
                                                                  "/ariane/views/injectors/external.jsf?id=docker",
                                                                  description="Docker injector", icon="icon-docker-injector",
                                                                  parent_id=self.injector_ui_system_entity.id,
                                                                  display_roles=["sysadmin", "sysreviewer"],
                                                                  display_permissions=["injMapSysDocker:display"],
                                                                  other_actions_roles={"action": ["sysadmin"]},
                                                                  other_actions_perms={"action": ["injMapSysDocker:action"]},
                                                                  remote_injector_tree_entity_gears_cache_id=
                                                                  self.gears_registry_cache_id,
                                                                  remote_injector_tree_entity_components_cache_id=
                                                                  self.components_registry_cache_id)
            self.injector_ui_procos_entity.save()
            self.ready = True

    def stop(self):
        if self.ready:
            if InjectorCachedGearService.get_gears_cache_size() == 0 and \
                    InjectorCachedComponentService.get_components_cache_size() == 0:
                self.injector_ui_procos_entity.remove()
            self.injector_service.stop()
            SessionService.close_session()
            self.ready = False
