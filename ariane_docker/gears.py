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
import pprint
import socket
import timeit
import traceback
from ariane_clip3.domino import DominoReceptor
from ariane_clip3.directory import OSInstanceService, RoutingAreaService, SubnetService, NICService, IPAddressService, \
    TeamService, Team, EnvironmentService, Environment, OSInstance, OSTypeService, CompanyService, Company, OSType, \
    IPAddress, NIC, LocationService
from ariane_clip3.injector import InjectorGearSkeleton
import time
import sys
from ariane_clip3.mapping import ContainerService, Container, NodeService, Node, EndpointService, Endpoint, Link, \
    Transport, SessionService
from ariane_procos.system import NetworkInterfaceCard
from ariane_docker.components import DockerComponent
from ariane_docker.docker import DockerContainer

__author__ = 'mffrench'

LOGGER = logging.getLogger(__name__)


class DirectoryGear(InjectorGearSkeleton):
    def __init__(self):
        LOGGER.debug("DirectoryGear.__init__")
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
        LOGGER.debug("DirectoryGear.on_start")
        self.running = True
        self.cache(running=self.running)

    def on_stop(self):
        LOGGER.debug("DirectoryGear.on_stop")
        if self.running:
            self.running = False
            self.cache(running=self.running)

    def on_failure(self, exception_type, exception_value, traceback_):
        LOGGER.debug("DirectoryGear.on_failure")
        LOGGER.error("DirectoryGear.on_failure - " + exception_type.__str__() + "/" + exception_value.__str__())
        LOGGER.error("DirectoryGear.on_failure - " + traceback_.format_exc())
        if self.running:
            self.running = False
            self.cache(running=self.running)

    def gear_start(self):
        LOGGER.debug("DirectoryGear.gear_start")
        self.on_start()
        LOGGER.debug('docker_directory_gear@' + str(DockerHostGear.hostname) + ' has been started.')

    def gear_stop(self):
        LOGGER.debug("DirectoryGear.gear_stop")
        if self.running:
            self.running = False
            self.cache(running=self.running)
            LOGGER.debug('docker_directory_gear@' + str(DockerHostGear.hostname) + ' has been stopped.')

    @staticmethod
    def sync_docker_host_osi(cached_docker_host):
        LOGGER.debug("DirectoryGear.sync_docker_host_osi")
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
        LOGGER.debug("DirectoryGear.sync_docker_host_lra")
        if cached_docker_host.lra_id is not None:
            DockerHostGear.docker_host_lra = RoutingAreaService.find_routing_area(ra_id=cached_docker_host.lra_id)
            if DockerHostGear.docker_host_lra is not None and \
                    DockerHostGear.docker_host_lra.name != DockerHostGear.hostname + '.local':
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

    @staticmethod
    def sync_docker_networks(docker_host):
        LOGGER.debug("DirectoryGear.sync_docker_host_networks")
        # CREATION AND REMOVAL OF DOCKER NETWORK ARE DONE BY ARIANE PROCOS PLUGIN
        for docker_network in docker_host.networks:
            if docker_network in docker_host.new_networks and docker_network.bridge_name is not None:
                # SYNC NIC HOLDING THE SUBNET BRIDGE
                nic_name = DockerHostGear.hostname + '.' + docker_network.bridge_name
                nic = NICService.find_nic(nic_name=nic_name)
                if nic is not None:
                    docker_network.nic_id = nic.id
                    docker_network.nic = nic
                    # SYNC SUBNET
                    if nic.nic_ipa_id > 0:
                        ip_address = IPAddressService.find_ip_address(ipa_id=nic.nic_ipa_id)
                        subnet = SubnetService.find_subnet(sb_id=ip_address.ipa_subnet_id)
                        if subnet is not None:
                            docker_network.subnet_id = subnet.id
                            docker_network.subnet = subnet
                        else:
                            LOGGER.warning('docker subnet for nic ' + nic_name + ' not found in Ariane directories !')
                    else:
                        LOGGER.warning('No IP defined for NIC ' + nic_name + ' in Ariane directories !')
                else:
                    LOGGER.warning(nic_name + ' NIC not found in Ariane directories !')

    @staticmethod
    def sync_docker_container_team(docker_container):
        LOGGER.debug("DirectoryGear.sync_docker_container_team")
        team_from_conf = docker_container.extract_team_from_env_vars()
        if team_from_conf is not None:
            team_from_ariane = TeamService.find_team(team_name=team_from_conf[DockerContainer.ariane_team_name])
            if team_from_ariane is None:
                team_from_ariane = Team(
                    name=team_from_conf[DockerContainer.ariane_team_name],
                    color_code=team_from_conf[DockerContainer.ariane_team_cc],
                    description=team_from_conf[DockerContainer.ariane_team_desc]
                )
                try:
                    team_from_ariane.save()
                except Exception as e:
                    LOGGER.warning("Unable to save team (" + str(team_from_conf) + ") in Ariane Directories !")
                    LOGGER.warning(e.__str__())
                    LOGGER.debug(traceback.format_exc())

            if team_from_ariane is not None:
                docker_container.team = team_from_ariane
                docker_container.tid = team_from_ariane.id
        else:
            LOGGER.warning("Team is not specified in the docker container ( " + docker_container.name +
                           " ) environment variables !")

        if docker_container.team is None and DockerHostGear.docker_host_osi.team_ids.__len__() > 0:
            LOGGER.warning("Docker container team will be inherited from host first team !")
            docker_container.team = TeamService.find_team(team_id=DockerHostGear.docker_host_osi.team_ids[0])
            docker_container.tid = DockerHostGear.docker_host_osi.team_ids[0]

    @staticmethod
    def sync_docker_container_env(docker_container):
        LOGGER.debug("DirectoryGear.sync_docker_container_env")
        env_from_conf = docker_container.extract_environment_from_env_vars()
        if env_from_conf is not None:
            env_from_ariane = EnvironmentService.find_environment(
                env_name=env_from_conf[DockerContainer.ariane_environment_name]
            )
            if env_from_ariane is None:
                env_from_ariane = Environment(
                    name=env_from_conf[DockerContainer.ariane_environment_name],
                    color_code=env_from_conf[DockerContainer.ariane_environment_cc],
                    description=env_from_conf[DockerContainer.ariane_environment_desc]
                )
                try:
                    env_from_ariane.save()
                except Exception as e:
                    LOGGER.warning("Unable to save environment (" + str(env_from_conf) + ") in Ariane Directories !")
                    LOGGER.warning(e.__str__())
                    LOGGER.debug(traceback.format_exc())

            if env_from_ariane is not None:
                docker_container.environment = env_from_ariane
                docker_container.eid = env_from_ariane.id
        else:
            LOGGER.warning("Environment is not specified in the docker container ( " + docker_container.name +
                           " ) environment variables !")

        if docker_container.environment is None and DockerHostGear.docker_host_osi.environment_ids.__len__() > 0:
            LOGGER.warning("Docker container environment will be inherited from host first environment !")
            docker_container.environment = EnvironmentService.find_environment(
                env_id=DockerHostGear.docker_host_osi.environment_ids[0]
            )
            docker_container.eid = DockerHostGear.docker_host_osi.environment_ids[0]

    @staticmethod
    def sync_docker_container_ost(docker_container):
        LOGGER.debug("DirectoryGear.sync_docker_container_ost")
        ost_from_conf = docker_container.extract_os_type_from_env_vars()
        if ost_from_conf is not None:
            ost_from_ariane = OSTypeService.find_ostype(ost_name=ost_from_conf[DockerContainer.ariane_ost_name],
                                                        ost_arch=ost_from_conf[DockerContainer.ariane_ost_arc])
            if ost_from_ariane is None:
                cmp_from_ariane = CompanyService.find_company(
                    cmp_name=ost_from_conf[DockerContainer.ariane_ost_scmp_name]
                )
                if cmp_from_ariane is None:
                    cmp_from_ariane = Company(
                        name=ost_from_conf[DockerContainer.ariane_ost_scmp_name],
                        description=ost_from_conf[DockerContainer.ariane_ost_scmp_desc]
                    )
                    cmp_from_ariane.save()
                ost_from_ariane = OSType(
                    name=ost_from_conf[DockerContainer.ariane_ost_name],
                    architecture=ost_from_conf[DockerContainer.ariane_ost_arc],
                    os_type_company_id=cmp_from_ariane.id
                )
                ost_from_ariane.save()
            docker_container.ostid = ost_from_ariane.id
            docker_container.ost = ost_from_ariane
        else:
            LOGGER.warning("OS Type is not specified in the docker container ( " + docker_container.name +
                           " ) environment variables !")

    @staticmethod
    def sync_docker_container_osi(docker_container):
        LOGGER.debug("DirectoryGear.sync_docker_container_osi")
        osi_from_ariane = OSInstanceService.find_os_instance(
            osi_name=docker_container.name + '.' + DockerHostGear.hostname
        )
        if osi_from_ariane is None:
            env_ids = [docker_container.eid] if docker_container.eid is not None else None
            team_ids = [docker_container.tid] if docker_container.tid is not None else None
            osi_from_ariane = OSInstance(
                name=docker_container.name + '.' + DockerHostGear.hostname,
                description=docker_container.name + '@' + DockerHostGear.hostname,
                admin_gate_uri=DockerHostGear.docker_host_osi.admin_gate_uri + '/$[docker exec -i -t ' +
                docker_container.name + ' /bin/bash]',
                osi_embedding_osi_id=DockerHostGear.docker_host_osi.id,
                osi_ost_id=docker_container.ostid,
                osi_environment_ids=env_ids,
                osi_team_ids=team_ids
            )
            osi_from_ariane.save()
        docker_container.oid = osi_from_ariane.id
        docker_container.osi = osi_from_ariane

    @staticmethod
    def sync_docker_container_ip_and_nic(docker_container, docker_host_networks):
        LOGGER.debug("DirectoryGear.sync_docker_container_ip_and_nic")
        for docker_container_nic in docker_container.nics:
            if docker_container_nic not in docker_container.last_nics:
                if not docker_container_nic.ipv4_address.startswith('127'):
                    # LOGGER.debug(str(docker_container_nic))
                    for docker_network in docker_host_networks:
                        if docker_network.subnet is None and docker_network.subnet_id is not None:
                            docker_network.subnet = SubnetService.find_subnet(sb_name=docker_network.subnet_id)

                        if docker_network.subnet is not None:
                            dock_subnet = docker_network.subnet
                            if NetworkInterfaceCard.ip_is_in_subnet(docker_container_nic.ipv4_address,
                                                                    docker_network.subnet.ip,
                                                                    docker_network.subnet.mask):
                                ip_address = IPAddressService.find_ip_address(
                                    ipa_ip_address=docker_container_nic.ipv4_address,
                                    ipa_subnet_id=docker_network.subnet.id
                                )
                                if ip_address is None:
                                    ip_address = IPAddress(ip_address=docker_container_nic.ipv4_address,
                                                           fqdn=docker_container_nic.ipv4_fqdn,
                                                           ipa_subnet_id=docker_network.subnet.id,
                                                           ipa_osi_id=docker_container.osi.id)
                                    ip_address.save()
                                    docker_network.subnet.sync()
                                else:
                                    if ip_address.ipa_os_instance_id != docker_container.osi.id:
                                        ip_address.ipa_os_instance_id = docker_container.osi.id
                                        ip_address.save()
                                nicmcaddr = docker_container_nic.mac_address
                                # LOGGER.debug(str(ip_address))
                # else:
                #     TODO: currently docker container local subnet and routing area.
                #     TODO: need to enable multiple routing area for one subnet on ariane directories
                #     NOTE: anyway this feature will probably not needed as docker routing is done from the host
                #     loopback_subnet_conf = SubnetConfig(
                #         name=docker_container.name + "." + docker_container.domain + ".loopback",
                #         description=docker_container.name + "." + docker_container.domain + " loopback subnet",
                #         subnet_ip="127.0.0.0",
                #         subnet_mask="255.0.0.0"
                #     )
                #     pass

                                if dock_subnet is not None:
                                    if docker_container.osi is not None:
                                        docker_container.osi.add_subnet(dock_subnet)
                                        docker_container.osi.sync()
                                    else:
                                        LOGGER.warning("docker_container " + docker_container.name + " osi is None ?!")

                                if nicmcaddr is not None and nicmcaddr:
                                    nic2save = NICService.find_nic(nic_mac_address=nicmcaddr)
                                    if nic2save is None:
                                        nic2save = NIC(
                                            name=docker_container.domain + "." + docker_container.name + "." +
                                            docker_container_nic.name,
                                            mac_address=nicmcaddr,
                                            duplex=docker_container_nic.duplex,
                                            speed=docker_container_nic.speed,
                                            mtu=docker_container_nic.mtu,
                                            nic_osi_id=docker_container.osi.id if docker_container.osi is not None else None,
                                            nic_ipa_id=ip_address.id if ip_address is not None else None
                                        )
                                        nic2save.save()
                                    else:
                                        nic2save.nic_ipa_id = ip_address.id if ip_address is not None else None
                                        nic2save.sync()
                                    docker_container_nic.nic_id = nic2save.id

    @staticmethod
    def sync_docker_containers(docker_host):
        LOGGER.debug("DirectoryGear.sync_docker_containers")
        for docker_container in docker_host.new_containers:
            DirectoryGear.sync_docker_container_team(docker_container)
            DirectoryGear.sync_docker_container_env(docker_container)
            DirectoryGear.sync_docker_container_ost(docker_container)
            DirectoryGear.sync_docker_container_osi(docker_container)
            DirectoryGear.sync_docker_container_ip_and_nic(docker_container, docker_host.networks)
            docker_container.osi.sync()

        # LOGGER.debug("last containers: " + pprint.pformat(docker_host.last_containers))
        # LOGGER.debug("current containers: " + pprint.pformat(docker_host.containers))
        for docker_container in docker_host.last_containers:
            if docker_container not in docker_host.containers:
                if docker_container.oid is not None:
                    osi_from_ariane = OSInstanceService.find_os_instance(
                        osi_id=docker_container.oid
                    )
                else:
                    osi_from_ariane = OSInstanceService.find_os_instance(
                        osi_name=docker_container.name + '.' + DockerHostGear.hostname
                    )
                if osi_from_ariane is not None:
                    osi_from_ariane.remove()
            else:
                for nic in docker_container.last_nics:
                    if nic not in docker_container.nics:
                        nic2rm = NICService.find_nic(nic_id=nic.nic_id)
                        if nic2rm is not None:
                            ip2rm = IPAddressService.find_ip_address(ipa_id=nic2rm.nic_ipa_id)
                            if ip2rm is not None:
                                ip2rm.remove()
                            else:
                                LOGGER.warning("IP " + ip2rm.ip_address + " already removed !?")
                            nic2rm.remove()
                        else:
                            LOGGER.warning("NIC " + nic2rm.macAddress + " already removed !?")
                DirectoryGear.sync_docker_container_ip_and_nic(docker_container, docker_host.networks)

    def update_ariane_directories(self, docker_host):
        LOGGER.debug("DirectoryGear.update_ariane_directories")
        if docker_host.networks != docker_host.last_networks:
            self.sync_docker_networks(docker_host)
        else:
            LOGGER.debug("No changes on docker host networks !")

        if docker_host.containers != docker_host.last_containers:
            self.sync_docker_containers(docker_host)
        else:
            LOGGER.debug("No changes on docker host containers !")

    def init_ariane_directories(self, component):
        docker_host = component.docker_host.get()
        LOGGER.debug("DirectoryGear.init_ariane_directories - init start")
        try:
            start_time = timeit.default_timer()
            self.sync_docker_host_osi(docker_host)
            self.sync_docker_host_lra(docker_host)
            self.sync_docker_networks(docker_host)
            self.sync_docker_containers(docker_host)
            sync_proc_time = timeit.default_timer()-start_time
            LOGGER.info('DirectoryGear.init_ariane_directories - time : ' + str(sync_proc_time))
            LOGGER.debug("DirectoryGear.init_ariane_directories - init done")
        except Exception as e:
            LOGGER.error("DirectoryGear.init_ariane_directories - " + e.__str__())
            LOGGER.debug("DirectoryGear.init_ariane_directories - " + traceback.format_exc())

    def synchronize_with_ariane_directories(self, component):
        if self.running:
            try:
                start_time = timeit.default_timer()
                docker_host = component.docker_host.get()
                LOGGER.debug("DirectoryGear.synchronize_with_ariane_directories - sync start")
                self.update_ariane_directories(docker_host)
                self.update_count += 1
                sync_proc_time = timeit.default_timer()-start_time
                LOGGER.info('DirectoryGear.synchronize_with_ariane_directories - time : ' + str(sync_proc_time))
                LOGGER.debug("DirectoryGear.synchronize_with_ariane_directories - sync done")
            except Exception as e:
                LOGGER.error("DirectoryGear.synchronize_with_ariane_directories - " + e.__str__())
                LOGGER.debug("DirectoryGear.synchronize_with_ariane_directories - " + traceback.format_exc())
        else:
            LOGGER.warning("Synchronization requested but docker_directory_gear@" + str(DockerHostGear.hostname) +
                           " is not running.")


class MappingGear(InjectorGearSkeleton):

    docker_host_mco = None

    def __init__(self):
        LOGGER.debug("MappingGear.__init__")
        super(MappingGear, self).__init__(
            gear_id='ariane.community.plugin.docker.gears.cache.mapping_gear@' + str(DockerHostGear.hostname),
            gear_name='docker_mapping_gear@' + str(DockerHostGear.hostname),
            gear_description='Ariane Docker injector gear for ' + str(DockerHostGear.hostname),
            gear_admin_queue='ariane.community.plugin.docker.gears.cache.mapping_gear@' + str(DockerHostGear.hostname),
            running=False
        )
        self.update_count = 0

    def on_start(self):
        LOGGER.debug("MappingGear.on_start")
        self.running = True
        self.cache(running=self.running)

    def on_stop(self):
        LOGGER.debug("MappingGear.on_stop")
        if self.running:
            self.running = False
            self.cache(running=self.running)

    def on_failure(self, exception_type, exception_value, traceback_):
        LOGGER.debug("MappingGear.on_failure")
        LOGGER.error("MappingGear.on_failure - " + exception_type.__str__() + "/" + exception_value.__str__())
        LOGGER.error("MappingGear.on_failure - " + traceback_.format_exc())
        if self.running:
            self.running = False
            self.cache(running=self.running)

    def gear_start(self):
        LOGGER.debug("MappingGear.gear_start")
        self.on_start()
        LOGGER.warning('docker_mapping_gear@' + str(DockerHostGear.hostname) + ' has been started.')

    def gear_stop(self):
        LOGGER.debug("MappingGear.gear_stop")
        if self.running:
            self.running = False
            self.cache(running=self.running)
            LOGGER.warning('docker_mapping_gear@' + str(DockerHostGear.hostname) + ' has been stopped.')

    @staticmethod
    def synchronize_new_map_socket(docker_container, process, map_socket):
        LOGGER.debug("MappingGear.synchronize_new_map_socket")
        if map_socket.source_ip is not None and map_socket.source_port is not None:
            proto = None
            if map_socket.type == "SOCK_STREAM":
                proto = "tcp://"
            elif map_socket.type == "SOCK_DGRAM":
                proto = "udp://"
            else:
                LOGGER.warning("MappingGear.synchronize_new_map_socket - socket type " + map_socket.type +
                               " currently not supported !")

            if proto is not None:
                source_endpoint = None
                source_url = proto + map_socket.source_ip + ":" + str(map_socket.source_port)

                target_endpoint = None
                target_url = None

                if map_socket.source_endpoint_id is None:
                    parent_node = None
                    if process.mdp is None:
                        if process.mdpid is not None and process.mdpid:
                            parent_node = NodeService.find_node(nid=process.mdpid)
                    else:
                        parent_node = process.mdp

                    if parent_node is not None:
                        source_endpoint = Endpoint(
                            url=source_url,
                            parent_node=parent_node
                        )
                        if map_socket.type is not None and map_socket.type:
                            source_endpoint.add_property(('type', map_socket.type))
                        if map_socket.family is not None and map_socket.family:
                            source_endpoint.add_property(('family', map_socket.family))
                        if map_socket.status is not None and map_socket.status:
                            source_endpoint.add_property(('status', map_socket.status))
                        if map_socket.file_descriptors is not None and map_socket.file_descriptors.__len__() > 0:
                            source_endpoint.add_property(('file descriptors', map_socket.file_descriptors))
                        source_endpoint.save()
                        map_socket.source_endpoint_id = source_endpoint.id
                    else:
                        LOGGER.warning("MappingGear.synchronize_new_map_socket - Fail to sync parent node for "
                                       "source endpoint " + source_url)
                else:
                    source_endpoint = EndpointService.find_endpoint(eid=map_socket.source_endpoint_id)

                if map_socket.destination_ip is not None and map_socket.destination_port is not None:
                    target_url = proto + map_socket.destination_ip + ":" + str(map_socket.destination_port)

                if target_url is not None:
                    if map_socket.destination_endpoint_id is None:
                        LOGGER.debug("MappingGear.synchronize_new_map_socket - source_url: " + source_url +
                                     "; target_url: " + target_url)
                        is_dhost_remote_destination = docker_container.is_local_destination(map_socket)
                        if is_dhost_remote_destination:
                            is_in_container_destination = docker_container.is_in_container_destination(map_socket)
                            if not is_in_container_destination:
                                selector = "endpointURL =~ '" + target_url + ".*'"
                                endpoints = EndpointService.find_endpoint(selector=selector)
                                if endpoints is not None:
                                    if endpoints.__len__() == 1:
                                        target_endpoint = endpoints[0]
                                    else:
                                        LOGGER.warning("MappingGear.synchronize_new_map_socket - Several endpoints "
                                                       "found for selector " + selector +
                                                       ". There should be one endpoint only !")
                                else:
                                    LOGGER.warning("MappingGear.synchronize_new_map_socket - No endpoint for selector "
                                                   + selector + "  ?!")
                            else:
                                target_local_process = None
                                mirror_map_socket = None
                                for dc_process in docker_container.processs:
                                    for m_map_socket in dc_process.map_sockets:
                                        if (m_map_socket.source_ip + ":" + m_map_socket.source_port) == target_url:
                                            target_local_process = dc_process
                                            mirror_map_socket = m_map_socket
                                            break
                                if target_local_process is not None and mirror_map_socket is not None:
                                    if mirror_map_socket.source_endpoint_id is None:
                                        if target_local_process.mdp is None:
                                            parent_node = NodeService.find_node(nid=target_local_process.mdpid)
                                        else:
                                            parent_node = target_local_process.mdp

                                        if parent_node is not None:
                                            target_endpoint = Endpoint(
                                                url=target_url,
                                                parent_node=parent_node
                                            )
                                            if mirror_map_socket.type is not None and mirror_map_socket.type:
                                                target_endpoint.add_property(('type', mirror_map_socket.type))
                                            if mirror_map_socket.family is not None and mirror_map_socket.family:
                                                target_endpoint.add_property(('family', mirror_map_socket.family))
                                            if mirror_map_socket.status is not None and mirror_map_socket.status:
                                                target_endpoint.add_property(('status', mirror_map_socket.status))
                                            if mirror_map_socket.file_descriptors is not None and \
                                                    mirror_map_socket.file_descriptors.__len__() > 0:
                                                target_endpoint.add_property((
                                                    'file descriptors', mirror_map_socket.file_descriptors
                                                ))
                                            target_endpoint.save()
                                            mirror_map_socket.source_endpoint_id = target_endpoint.id
                                        else:
                                            LOGGER.warning("MappingGear.synchronize_new_map_socket - "
                                                           "Fail to sync parent node for target endpoint " + target_url)
                                    else:
                                        target_endpoint = EndpointService.find_endpoint(
                                            eid=mirror_map_socket.source_endpoint_id
                                        )
                        else:
                            selector = "endpointURL =~ '" + target_url + ".*'"
                            endpoints = EndpointService.find_endpoint(selector=selector)
                            if endpoints is not None:
                                if endpoints.__len__() == 1:
                                    target_endpoint = endpoints[0]
                                else:
                                    LOGGER.warning("MappingGear.synchronize_new_map_socket - Several endpoints found "
                                                   "for selector " + selector + ". There should be one endpoint only !")
                            else:
                                LOGGER.warning("MappingGear.synchronize_new_map_socket - No endpoint for selector " +
                                               selector + "  ?!")
                    else:
                        target_endpoint = EndpointService.find_endpoint(map_socket.destination_endpoint_id)

                    if source_endpoint is None:
                        LOGGER.warning("MappingGear.synchronize_new_map_socket - Unable to define source endpoint: " +
                                       source_url)
                    else:
                        if target_endpoint is None:
                            # unable_to_define_target_ep = True
                            LOGGER.warning("MappingGear.synchronize_new_map_socket - Unable to define target endpoint: "
                                           + target_url)
                        else:
                            map_socket.destination_endpoint_id = target_endpoint.id
                            map_socket.destination_node_id = target_endpoint.parent_node_id

                            transport = Transport(name=proto)
                            if transport.id is None:
                                transport.save()

                            if transport.id is not None:
                                link = Link(source_endpoint_id=map_socket.source_endpoint_id,
                                            target_endpoint_id=map_socket.destination_endpoint_id,
                                            transport_id=transport.id)
                                link.save()
                                map_socket.transport_id = transport.id
                                map_socket.link_id = link.id
        else:
            LOGGER.warning("MappingGear.synchronize_new_map_socket - no source ip / port - " + str(map_socket))

    @staticmethod
    def synchronize_removed_map_socket(docker_container, process, map_socket):
        LOGGER.debug("MappingGear.synchronize_removed_map_socket")
        if map_socket.source_endpoint_id is not None:
            source_endpoint = EndpointService.find_endpoint(eid=map_socket.source_endpoint_id)
            if source_endpoint is not None:
                LOGGER.debug("Remove (source) endpoint " + source_endpoint.url)
                source_endpoint.remove()
            else:
                LOGGER.warning("Dead socket (source endpoint : " + str(map_socket.source_endpoint_id) +
                               ") doesn't exist anymore on DB!")

        # if map_socket.destination_endpoint_id is not None:
        #     destination_endpoint = EndpointService.find_endpoint(eid=map_socket.destination_endpoint_id)
        #     if destination_endpoint is not None:
        #         LOGGER.debug("Remove (destination) endpoint " + destination_endpoint.url)
        #         destination_endpoint.remove()
        #     else:
        #         LOGGER.warning("Dead socket (destination endpoint : " + str(map_socket.source_endpoint_id) +
        #                        ") doesn't exist anymore on DB!")

    @staticmethod
    def synchronize_process_sockets(docker_container, process):
        LOGGER.debug("MappingGear.synchronize_process_sockets")
        LOGGER.debug("current sockets: " + pprint.pformat(process.map_sockets))
        LOGGER.debug("new sockets: " + pprint.pformat(process.new_map_sockets))
        LOGGER.debug("last sockets: " + pprint.pformat(process.last_map_sockets))
        for map_socket in process.new_map_sockets:
            MappingGear.synchronize_new_map_socket(docker_container, process, map_socket)
        for map_socket in process.last_map_sockets:
            if map_socket not in process.map_sockets:
                MappingGear.synchronize_removed_map_socket(docker_container, process, map_socket)

    @staticmethod
    def synchronize_process_properties(docker_container, process):
        LOGGER.debug("MappingGear.synchronize_processs_properties")
        if process.mosp is None and process.mospid is not None:
            process.mosp = NodeService.find_node(nid=process.mospid)
        if process.mosp is not None:
            process.mosp.sync()
            if process.mdp is None and process.mdpid is not None:
                process.mdp = NodeService.find_node(nid=process.mdpid)
            if process.mdp is not None:
                process.mdp.sync()
                if process.mosp.properties is not None:
                    for key in process.mosp.properties.keys():
                        process.mdp.add_property((key, process.mosp.properties[key]))
                else:
                    LOGGER.warning("No properties for process " +
                                   str(process.mosp.name) if process.mosp.name is not None else "???" + " ?!")
            else:
                LOGGER.warning("Process " + str(process.mdpid) + " has been lost on mapping DB ?!")
        else:
            LOGGER.warning("Shadow process " + str(process.mospid) + " has been lost on mapping DB ?!")

    @staticmethod
    def synchronize_new_processs_node(docker_container, process):
        LOGGER.debug("MappingGear.synchronize_new_processs_node")
        mapping_container = docker_container.mcontainer
        process.mcid = mapping_container.id

        mosp = None
        MappingGear.docker_host_mco.sync()

        nodes_to_test = NodeService.find_node(selector="nodeName =~ '.*" + str(process.pid) + ".*'")
        if nodes_to_test is not None:
            for node_to_test in nodes_to_test:
                if node_to_test.name.startswith('[' + str(process.pid) + ']'):
                    LOGGER.debug("Shadow Mapping OS node found : " + node_to_test.name)
                    mosp = node_to_test
                    break

        if mosp is not None:
            process_node = Node(
                name=mosp.name,
                container_id=process.mcid
            )
            process_node.save()
            process.mdpid = process_node.id
            process.mdp = process_node
            process.mospid = mosp.id
            process.mosp = mosp
        else:
            LOGGER.warning("Shadow Mapping OS node for process " + str(process.pid) + " not found !")

    @staticmethod
    def synchronize_removed_processs_node(docker_container, process):
        LOGGER.debug("MappingGear.synchronize_removed_processs_node")
        mapping_container = docker_container.mcontainer
        if mapping_container is None and docker_container.mid is not None:
            docker_container.mcontainer = ContainerService.find_container(cid=docker_container.mid)
            mapping_container = docker_container.mcontainer
        if mapping_container is not None:
            process_node = NodeService.find_node(nid=process.mdpid)
            if process_node is not None:
                process_node.remove()
            else:
                LOGGER.warning("Mapping node for process " + process.pid + "@" + mapping_container.name +
                               " not found !")
        else:
            LOGGER.warning("Mapping container not found for container " + docker_container.name + " !?")

    @staticmethod
    def synchronize_container_processs(docker_container):
        LOGGER.debug("MappingGear.synchronize_container_processs")
        # SYNC NEW PROCESSES NODES
        for process in docker_container.new_processs:
            MappingGear.synchronize_new_processs_node(docker_container, process)
        # SYNC CURRENT PROCESSES AND SOCKETS
        for process in docker_container.processs:
            MappingGear.synchronize_process_properties(docker_container, process)
            MappingGear.synchronize_process_sockets(docker_container, process)
        # SYNC DEAD PROCESSES
        for process in docker_container.last_processs:
            if process not in docker_container.processs:
                MappingGear.synchronize_removed_processs_node(docker_container, process)

    @staticmethod
    def synchronize_container_properties(docker_container):
        LOGGER.debug("MappingGear.synchronize_container_properties")
        mapping_container = docker_container.mcontainer
        if docker_container.osi is None and docker_container.oid is not None:
            docker_container.osi = OSInstanceService.find_os_instance(osi_id=docker_container.oid)

        if docker_container.team is None and docker_container.tid is not None:
            docker_container.team = TeamService.find_team(team_id=docker_container.tid)

        is_ok = True
        if docker_container.osi is not None:
            docker_container.osi.sync()
        else:
            is_ok = False
            LOGGER.warning("Docker container " + docker_container.name + " linked OS instance not found !?")

        if is_ok and docker_container.team is not None:
            docker_container.team.sync()
        else:
            is_ok = False
            LOGGER.warning("Docker container " + docker_container.name + " linked team not found !?")

        mapping_container.add_property((
            Container.OWNER_MAPPING_PROPERTY,
            'docker_host_gear@' + str(DockerHostGear.hostname)
        ))

        if is_ok:
            if DockerHostGear.docker_host_lra.loc_ids.__len__() > 1:
                LOGGER.warning("Localhost routing area " + DockerHostGear.docker_host_lra.name +
                               " have more than one location ?!")
            elif DockerHostGear.docker_host_lra.loc_ids.__len__() == 1:
                location = LocationService.find_location(DockerHostGear.docker_host_lra.loc_ids[0])
                if location is not None:
                    location_properties = {
                        Container.PL_NAME_MAPPING_FIELD: location.name,
                        Container.PL_ADDR_MAPPING_FIELD: location.address,
                        Container.PL_TOWN_MAPPING_FIELD: location.town,
                        Container.PL_CNTY_MAPPING_FIELD: location.country,
                        Container.PL_GPSA_MAPPING_FIELD: location.gpsLatitude,
                        Container.PL_GPSN_MAPPING_FIELD: location.gpsLongitude
                    }
                    mapping_container.add_property((Container.PL_MAPPING_PROPERTIES, location_properties))
                else:
                    LOGGER.warning("Location ( " + DockerHostGear.docker_host_lra.loc_ids[0] + " ) not found ?!")
            else:
                LOGGER.warning("Localhost routing area " + DockerHostGear.docker_host_lra.name +
                               " don't have location ?!")

            network_properties = []
            ra_subnets = {}
            ra_list = []
            if docker_container.osi is not None and docker_container.osi.subnet_ids is not None:
                for subnet_id in docker_container.osi.subnet_ids:
                    subnet = SubnetService.find_subnet(subnet_id)
                    if subnet is not None:
                        if subnet.routing_area_id is not None:
                            if subnet.routing_area_id not in ra_subnets:
                                routing_area = RoutingAreaService.find_routing_area(ra_id=subnet.routing_area_id)
                                if routing_area is not None:
                                    ra_list.append(routing_area)
                                    ra_subnets[subnet.routing_area_id] = []
                                    ra_subnets[subnet.routing_area_id].append({
                                        Container.SUBNET_NAME_MAPPING_FIELD: subnet.name,
                                        Container.SUBNET_IPAD_MAPPING_FIELD: subnet.ip,
                                        Container.SUBNET_MASK_MAPPING_FIELD: subnet.mask,
                                        Container.SUBNET_ISDEFAULT_MAPPING_FIELD: subnet.is_default
                                    })
                                else:
                                    LOGGER.warning("Routing Area ( " + subnet.routing_area_id + " ) for subnet (" +
                                                   subnet.name + ") not fount !?")
                            else:
                                ra_subnets[subnet.routing_area_id].append({
                                    Container.SUBNET_NAME_MAPPING_FIELD: subnet.name,
                                    Container.SUBNET_IPAD_MAPPING_FIELD: subnet.ip,
                                    Container.SUBNET_MASK_MAPPING_FIELD: subnet.mask,
                                    Container.SUBNET_ISDEFAULT_MAPPING_FIELD: subnet.is_default
                                })
                    else:
                        LOGGER.warning("Subnet (" + subnet_id + ") not found !?")
            else:
                if docker_container.osi is None:
                    LOGGER.warning("docker_container " + docker_container.name + " osi is None ?!")
                else:
                    LOGGER.warning("docker_container " + docker_container.name + " osi subnets is None ?!")

            for ra in ra_list:
                network_properties.append(
                    {
                        Container.RAREA_NAME_MAPPING_FIELD: ra.name,
                        Container.RAREA_MLTC_MAPPING_FIELD: ra.multicast,
                        Container.RAREA_TYPE_MAPPING_FIELD: ra.type,
                        Container.RAREA_SUBNETS: ra_subnets[ra.id]
                    })
            if network_properties.__len__() > 0:
                mapping_container.add_property((Container.NETWORK_MAPPING_PROPERTIES, network_properties))

            team_properties = {
                Container.TEAM_NAME_MAPPING_FIELD: docker_container.team.name,
                Container.TEAM_COLR_MAPPING_FIELD: docker_container.team.color_code
            }
            mapping_container.add_property((Container.TEAM_SUPPORT_MAPPING_PROPERTIES, team_properties))

            mapping_container.add_property((
                DockerContainer.docker_props_config_image,
                docker_container.details['Config']['Image']
            ))

            exposed_ports = []
            dict_key_ep = docker_container.details['Config']['ExposedPorts'].keys()
            for key in dict_key_ep:
                exposed_ports.append(key)
            if exposed_ports.__len__() > 0:
                mapping_container.add_property((
                    DockerContainer.docker_props_config_exposed_ports,
                    exposed_ports
                ))

            docker_cmd = docker_container.details['Config']['Cmd']
            if docker_cmd is not None and docker_cmd.__len__() > 0:
                for cmd_part in docker_cmd:
                    if "-pass" in cmd_part or "-pwd" in cmd_part:
                        pass_index = docker_cmd.index(cmd_part)
                        if pass_index + 1 < docker_cmd.__len__():
                            docker_cmd[pass_index+1] = "*****"
                mapping_container.add_property((
                    DockerContainer.docker_props_config_cmd,
                    docker_cmd
                ))
            else:
                LOGGER.debug("docker_cmd ( " + str(docker_container.details['Config']['Cmd']) +
                             " ) not defined for container " + docker_container.name)

            docker_entrypoint = docker_container.details['Config']['Entrypoint']
            if docker_entrypoint is not None and docker_entrypoint.__len__() > 0:
                for entrypoint_part in docker_entrypoint:
                    if "-pass" in entrypoint_part or "-pwd" in entrypoint_part:
                        pass_index = docker_entrypoint.index(entrypoint_part)
                        if pass_index + 1 < docker_entrypoint.__len__():
                            docker_entrypoint[pass_index+1] = "*****"

                mapping_container.add_property((
                    DockerContainer.docker_props_config_entrypoint,
                    docker_entrypoint
                ))
            else:
                LOGGER.debug("docker_entrypoint ( " + str(docker_container.details['Config']['Entrypoint']) +
                             " ) not defined for container " + docker_container.name)
            env = {}
            for envvar in docker_container.details['Config']['Env']:
                envvar_name = envvar.split('=')[0]
                if 'ARIANE' not in envvar_name:
                    envvar_value = None
                    if 'PASSWORD' in envvar_name or 'password' in envvar_name or \
                            'PWD' in envvar_name or 'pwd' in envvar_name:
                        envvar_value = '*****'
                    else:
                        envvar_value = envvar.split('=')[1]
                    env[envvar_name] = envvar_value

            if env.keys().__len__() > 0:
                mapping_container.add_property((
                    DockerContainer.docker_props_config_env,
                    env
                ))

            mapping_container.add_property((
                DockerContainer.docker_props_config_hostname,
                docker_container.details['Config']['Hostname']
            ))

            mapping_container.add_property((
                DockerContainer.docker_props_driver,
                docker_container.details['Driver']
            ))

            ports_binding = []
            ports_binding_keys = docker_container.details['HostConfig']['PortBindings']
            if ports_binding_keys.__len__() > 0:
                for exposed_port in ports_binding_keys:
                    targets = docker_container.details['HostConfig']['PortBindings'][exposed_port]
                    if targets.__len__() > 0:
                        port_binding = exposed_port + ' <-> '
                        for target in targets:
                            host_ip = target['HostIp']
                            host_port = target['HostPort']
                            if host_ip == '':
                                host_ip = '0.0.0.0'
                            port_binding += host_ip + ':' + host_port + ' '
                        ports_binding.append(port_binding)
            mapping_container.add_property((
                DockerContainer.docker_props_host_config_port_binding,
                ports_binding
            ))

    @staticmethod
    def synchronize_existing_container(docker_container):
        LOGGER.debug("MappingGear.synchronize_existing_containers")
        MappingGear.synchronize_container_processs(docker_container)

    @staticmethod
    def synchronize_new_container(docker_container):
        LOGGER.debug("MappingGear.synchronize_new_container")
        if docker_container.ost is None:
            if docker_container.ostid is not None:
                docker_container.ost = OSTypeService.find_ostype(ost_id=docker_container.ostid)

        product = "Docker Container"
        company = "Docker Inc."
        if docker_container.ost is not None:
            if docker_container.ost.company is None:
                docker_container.ost.company = CompanyService.find_company(docker_container.ost.company_id)
            if docker_container.ost.company is not None:
                product = docker_container.ost.name + ' - ' + docker_container.ost.architecture
                company = docker_container.ost.company.name

        mapping_container = Container(
            name=docker_container.name,
            gate_uri=DockerHostGear.docker_host_osi.admin_gate_uri + '/$[docker exec -i -t ' +
            docker_container.name + ' /bin/bash]',
            primary_admin_gate_name='NamespaceAccess@'+docker_container.name,
            parent_container_id=MappingGear.docker_host_mco.id,
            company=company,
            product=product,
            c_type="Docker Container"
        )
        mapping_container.save()
        LOGGER.debug(pprint.pformat(mapping_container.__dict__))
        docker_container.mid = mapping_container.id
        docker_container.mcontainer = mapping_container
        MappingGear.synchronize_container_properties(docker_container)
        MappingGear.synchronize_container_processs(docker_container)

    @staticmethod
    def synchronize_removed_container(docker_container):
        LOGGER.debug("MappingGear.synchronize_removed_container - " + docker_container.name)
        docker_container.mcontainer.remove()

    def synchronize_container(self, docker_host):
        LOGGER.debug("MappingGear.synchronize_container")
        LOGGER.debug("current containers: " + pprint.pformat(docker_host.containers))
        LOGGER.debug("new containers: " + pprint.pformat(docker_host.new_containers))
        LOGGER.debug("last containers: " + pprint.pformat(docker_host.last_containers))
        for docker_container in docker_host.last_containers:
            if docker_container.mcontainer is None:
                if docker_container.mid is None:
                    docker_container.mcontainer = ContainerService.find_container(
                        primary_admin_gate_url=DockerHostGear.docker_host_osi.admin_gate_uri + '/$[docker exec -i -t ' +
                        docker_container.name + ' /bin/bash]'
                    )
                    if docker_container.mcontainer is not None:
                        docker_container.mid = docker_container.mcontainer.id
                else:
                    docker_container.mcontainer = ContainerService.find_container(cid=docker_container.mid)
            if docker_container.mcontainer is not None:
                self.synchronize_existing_container(docker_container)
            else:
                LOGGER.warning("Mapping container not found for container to be updated (" +
                               docker_container.name + ") !?")

        for docker_container in docker_host.new_containers:
            self.synchronize_new_container(docker_container)

        for docker_container in docker_host.last_containers:
            if docker_container not in docker_host.containers:
                if docker_container.mcontainer is None:
                    if docker_container.mid is None:
                        docker_container.mcontainer = ContainerService.find_container(
                            primary_admin_gate_url=DockerHostGear.docker_host_osi.admin_gate_uri +
                            '/$[docker exec -i -t ' + docker_container.name + ' /bin/bash]'
                        )
                        if docker_container.mcontainer is not None:
                            docker_container.mid = docker_container.mcontainer.id
                    else:
                        docker_container.mcontainer = ContainerService.find_container(cid=docker_container.mid)
                if docker_container.mcontainer is not None:
                    self.synchronize_removed_container(docker_container)
                else:
                    LOGGER.warning("Mapping container not found for container to be removed (" +
                                   docker_container.name + ") !?")

    def init_ariane_mapping(self, component):
        SessionService.open_session("ArianeDocker_" + socket.gethostname())
        MappingGear.docker_host_mco = ContainerService.find_container(
            primary_admin_gate_url=DockerHostGear.docker_host_osi.admin_gate_uri
        )
        if MappingGear.docker_host_mco is None:
            LOGGER.error('Docker host ' + str(DockerHostGear.hostname) +
                         ' Ariane container not found in Ariane mapping DB')
            LOGGER.error('Did you run Ariane ProcOS on this host first ? Stopping ...')
            SessionService.close_session()
            sys.exit(-1)
        else:
            try:
                LOGGER.debug("MappingGear.init_ariane_mapping - init start")
                docker_host = component.docker_host.get()
                self.synchronize_container(docker_host)
                SessionService.commit()
                LOGGER.debug("MappingGear.init_ariane_mapping - init done")
                SessionService.close_session()
            except Exception as e:
                LOGGER.error("MappingGear.init_ariane_mapping - " + e.__str__())
                LOGGER.debug("MappingGear.init_ariane_mapping - " + traceback.format_exc())
                try:
                    LOGGER.error("MappingGear.init_ariane_mapping - mapping rollback to previous state")
                    SessionService.rollback()
                except Exception as e:
                    LOGGER.error("MappingGear.init_ariane_mapping - exception on mapping rollback : " + e.__str__())
                    LOGGER.debug("MappingGear.init_ariane_mapping - exception on mapping rollback : " +
                                 traceback.format_exc())
                try:
                    LOGGER.error("MappingGear.init_ariane_mapping - mapping session close")
                    SessionService.close_session()
                except Exception as e:
                    LOGGER.error("MappingGear.init_ariane_mapping - exception on mapping session closing : " +
                                 e.__str__())
                    LOGGER.debug("MappingGear.init_ariane_mapping - exception on mapping session closing : " +
                                 traceback.format_exc())

    def synchronize_with_ariane_mapping(self, component):
        if self.running:
            try:
                start_time = timeit.default_timer()
                SessionService.open_session("ArianeDocker_" + socket.gethostname())
                docker_host = component.docker_host.get()
                LOGGER.debug("MappingGear.synchronize_with_ariane_mapping - sync start")
                self.synchronize_container(docker_host)
                SessionService.commit()
                self.update_count += 1
                LOGGER.debug("MappingGear.synchronize_with_ariane_mapping - sync done")
                SessionService.close_session()
                sync_proc_time = timeit.default_timer()-start_time
                LOGGER.info('MappingGear.synchronize_with_ariane_mapping - time : ' + str(sync_proc_time))
            except Exception as e:
                LOGGER.error("MappingGear.synchronize_with_ariane_mapping - " + e.__str__())
                LOGGER.debug("MappingGear.synchronize_with_ariane_mapping - " + traceback.format_exc())
                try:
                    LOGGER.error("MappingGear.synchronize_with_ariane_mapping - mapping rollback to previous state")
                    SessionService.rollback()
                except Exception as e:
                    LOGGER.error("MappingGear.synchronize_with_ariane_mapping - exception on mapping rollback : " +
                                 e.__str__())
                    LOGGER.debug("MappingGear.synchronize_with_ariane_mapping - exception on mapping rollback : " +
                                 traceback.format_exc())
                try:
                    SessionService.close_session()
                except Exception as e:
                    LOGGER.error("MappingGear.synchronize_with_ariane_mapping - exception on mapping session closing : "
                                 + e.__str__())
                    LOGGER.debug("MappingGear.synchronize_with_ariane_mapping - exception on mapping session closing : "
                                 + traceback.format_exc())
                try:
                    component.rollback().get()
                except Exception as e:
                    LOGGER.error("MappingGear.synchronize_with_ariane_mapping - exception on injector cache rollback : "
                                 + e.__str__())
                    LOGGER.debug("MappingGear.synchronize_with_ariane_mapping - exception on injector cache rollback : "
                                 + traceback.format_exc())
        else:
            LOGGER.warning('Synchronization requested but docker_mapping_gear@' +
                           str(DockerHostGear.hostname) + ' is not running.')


class DockerHostGear(InjectorGearSkeleton):
    # static reference on commons var
    config = None
    hostname = None

    docker_host_osi = None
    docker_host_lra = None

    def __init__(self, config, cli):
        LOGGER.debug("DockerHostGear.__init__")
        DockerHostGear.hostname = socket.gethostname()
        DockerHostGear.config = config
        super(DockerHostGear, self).__init__(
            gear_id='ariane.community.plugin.docker.gears.cache.docker_host_gear@' + str(DockerHostGear.hostname),
            gear_name='docker_host_gear@' + str(DockerHostGear.hostname),
            gear_description='Ariane Docker Host gear for ' + str(DockerHostGear.hostname),
            gear_admin_queue='ariane.community.plugin.docker.gears.cache.docker_host_gear@' +
                             str(DockerHostGear.hostname),
            running=False
        )
        self.component = DockerComponent.start(
            attached_gear_id=self.gear_id(),
            hostname=DockerHostGear.hostname,
            docker_cli=cli,
            docker_gear_actor_ref=self.actor_ref
        ).proxy()
        self.directory_gear = DirectoryGear.start().proxy()
        self.mapping_gear = MappingGear.start().proxy()
        self.domino_receptor = None
        self.call_from_component = True  # set to True for init
        self.to_be_sync = False

    def synchronize_with_ariane_dbs(self):
        self.call_from_component = True
        print_wait = True
        LOGGER.debug("DockerHostGear.synchronize_with_ariane_dbs - start")
        while not self.to_be_sync:
            if print_wait:
                LOGGER.debug("DockerHostGear.synchronize_with_ariane_dbs - Waiting ariane sync order from ProcOS")
                print_wait = False
            time.sleep(1)
        self.to_be_sync = False
        self.call_from_component = False
        self.directory_gear.synchronize_with_ariane_directories(self.component)
        self.mapping_gear.synchronize_with_ariane_mapping(self.component)

    def init_with_ariane_dbs(self):
        LOGGER.debug("DockerHostGear.init_with_ariane_dbs - start")
        print_wait = True
        while not self.to_be_sync:
            if print_wait:
                LOGGER.info("DockerHostGear.init_with_ariane_dbs - Waiting ariane sync order from ProcOS")
                print_wait = False
            time.sleep(1)
        self.to_be_sync = False
        self.call_from_component = False
        self.directory_gear.init_ariane_directories(self.component).get()
        self.mapping_gear.init_ariane_mapping(self.component).get()
        LOGGER.debug("DockerHostGear.init_with_ariane_dbs - Synchonize with Ariane DBs...")
        self.directory_gear.synchronize_with_ariane_directories(self.component).get()
        self.mapping_gear.synchronize_with_ariane_mapping(self.component).get()
        self.component.set_docker_gear_ready().get()
        LOGGER.debug("DockerHostGear.init_with_ariane_dbs - done")

    def on_msg(self, msg):
        LOGGER.debug("DockerHostGear.on_msg - message received : " + str(msg))
        if self.call_from_component:
            self.to_be_sync = True
        else:
            # If a message is lost this could happen and result on bad sync between ProcOS and Docker plugin
            # => wait next round for good sync
            LOGGER.warn("DockerHostGear.on_msg - message receiver before component call to sync... ignore")

    def on_start(self):
        LOGGER.debug("DockerHostGear.on_start")
        args_driver = {'type': 'Z0MQ'}
        args_receptor = {
            'topic': "domino_ariane_sync",
            'treatment_callback': self.on_msg,
            'subscriber_name': "Ariane Docker Plugin Mapping Gear"
        }
        self.domino_receptor = DominoReceptor(args_driver, args_receptor)
        self.cache(running=self.running)
        self.init_with_ariane_dbs()
        self.running = True
        self.cache(running=self.running)

    def on_stop(self):
        LOGGER.debug("DockerHostGear.on_stop")
        try:
            self.domino_receptor.stop()
            if self.running:
                self.running = False
                self.cache(running=self.running)
            self.component.stop().get()
            self.directory_gear.stop().get()
            self.mapping_gear.stop().get()
            self.cached_gear_actor.remove().get()
        except Exception as e:
            LOGGER.error(e.__str__())
            LOGGER.debug(traceback.format_exc())

    def gear_start(self):
        LOGGER.debug("DockerHostGear.gear_start")
        self.component.start().get()
        self.running = True
        self.cache(running=self.running)
        LOGGER.warning('docker_host_gear@' + str(DockerHostGear.hostname) + ' has been restarted')

    def gear_stop(self):
        LOGGER.debug("DockerHostGear.gear_stop")
        if self.running:
            LOGGER.warning('docker_host_gear@' + str(DockerHostGear.hostname) + ' has been stopped')
            self.running = False
            self.cache(running=self.running)
            self.component.stop().get()
