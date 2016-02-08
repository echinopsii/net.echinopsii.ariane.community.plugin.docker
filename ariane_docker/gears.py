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
from ariane_clip3.directory import OSInstanceService, RoutingAreaService, SubnetService, NICardService, IPAddressService, \
    TeamService, Team, EnvironmentService, Environment, OSInstance, OSTypeService, CompanyService, Company, OSType, \
    IPAddress, NICard
from ariane_clip3.injector import InjectorGearSkeleton
import time
import sys
from ariane_clip3.mapping import ContainerService, Container, NodeService, Node, EndpointService
from ariane_procos.system import NetworkInterfaceCard
from components import DockerComponent
from docker import DockerContainer

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

    @staticmethod
    def sync_docker_networks(docker_host):
        # CREATION AND REMOVAL OF DOCKER NETWORK ARE DONE BY ARIANE PROCOS PLUGIN
        for docker_network in docker_host.networks:
            if docker_network in docker_host.new_networks and docker_network.bridge_name is not None:
                #SYNC NIC HOLDING THE SUBNET BRIDGE
                nic_name = docker_network.bridge_name + '.' + DockerHostGear.hostname
                nic = NICardService.find_niCard(nic_name=nic_name)
                if nic is not None:
                    docker_network.nic_id = nic.id
                    docker_network.nic = nic
                    #SYNC SUBNET
                    ip_address = IPAddressService.find_ip_address(ipa_id=nic.nic_ipa_id)
                    subnet = SubnetService.find_subnet(sb_name=ip_address.ipa_subnet_id)
                    if subnet is not None:
                        docker_network.subnet_id = subnet.id
                        docker_network.subnet = subnet
                    else:
                        LOGGER.warning('docker subnet for nic ' + nic_name + ' not found in Ariane directories !')
                else:
                    LOGGER.warning(nic_name + ' NIC not found in Ariane directories !')

    @staticmethod
    def sync_docker_containers(docker_host):
        for docker_container in docker_host.new_containers:
            team_from_conf = docker_container.extract_team_from_env_vars()
            if team_from_conf is not None:
                team_from_ariane = TeamService.find_team(team_name=team_from_conf[DockerContainer.ariane_team_name])
                if team_from_ariane is None:
                    team_from_ariane = Team(
                        name=team_from_conf[DockerContainer.ariane_team_name],
                        color_code=team_from_conf[DockerContainer.ariane_team_cc],
                        description=team_from_conf[DockerContainer.ariane_team_desc]
                    )
                    team_from_ariane.save()
                docker_container.team = team_from_ariane
                docker_container.tid = team_from_ariane.id
            else:
                LOGGER.warning("Team is not specified in the docker container ( " + docker_container.name +
                               " ) environment variables !")

            env_from_conf = docker_container.extract_env_from_env_vars()
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
                    env_from_ariane.save()
                docker_container.environment = env_from_ariane
                docker_container.eid = env_from_ariane.id
            else:
                LOGGER.warning("Environment is not specified in the docker container ( " + docker_container.name +
                               " ) environment variables !")

            ost_from_conf = docker_container.extract_os_type_from_env_vars()
            if ost_from_conf is not None:
                ost_from_ariane = OSTypeService.find_ostype(ost_name=ost_from_conf[DockerContainer.ariane_ost_name])
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

            for nic in docker_container.nics:
                for docker_network in docker_host.networks:
                    if docker_network.subnet is None and docker_network.subnet_id is not None:
                        docker_network.subnet = SubnetService.find_subnet(sb_name=docker_network.subnet_id)

                    if docker_network.subnet is not None:
                        if NetworkInterfaceCard.ip_is_in_subnet(nic.ipv4_address,
                                                                docker_network.subnet.ip, docker_network.subnet.mask):
                            ip_address = IPAddressService.find_ip_address(ipa_ip_address=nic.ipv4_address,
                                                                          ipa_subnet_id=docker_network.subnet.id)
                            if ip_address is None:
                                ip_address = IPAddress(ip_address=nic.ipv4_address, fqdn=nic.ipv4_fqdn,
                                                       ipa_subnet_id=docker_network.subnet.id,
                                                       ipa_osi_id=osi_from_ariane.id)
                                ip_address.save()
                                docker_network.subnet.sync()
                            else:
                                if ip_address.ipa_os_instance_id != osi_from_ariane.id:
                                    ip_address.ipa_os_instance_id = osi_from_ariane.id
                                    ip_address.save()

                            if (nic.mac_address is None or not nic.mac_address) or nic.name == "lo":
                                nicmcaddr = nic.ipv4_fqdn
                            else:
                                nicmcaddr = nic.mac_address

                            if nicmcaddr is not None and nicmcaddr:
                                nic2save = NICardService.find_niCard(nic_mac_Address=nicmcaddr)
                                if nic2save is None:
                                    nic2save = NICard(
                                        name=docker_container.fqdn+"."+nic.name,
                                        macAddress=nicmcaddr,
                                        duplex=nic.duplex,
                                        speed=nic.speed,
                                        mtu=nic.mtu,
                                        nic_osi_id=osi_from_ariane.id,
                                        nic_ipa_id=ip_address.id if ip_address is not None else None
                                    )
                                else:
                                    nic2save.nic_ipa_id = ip_address.id if ip_address is not None else None
                                nic2save.save()

            osi_from_ariane.sync()
            docker_container.oid = osi_from_ariane.id
            docker_container.osi = osi_from_ariane

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
                pass

    def update_ariane_directories(self, docker_host):
        if docker_host.networks != docker_host.last_networks:
            self.sync_docker_networks(docker_host)
        if docker_host.containers != docker_host.last_containers:
            self.sync_docker_containers(docker_host)

    def init_ariane_directories(self, component):
        docker_host = component.docker_host.get()
        self.sync_docker_host_osi(docker_host)
        self.sync_docker_host_lra(docker_host)

    def synchronize_with_ariane_directories(self, component):
        if self.running:
            docker_host = component.docker_host.get()
            self.update_ariane_directories(docker_host)
            self.update_count += 1
        else:
            LOGGER.warn("Synchronization requested but docker_directory_gear@" + str(DockerHostGear.hostname) +
                        " is not running.")


class MappingGear(InjectorGearSkeleton):

    docker_host_mco = None

    def __init__(self):
        super(MappingGear, self).__init__(
            gear_id='ariane.community.plugin.docker.gears.cache.mapping_gear@' + str(DockerHostGear.hostname),
            gear_name='docker_mapping_gear@' + str(DockerHostGear.hostname),
            gear_description='Ariane Docker injector gear for ' + str(DockerHostGear.hostname),
            gear_admin_queue='ariane.community.plugin.docker.gears.cache.mapping_gear@' + str(DockerHostGear.hostname),
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
        LOGGER.warning('docker_mapping_gear@' + str(DockerHostGear.hostname) + ' has been started.')
        self.on_start()

    def gear_stop(self):
        if self.running:
            LOGGER.warning('docker_mapping_gear@' + str(DockerHostGear.hostname) + ' has been stopped.')
            self.running = False
            self.cache(running=self.running)

    @staticmethod
    def synchronize_new_map_socket(docker_container, process, map_socket):
        if map_socket.source_ip is not None and map_socket.source_port is not None:
            proto = None
            if map_socket.type == "SOCK_STREAM":
                proto = "tcp://"
            elif map_socket.type == "SOCK_DGRAM":
                proto = "udp://"
            else:
                LOGGER.warning("socket type " + map_socket.type + " currently not supported !")

            if proto is not None:
                process_mid = process.mdpid
                source_url = proto + map_socket.source_ip + ":" + str(map_socket.source_port)

                #TEST IF LOCAL SOCKET
                is_local = True
                if is_local:
                    pass
                else:
                    #TEST IF INSIDE DOCKER HOST
                    is_inside_docker_host = True
                    if is_inside_docker_host:
                        pass
                    else:
                        pass
                    pass
                pass
        else:
            LOGGER.warning('no source ip / port - ' + str(map_socket))

    @staticmethod
    def synchronize_removed_map_socket(docker_container, process, map_socket):
        if map_socket.source_endpoint_id is not None:
            source_endpoint = EndpointService.find_endpoint(eid=map_socket.source_endpoint_id)
            if source_endpoint is not None:
                source_endpoint.remove()
            else:
                LOGGER.warn("Dead socket (source endpoint : " + str(map_socket.source_endpoint_id) +
                            ") doesn't exist anymore on DB!")

        if map_socket.destination_endpoint_id is not None:
            destination_endpoint = EndpointService.find_endpoint(eid=map_socket.destination_endpoint_id)
            if destination_endpoint is not None:
                destination_endpoint.remove()
            else:
                LOGGER.warn("Dead socket (destination endpoint : " + str(map_socket.source_endpoint_id) +
                            ") doesn't exist anymore on DB!")

    @staticmethod
    def synchronize_process_sockets(docker_container, process):
        for map_socket in process.map_sockets:
            if map_socket in process.new_map_sockets:
                MappingGear.synchronize_new_map_socket(docker_container, process, map_socket)
        for map_socket in process.last_map_sockets:
            if map_socket not in process.map_sockets:
                MappingGear.synchronize_removed_map_socket(docker_container, process, map_socket)

    @staticmethod
    def synchronize_process_properties(docker_container, process):
        #TODO
        pass

    @staticmethod
    def synchronize_existing_processs_node(docker_container, process):
        mapping_container = docker_container.mcontainer
        #SYNC PROCESS PROPERTIES

    @staticmethod
    def synchronize_new_processs_node(docker_container, process):
        mapping_container = docker_container.mcontainer
        process.mcid = mapping_container.id

        mosp = None
        MappingGear.docker_host_mco.sync()
        #TODO : provide find_node(name_pattern=...) to improve following source
        for docker_host_mpid in MappingGear.docker_host_mco.nodes_id:
            node_to_test = NodeService.find_node(nid=docker_host_mpid)
            if node_to_test is not None and node_to_test.name.startswith('[' + str(process.pid) + ']'):
                mosp = node_to_test
                break

            if mosp is not None:
                process_node = Node(
                    name=mosp.name,
                    container_id=process.mcid
                )
                process.mdpid = process_node.id
                process.msp = process_node
                process.mospid = mosp.id
                process.mos = mosp
            else:
                LOGGER.warning("Shadow Mapping OS node for process " + str(process.pid) + " not found !")

    @staticmethod
    def synchronize_removed_processs_node(docker_container, process):
        mapping_container = docker_container.mcontainer
        process_node = NodeService.find_node(nid=process.mdpid)
        if process_node is not None:
            process_node.remove()
        else:
            LOGGER.warning("Mapping node for process " + process.pid + "@" + mapping_container.name +
                           " not found !")

    @staticmethod
    def synchronize_container_processs(docker_container):
        # SYNC EXISTING/NEW PROCESSES NODES
        for process in docker_container.processs:
            if process in docker_container.new_processs:
                MappingGear.synchronize_new_processs_node(docker_container, process)
            elif process in docker_container.last_processs:
                MappingGear.synchronize_existing_processs_node(docker_container, process)
        # SYNC PROCESSES SOCKETS
        for process in docker_container.processs:
            MappingGear.synchronize_process_sockets(docker_container, process)
        # SYNC DEAD PROCESSES
        for process in docker_container.last_processs:
            if process not in docker_container.processs:
                MappingGear.synchronize_removed_processs_node(docker_container, process)

    @staticmethod
    def synchronize_container_properties(docker_container, mapping_container):
        #TODO
        pass

    @staticmethod
    def synchronize_existing_containers(docker_host):
        for docker_container in docker_host.containers:
            if docker_container not in docker_host.new_containers:
                mapping_container = Container(
                    name=docker_container.name,
                    gate_uri=DockerHostGear.docker_host_osi.admin_gate_uri + '/$[docker exec -i -t ' +
                             docker_container.name + ' /bin/bash]',
                    primary_admin_gate_name='NamespaceAccess@'+docker_container.name,
                    parent_container_id=MappingGear.docker_host_mco.id,
                    company="Docker Inc.",     #TODO: ADD DOCKER CONTAINER ENV VAR
                    product="Docker Container",#TODO: ADD DOCKER CONTAINER ENV VAR
                    c_type="Docker Container"
                )
                mapping_container.save()
                docker_container.mid = mapping_container.id
                docker_container.mcontainer = mapping_container
                MappingGear.synchronize_container_properties(docker_container)
                MappingGear.synchronize_container_processs(docker_container)

    @staticmethod
    def synchronize_new_containers(docker_host):
        for docker_container in docker_host.containers:
            if docker_container in docker_host.new_containers:
                pass

    @staticmethod
    def synchronize_removed_containers(docker_host):
        for docker_container in docker_host.last_containers:
            if docker_container not in docker_host.containers:
                if docker_container.mid is None:
                    mapping_container = ContainerService.find_container(
                        primary_admin_gate_url=DockerHostGear.docker_host_osi.admin_gate_uri + '/$[docker exec -i -t ' +
                                               docker_container.name + ' /bin/bash]'
                    )
                    if mapping_container is not None:
                        docker_container.mid = mapping_container.id
                else:
                    mapping_container = ContainerService.find_container(cid=docker_container.mid)

                if mapping_container is not None:
                    mapping_container.remove()
                else:
                    LOGGER.warning("No mapping container found for removed docker container " +
                                   str(docker_container.name) + " !")

    @staticmethod
    def init_ariane_mapping():
        docker_host_mco = ContainerService.find_container(
            primary_admin_gate_url=DockerHostGear.docker_host_osi.admin_gate_uri
        )
        if docker_host_mco is None:
            LOGGER.error('Docker host ' + str(DockerHostGear.hostname) +
                         ' Ariane container not found in Ariane mapping DB')
            LOGGER.error('Did you run Ariane ProcOS on this host first ? Stopping ...')
            sys.exit(-1)

    def synchronize_with_ariane_mapping(self, component):
        if self.running:
            docker_host = component.docker_host.get()
            try:
                self.synchronize_existing_containers(docker_host)
                self.synchronize_new_containers(docker_host)
                self.synchronize_removed_containers(docker_host)
            except Exception as e:
                LOGGER.error(e.__str__())
                LOGGER.error(traceback.format_exc())
            self.update_count += 1
        else:
            LOGGER.warn('Synchronization requested but docker_mapping_gear@' +
                        str(DockerHostGear.hostname) + ' is not running.')


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
            gear_id='ariane.community.plugin.docker.gears.cache.docker_host_gear@' + str(DockerHostGear.hostname),
            gear_name='docker_host_gear@' + str(DockerHostGear.hostname),
            gear_description='Ariane Docker Host gear for ' + str(DockerHostGear.hostname),
            gear_admin_queue='ariane.community.plugin.docker.gears.cache.docker_host_gear@' +
                             str(DockerHostGear.hostname),
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
        self.mapping_gear.init_ariane_mapping().get()
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
            LOGGER.warn('docker_host_gear@' + str(DockerHostGear.hostname) + ' has been restarted')
            self.on_start()

    def gear_stop(self):
        if self.running:
            LOGGER.warn('docker_host_gear@' + str(DockerHostGear.hostname) + ' has been stopped')
            self.running = False
            self.cache(running=self.running)
