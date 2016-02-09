# Ariane Docker plugin
# Docker config
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
import configparser
import json
import os
from ariane_docker import exceptions

__author__ = 'mffrench'


class Config(object):
    def __init__(self):
        self.rest_base_url = None
        self.rest_user = None
        self.rest_password = None

        self.rbmq_host = None
        self.rbmq_port = None
        self.rbmq_user = None
        self.rbmq_password = None
        self.rbmq_vhost = None

        self.sleeping_period = 20
        self.log_conf_file_path = "/etc/ariane/adocker_logging.json"

        self.docker_client_url = 'unix://var/run/docker.sock'
        self.docker_client_version = 'auto'
        self.docker_client_timeout = 0
        self.docker_client_tls = False

        #List of possible locations this OS instance could be located with routing area and subnets
        #(labtop of VM which can move through an hypervisor)

    def parse(self, config_file):
        if not os.path.isfile(config_file):
            raise exceptions.ArianeDockerConfigFileError(config_file)

        config_file = open(config_file, 'r')
        config = json.load(config_file)

        ariane_server_missing_fields = []
        if 'ariane_server' in config:
            self.rest_base_url = config['ariane_server']['rest_base_url']
            if self.rest_base_url is None or not self.rest_base_url:
                ariane_server_missing_fields.append('rest_base_url')

            self.rest_user = config['ariane_server']['rest_user']
            if self.rest_user is None or not self.rest_user:
                ariane_server_missing_fields.append('rest_user')

            self.rest_password = config['ariane_server']['rest_password']
            if self.rest_password is None or not self.rest_password:
                ariane_server_missing_fields.append('rest_password')

            self.rbmq_host = config['ariane_server']['rbmq_host']
            if self.rbmq_host is None or not self.rbmq_host:
                ariane_server_missing_fields.append('rbmq_host')

            self.rbmq_port = config['ariane_server']['rbmq_port']
            if self.rbmq_port is None or not self.rbmq_port:
                ariane_server_missing_fields.append('rbmq_port')

            self.rbmq_user = config['ariane_server']['rbmq_user']
            if self.rbmq_user is None or not self.rbmq_user:
                ariane_server_missing_fields.append('rbmq_user')

            self.rbmq_password = config['ariane_server']['rbmq_password']
            if self.rbmq_password is None or not self.rest_password:
                ariane_server_missing_fields.append('rbmq_password')

            self.rbmq_vhost = config['ariane_server']['rbmq_vhost']
            if self.rbmq_vhost is None or not self.rbmq_vhost:
                ariane_server_missing_fields.append('rbmq_vhost')
        else:
            raise exceptions.ArianeDockerConfigMandatorySectionMissingError('ariane_server')

        if 'ariane_docker' in config:
            if 'sleeping_period' in config['ariane_docker'] and config['ariane_docker']['sleeping_period']:
                self.sleeping_period = config['ariane_docker']['sleeping_period']
            if 'client_url' in config['ariane_docker'] and config['ariane_docker']['client_url']:
                self.docker_client_url = config['ariane_docker']['client_url']
            if 'log_conf_file_path' in config['ariane_docker'] and config['ariane_docker']['log_conf_file_path']:
                self.log_conf_file_path = config['ariane_docker']['log_conf_file_path']

        if ariane_server_missing_fields.__len__() > 0:
            raise exceptions.ArianeDockerConfigMandatoryFieldsMissingError(ariane_server_missing_fields)

        return self
