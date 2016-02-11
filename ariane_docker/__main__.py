# Ariane Docker plugin
# main
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
import argparse
import json
import logging
import logging.config
import socket
import signal
import time
from ariane_docker.config import Config


__author__ = 'mffrench'

ariane_connector = None
config_path = "/etc/ariane/adocker_configuration.json"
ariane_docker_config = None
docker_host_gear = None


def shutdown_handle(signum, frame):
    LOGGER.info("Ariane Docker@" + socket.gethostname() + " is stopping...")
    if docker_host_gear is not None:
        docker_host_gear.stop().get()
    if ariane_connector is not None:
        time.sleep(5)
        ariane_connector.stop()
    LOGGER.info("Ariane Docker@" + socket.gethostname() + " is stopped...")

parser = argparse.ArgumentParser()
parser.add_argument("-c", "--configuration",
                    help="define your Ariane Docker configuration file path")
args = parser.parse_args()

if args.configuration:
    config_path = args.configuration

try:
    ariane_docker_config = Config().parse(config_path)
except Exception as e:
    print('Ariane Docker plugin config issue: ' + e.__str__())
    exit(1)

try:
    with open(ariane_docker_config.log_conf_file_path, 'rt') as f:
        log_conf = json.load(f)
    logging.config.dictConfig(log_conf)
except Exception as e:
    print("Error while loading configuration file: " + e.__str__())
    logging.basicConfig(format='[%(levelname)s]%(asctime)s - %(name)s - %(message)s', level=logging.WARN)

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)

from ariane_docker.connector import ArianeConnector
from ariane_docker.connector import DockerConnector
from ariane_docker.gears import DockerHostGear

if ariane_docker_config is not None:
    ariane_connector = ArianeConnector(ariane_docker_config)
    docker_connector = DockerConnector(ariane_docker_config)
    if ariane_connector.ready:
        signal.signal(signal.SIGINT, shutdown_handle)
        signal.signal(signal.SIGTERM, shutdown_handle)
        docker_host_gear = DockerHostGear.start(config=ariane_docker_config, cli=docker_connector.cli).proxy()
        LOGGER.info("Ariane Docker@" + socket.gethostname() + " is started...")
        signal.pause()
