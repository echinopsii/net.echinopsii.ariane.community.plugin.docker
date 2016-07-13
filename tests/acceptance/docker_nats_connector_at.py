import os
from pprint import pprint
import unittest
from tests.acceptance.docker_test_tools import DockerTestTools
from ariane_docker.config import Config
from ariane_docker.connector import DockerConnector
from ariane_docker.docker import DockerHost

__author__ = 'mffrench'

class DockerConnectorTest(unittest.TestCase):

    def setUp(self):
        self.config = Config().parse(os.path.dirname(__file__) + os.sep + "valid_nats_conf.json")
        self.docker_connector = DockerConnector(self.config)
        self.docker_test_tool = DockerTestTools(self.docker_connector.cli)
        self.docker_test_tool.bootstrap_test_container()

    def tearDown(self):
        self.docker_test_tool.clean_test_container()

    def test_docker_host_sniff(self):
        docker_host = DockerHost()
        docker_host.sniff(self.docker_connector.cli)
        pprint(docker_host.to_json())
