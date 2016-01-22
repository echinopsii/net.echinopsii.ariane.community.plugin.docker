from pprint import pprint
import unittest
from acceptance.docker_test_tools import DockerTestTools
from config import Config
from connector import DockerConnector
from system import DockerHost

__author__ = 'mffrench'

class DockerConnectorTest(unittest.TestCase):

    def setUp(self):
        self.config = Config().parse("valid_conf.json")
        self.docker_connector = DockerConnector(self.config)
        self.docker_test_tool = DockerTestTools(self.docker_connector.cli)
        self.docker_test_tool.bootstrap_test_container()

    def tearDown(self):
        self.docker_test_tool.clean_test_container()

    def test_docker_host_sniff(self):
        docker_host = DockerHost(self.docker_connector.cli)
        docker_host.sniff()
        pprint(docker_host.to_json())
