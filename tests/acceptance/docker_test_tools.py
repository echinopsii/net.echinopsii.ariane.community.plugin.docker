__author__ = 'mffrench'

class DockerTestTools(object):
    def __init__(self, cli):
        self.cli = cli
        self.test_container = None

    def bootstrap_test_container(self):
        self.test_container = self.cli.create_container(
            name="ariane_docker_ctest",
            hostname="ariane_docker_ctest",
            environment={"MYSQL_ROOT_PASSWORD": "YHN444rty"},
            detach=True,
            image="mariadb"
        )
        self.cli.start(self.test_container['Id'])

    def clean_test_container(self):
        self.cli.stop(self.test_container['Id'])
        self.cli.remove_container(self.test_container['Id'])
