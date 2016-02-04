from ariane_docker.docker import DockerContainer

__author__ = 'mffrench'

class DockerTestTools(object):
    def __init__(self, cli):
        self.cli = cli
        self.test_container = None

    def bootstrap_test_container(self):
        self.test_container = self.cli.create_container(
            name="ariane_docker_ctest",
            hostname="ariane_docker_ctest",
            environment={
                "MYSQL_ROOT_PASSWORD": "YHN444rty",
                DockerContainer.ariane_ost_name: "Linux Debian 8",
                DockerContainer.ariane_ost_arc: "x86_64",
                DockerContainer.ariane_ost_scmp_name: "Debian Community",
                DockerContainer.ariane_ost_scmp_desc: "Debian",
                DockerContainer.ariane_team_name: "TSTdev",
                DockerContainer.ariane_team_cc: "000000",
                DockerContainer.ariane_team_desc: "TST DEV",
                DockerContainer.ariane_environment_name: "TEST",
                DockerContainer.ariane_environment_cc: "333333",
                DockerContainer.ariane_environment_desc: "TEST ENV"
            },
            detach=True,
            image="mariadb"
        )
        self.cli.start(self.test_container['Id'])

    def clean_test_container(self):
        self.cli.stop(self.test_container['Id'])
        self.cli.remove_container(self.test_container['Id'])
