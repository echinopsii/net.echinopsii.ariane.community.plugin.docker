import unittest
from config import Config
from ariane_docker import exceptions

__author__ = 'mffrench'

class ConfigurationTest(unittest.TestCase):

    def test_bad_conf_file(self):
        try:
            Config().parse("some_unknown_file")
        except exceptions.ArianeDockerConfigFileError:
            pass
        except Exception as e:
            self.fail('unexpected exception thrown: ' + str(e))
        else:
            self.fail('no exception thrown')

    def test_ariane_good_conf_01(self):
        try:
            config = Config().parse("valid_conf_01.json")
        except Exception as e:
            self.fail('unexpected exception thrown: ' + str(e))
        else:
            pass

    def test_ariane_good_conf_02(self):
        try:
            config = Config().parse("valid_conf_02.json")
        except Exception as e:
            self.fail('unexpected exception thrown: ' + str(e))
        else:
            pass

    def test_ariane_server_not_in_conf_file(self):
        try:
            Config().parse("invalid_conf_10.json")
        except exceptions.ArianeDockerConfigMandatorySectionMissingError:
            pass
        except Exception as e:
            self.fail('unexpected exception thrown: ' + str(e))
        else:
            self.fail('no exception thrown')

    def test_ariane_server_missing_mandatory_fields(self):
        try:
            Config().parse("invalid_conf_11.json")
        except exceptions.ArianeDockerConfigMandatoryFieldsMissingError:
            pass
        except Exception as e:
            self.fail('unexpected exception thrown: ' + str(e))
        else:
            self.fail('no exception thrown')

        try:
            Config().parse("invalid_conf_12.json")
        except exceptions.ArianeDockerConfigMandatoryFieldsMissingError:
            pass
        except Exception as e:
            self.fail('unexpected exception thrown: ' + str(e))
        else:
            self.fail('no exception thrown')