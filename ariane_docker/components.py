# Ariane Docker plugin
# Docker component
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
from ariane_clip3.injector import InjectorComponentSkeleton

__author__ = 'mffrench'


LOGGER = logging.getLogger(__name__)

class DockerComponent(InjectorComponentSkeleton):

    def __init__(self):
        pass

    def data_blob(self):
        pass

    def sniff(self):
        pass
