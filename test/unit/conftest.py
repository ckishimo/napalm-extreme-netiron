"""Test fixtures."""
from __future__ import print_function
from __future__ import unicode_literals

from builtins import super

import pytest
import json

from napalm_base.test import conftest as parent_conftest

from napalm_base.test.double import BaseTestDouble
from napalm_base.utils import py23_compat

from napalm_netiron import netiron 

@pytest.fixture(scope='class')
def set_device_parameters(request):
    """Set up the class."""
    def fin():
        request.cls.device.close()
    request.addfinalizer(fin)

    request.cls.driver = netiron.NetironDriver
    request.cls.patched_driver = PatchedNetironDriver
    request.cls.vendor = 'netiron'
    parent_conftest.set_device_parameters(request)

def pytest_generate_tests(metafunc):
    """Generate test cases dynamically."""
    parent_conftest.pytest_generate_tests(metafunc, __file__)


class PatchedNetironDriver(netiron.NetironDriver):
    """Patched Netiron Driver."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Patched Netiron Driver constructor."""
        super().__init__(hostname, username, password, timeout, optional_args)

        self.patched_attrs = ['device']
        self.device = FakeNetironDevice()

    def disconnect(self):
        pass

    def is_alive(self):
        return {
            'is_alive': True  # In testing everything works..
        }

    def open(self):
        pass


class FakeNetironDevice(BaseTestDouble):
    """Netiron device test double."""

    def send_command(self, command, **kwargs):
        filename = '{}.txt'.format(self.sanitize_text(command))
        full_path = self.find_file(filename)
        result = self.read_txt_file(full_path)
        return result
        #return py23_compat.text_type(result)

    def disconnect(self):
        pass

    def run_commands(self, command_list, encoding='json'):
        """Fake run_commands."""
        result = list()

        for command in command_list:
            filename = '{}.{}'.format(self.sanitize_text(command), encoding)
            full_path = self.find_file(filename)

            if encoding == 'json':
                result.append(self.read_json_file(full_path))
            else:
                result.append({'output': self.read_txt_file(full_path)})

        return result
