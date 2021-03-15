# Copyright 2019 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import mock

import reactive.ovn_chassis_charm_handlers as handlers

import charms_openstack.test_utils as test_utils


class TestRegisteredHooks(test_utils.TestRegisteredHooks):

    def test_hooks(self):
        defaults = [
            'charm.installed',
            'config.changed',
            'config.rendered',
            'charm.default-select-release',
            'update-status',
            'upgrade-charm',
            'certificates.available',
        ]
        hook_set = {
            'when': {
                'amqp_connection': (
                    handlers.OVN_CHASSIS_ENABLE_HANDLERS_FLAG,
                    'amqp.connected',),
                'enable_chassis_reactive_code': (
                    handlers.OVN_CHASSIS_ENABLE_HANDLERS_FLAG,),
                'configure_ovs': (
                    handlers.OVN_CHASSIS_ENABLE_HANDLERS_FLAG,
                    'ovsdb.available',
                    'certificates.available'),
                'disable_openstack': (
                    handlers.OVN_CHASSIS_ENABLE_HANDLERS_FLAG,),
                'enable_openstack': (
                    handlers.OVN_CHASSIS_ENABLE_HANDLERS_FLAG,
                    'nova-compute.connected',),
                'ensure_networking_tools_installed': (
                    handlers.OVN_CHASSIS_ENABLE_HANDLERS_FLAG,
                    'config.changed.enable-hardware-offload',),
                'configure_bridges': (
                    handlers.OVN_CHASSIS_ENABLE_HANDLERS_FLAG,
                    'config.rendered',),
                'pause_unit_from_config': (
                    handlers.OVN_CHASSIS_ENABLE_HANDLERS_FLAG,
                    'config.set.new-units-paused'),
                'configure_nrpe': (
                    handlers.OVN_CHASSIS_ENABLE_HANDLERS_FLAG,
                    'config.rendered',),
            },
            'when_none': {
                'amqp_connection': ('charm.paused', 'is-update-status-hook'),
                'disable_openstack': (
                    'charm.paused',
                    'is-update-status-hook',
                    'nova-compute.connected',),
                'enable_openstack': ('charm.paused', 'is-update-status-hook'),
                'ensure_networking_tools_installed': (
                    'charm.paused',
                    'is-update-status-hook'),
                'configure_bridges': (
                    'charm.paused',
                    'is-update-status-hook'),
                'configure_ovs': ('charm.paused', 'is-update-status-hook'),
                'pause_unit_from_config': ('charm.installed', 'charm.paused'),
                'configure_nrpe': (
                    'charm.paused',
                    'is-update-status-hook',),
            },
            'when_any': {
                'configure_bridges': (
                    'config.changed.ovn-bridge-mappings',
                    'config.changed.bridge-interface-mappings',
                    'run-default-upgrade-charm',),
                'configure_nrpe': (
                    'config.changed.nagios_context',
                    'config.changed.nagios_servicegroups',
                    'endpoint.nrpe-external-master.changed',
                    'nrpe-external-master.available'),
            },
        }
        # test that the hooks were registered via the
        # reactive.ovn_handlers
        handlers.enable_chassis_reactive_code()
        self.registered_hooks_test_helper(handlers, hook_set, defaults)


class TestOvnHandlers(test_utils.PatchHelper):

    def setUp(self):
        super().setUp()
        self.charm = mock.MagicMock()
        self.patch_object(handlers.charm, 'provide_charm_instance',
                          new=mock.MagicMock())
        self.provide_charm_instance().__enter__.return_value = \
            self.charm
        self.provide_charm_instance().__exit__.return_value = None

    def test_amqp_connection(self):
        self.patch_object(handlers.reactive, 'endpoint_from_flag')
        amqp = mock.MagicMock()
        self.endpoint_from_flag.return_value = amqp
        handlers.amqp_connection()
        amqp.request_access.assert_called_once_with(
            username='neutron', vhost='openstack')
        self.charm.assess_status.assert_called_once_with()

    def test_disable_openstack(self):
        self.patch_object(handlers.reactive, 'clear_flag')
        handlers.disable_openstack()
        self.clear_flag.assert_called_once_with(
            'charm.ovn-chassis.enable-openstack')

    def test_enable_openstack(self):
        self.patch_object(handlers.reactive, 'endpoint_from_flag')
        self.patch_object(handlers.reactive, 'set_flag')
        nova_compute = mock.MagicMock()
        self.endpoint_from_flag.return_value = nova_compute
        handlers.enable_openstack()
        self.set_flag.assert_called_once_with(
            'charm.ovn-chassis.enable-openstack')
        nova_compute.publish_shared_secret.assert_called_once_with()
        self.charm.install.assert_called_once_with()
        self.charm.assess_status.assert_called_once_with()

    def test_configure_ovs(self):
        self.patch_object(handlers.reactive, 'endpoint_from_flag')
        self.patch_object(handlers.charm, 'optional_interfaces')
        self.patch_object(handlers.reactive, 'set_flag')
        self.patch_object(handlers.reactive, 'is_flag_set', return_value=True)
        ovsdb = mock.MagicMock()
        ovsdb.db_sb_connection_strs = [
            'ssl:192.0.2.11:6642',
            'ssl:192.0.2.12:6642',
            'ssl:192.0.2.13:6642',
        ]
        self.endpoint_from_flag.return_value = ovsdb
        handlers.configure_ovs()
        self.charm.configure_ovs.assert_called_once_with(
            ','.join(ovsdb.db_sb_connection_strs), True)
        self.charm.render_with_interfaces.assert_called_once_with(
            self.optional_interfaces((ovsdb,),
                                     'nova-compute.connected',
                                     'amqp.connected'))
        self.set_flag.assert_called_once_with('config.rendered')
        self.charm.assess_status.assert_called_once_with()

    def test_configure_nrpe(self):
        self.patch_object(handlers.reactive, 'endpoint_from_flag')
        self.endpoint_from_flag.return_value = 'nrpe-external-master'
        self.patch_object(handlers.charm, 'provide_charm_instance')
        handlers.configure_nrpe()
        self.provide_charm_instance.assert_has_calls([
            mock.call().__enter__().render_nrpe(),
        ])

    def test_pause_unit_from_config(self):
        handlers.pause_unit_from_config()
        self.charm.pause.assert_called_once_with()
        self.charm.assess_status.assert_called_once_with()
