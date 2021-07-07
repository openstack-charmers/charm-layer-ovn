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

import collections
import io
import unittest.mock as mock

import charms_openstack.charm.core as chm_core
import charms_openstack.test_utils as test_utils

import charms.ovn_charm as ovn_charm


class TestDeferredEventMixin(test_utils.PatchHelper):

    class FakeBaseClass():
        def install(self):
            return

        def configure_ovs(self, sb_conn, mlockall_changed):
            return

    class FakeCharm(ovn_charm.DeferredEventMixin, FakeBaseClass):

        @property
        def services(self):
            return ['mysvc']

    def setUp(self):
        super().setUp()
        self.charm_instance = self.FakeCharm()

    def test_deferable_services(self):
        self.assertEqual(
            self.charm_instance.deferable_services,
            [
                'ovn-host',
                'openvswitch-switch',
                'mysvc',
                'ovs-vswitchd',
                'ovsdb-server',
                'ovs-record-hostname',
                'ovn-controller'])

    def test_configure_deferred_restarts(self):
        self.patch_object(
            ovn_charm.ch_core.hookenv,
            'config',
            return_value={'enable-auto-restarts': True})
        self.patch_object(
            ovn_charm.ch_core.hookenv,
            'service_name',
            return_value='myapp')
        self.patch_object(
            ovn_charm.deferred_events,
            'configure_deferred_restarts')
        self.patch_object(ovn_charm.os, 'chmod')
        self.charm_instance.configure_deferred_restarts()
        self.configure_deferred_restarts.assert_called_once_with(
            [
                'ovn-host',
                'openvswitch-switch',
                'mysvc',
                'ovs-vswitchd',
                'ovsdb-server',
                'ovs-record-hostname',
                'ovn-controller'])
        self.chmod.assert_called_once_with(
            '/var/lib/charm/myapp/policy-rc.d',
            493)

    def test_configure_deferred_restarts_unsupported(self):
        self.patch_object(ovn_charm.ch_core.hookenv, 'config', return_value={})
        self.patch_object(
            ovn_charm.deferred_events,
            'configure_deferred_restarts')
        self.charm_instance.configure_deferred_restarts()
        self.assertFalse(self.configure_deferred_restarts.called)

    def test_custom_assess_status_check(self):
        event_mock1 = mock.MagicMock()
        event_mock1.service = 'serviceA'
        event_mock1.action = 'restart'
        event_mock2 = mock.MagicMock()
        event_mock2.service = 'serviceB'
        event_mock2.action = 'restart'
        self.patch_object(
            ovn_charm.deferred_events,
            'check_restart_timestamps')
        self.patch_object(ovn_charm.deferred_events, 'get_deferred_events')
        self.patch_object(ovn_charm.deferred_events, 'get_deferred_hooks')

        # Test restart but no hook
        self.get_deferred_events.return_value = [
            event_mock1,
            event_mock2]
        self.get_deferred_hooks.return_value = []
        self.assertEqual(
            self.charm_instance.custom_assess_status_check(),
            ('active', 'Services queued for restart: serviceA, serviceB'))

        # Test hook but no restarts
        self.get_deferred_events.return_value = []
        self.get_deferred_hooks.return_value = ['configure_ovs', 'install']
        self.assertEqual(
            self.charm_instance.custom_assess_status_check(),
            (
                'active',
                ('Hooks skipped due to disabled auto restarts: configure_ovs, '
                 'install')))

        # Test restart and hook
        self.get_deferred_events.return_value = [
            event_mock1,
            event_mock2]
        self.get_deferred_hooks.return_value = ['configure_ovs', 'install']
        self.assertEqual(
            self.charm_instance.custom_assess_status_check(),
            (
                'active',
                ('Services queued for restart: serviceA, serviceB. '
                 'Hooks skipped due to disabled auto restarts: '
                 'configure_ovs, install')))

        # Test no restart and no hook
        self.get_deferred_events.return_value = []
        self.get_deferred_hooks.return_value = []
        self.assertEqual(
            self.charm_instance.custom_assess_status_check(),
            (None, None))

    def test_configure_ovs(self):
        self.patch_object(ovn_charm.deferred_events, 'is_restart_permitted')
        self.patch_object(ovn_charm.deferred_events, 'clear_deferred_hook')
        self.patch_object(ovn_charm.deferred_events, 'set_deferred_hook')
        self.patch_object(ovn_charm.reactive.flags, 'is_flag_set')

        # Tests with restarts permitted
        self.clear_deferred_hook.reset_mock()
        self.is_flag_set.return_value = False
        self.is_restart_permitted.return_value = True
        self.charm_instance.configure_ovs(
            's_conn',
            'mlockall_changed',
            check_deferred_events=True)
        self.clear_deferred_hook.assert_called_once_with('configure_ovs')

        self.clear_deferred_hook.reset_mock()
        self.charm_instance.configure_ovs(
            's_conn',
            'mlockall_changed',
            check_deferred_events=False)
        self.clear_deferred_hook.assert_called_once_with('configure_ovs')

        # Tests with restarts not permitted
        self.clear_deferred_hook.reset_mock()
        self.is_restart_permitted.return_value = False
        self.charm_instance.configure_ovs(
            's_conn',
            'mlockall_changed',
            check_deferred_events=True)
        self.assertFalse(self.clear_deferred_hook.called)

        self.clear_deferred_hook.reset_mock()
        self.charm_instance.configure_ovs(
            's_conn',
            'mlockall_changed',
            check_deferred_events=False)
        self.clear_deferred_hook.assert_called_once_with('configure_ovs')

        # Tests with restarts not permitted from this hooks onwards.
        self.clear_deferred_hook.reset_mock()
        self.is_restart_permitted.return_value = False
        self.is_flag_set.return_value = True
        self.charm_instance.configure_ovs(
            's_conn',
            'mlockall_changed',
            check_deferred_events=True)
        self.clear_deferred_hook.assert_called_once_with('configure_ovs')

        self.clear_deferred_hook.reset_mock()
        self.charm_instance.configure_ovs(
            's_conn',
            'mlockall_changed',
            check_deferred_events=False)
        self.clear_deferred_hook.assert_called_once_with('configure_ovs')

    def test_install(self):
        self.patch_object(ovn_charm.deferred_events, 'is_restart_permitted')
        self.patch_object(ovn_charm.deferred_events, 'clear_deferred_hook')
        self.patch_object(ovn_charm.deferred_events, 'set_deferred_hook')
        self.patch_object(ovn_charm.reactive.flags, 'is_flag_set')

        # Tests with restarts permitted
        self.clear_deferred_hook.reset_mock()
        self.is_flag_set.return_value = False
        self.is_restart_permitted.return_value = True
        self.charm_instance.install(check_deferred_events=True)
        self.clear_deferred_hook.assert_called_once_with('install')

        self.clear_deferred_hook.reset_mock()
        self.charm_instance.install(check_deferred_events=False)
        self.clear_deferred_hook.assert_called_once_with('install')

        # Tests with restarts not permitted
        self.clear_deferred_hook.reset_mock()
        self.is_restart_permitted.return_value = False
        self.charm_instance.install(check_deferred_events=True)
        self.assertFalse(self.clear_deferred_hook.called)

        self.clear_deferred_hook.reset_mock()
        self.charm_instance.install(check_deferred_events=False)
        self.clear_deferred_hook.assert_called_once_with('install')

        # Tests with restarts not permitted from this hooks onwards.
        self.clear_deferred_hook.reset_mock()
        self.is_restart_permitted.return_value = False
        self.is_flag_set.return_value = True
        self.charm_instance.install(check_deferred_events=True)
        self.clear_deferred_hook.assert_called_once_with('install')

        self.clear_deferred_hook.reset_mock()
        self.charm_instance.install(check_deferred_events=False)
        self.clear_deferred_hook.assert_called_once_with('install')


class TestOVNConfigurationAdapter(test_utils.PatchHelper):

    def setUp(self):
        super().setUp()
        self.charm_instance = mock.MagicMock()
        self.charm_instance.ovn_sysconfdir.return_value = '/etc/path'
        self.patch('charmhelpers.contrib.openstack.context.DPDKDeviceContext',
                   name='DPDKDeviceContext')
        self.DPDKDeviceContext.return_value = lambda: {
            'devices': {
                'fakepci': 'fakeif',
            },
            'driver': 'fakedriver',
        }
        self.patch('charmhelpers.contrib.openstack.context.SRIOVContext',
                   name='SRIOVContext')
        m = mock.patch.object(ovn_charm.ch_core.hookenv, 'config')
        m.start()
        self.target = ovn_charm.OVNConfigurationAdapter(
            charm_instance=self.charm_instance)
        m.stop()
        setattr(self, 'config', None)

    def test_ovn_key(self):
        self.assertEquals(self.target.ovn_key, '/etc/path/key_host')

    def test_ovn_cert(self):
        self.assertEquals(self.target.ovn_cert, '/etc/path/cert_host')

    def test_ovn_ca_cert(self):
        self.charm_instance.name = mock.PropertyMock().return_value = 'name'
        self.assertEquals(self.target.ovn_ca_cert, '/etc/path/name.crt')

    def test_dpdk_device(self):
        self.assertDictEqual(self.target.dpdk_device.devices,
                             {'fakepci': 'fakeif'})
        self.assertEquals(self.target.dpdk_device.driver, 'fakedriver')

    def test_sriov_device(self):
        self.assertEquals(self.target.sriov_device, self.SRIOVContext())

    def _test_mlock_d(self, config_rv, container_rv, mlock_rv):
        hookenv = ovn_charm.ch_core.hookenv
        host = ovn_charm.ch_core.host

        self.patch_object(hookenv, 'config', return_value=config_rv)
        self.patch_object(host, 'is_container', return_value=container_rv)
        self.assertEquals(self.target.mlockall_disabled, mlock_rv)

    def test_mlockall_disabled_true(self):
        self._test_mlock_d(config_rv=True, container_rv=False, mlock_rv=True)

    def test_mlockall_disabled_false(self):
        self._test_mlock_d(config_rv=False, container_rv=False, mlock_rv=False)

    def test_mlockall_disabled_none_true(self):
        self._test_mlock_d(config_rv=None, container_rv=True, mlock_rv=True)

    def test_mlockall_disabled_none_false(self):
        self._test_mlock_d(config_rv=None, container_rv=False, mlock_rv=False)


class Helper(test_utils.PatchHelper):

    def setUp(self, release=None, is_flag_set_return_value=False, config=None):
        super().setUp()
        self.patch_release(release or 'ussuri')
        self.patch_object(ovn_charm.reactive, 'is_flag_set',
                          return_value=is_flag_set_return_value)
        self.patch_object(
            ovn_charm.charms_openstack.adapters, '_custom_config_properties')
        self._custom_config_properties.side_effect = {}
        self.patch('charmhelpers.contrib.openstack.context.DPDKDeviceContext',
                   name='DPDKDeviceContext')
        self.DPDKDeviceContext.return_value = lambda: {
            'devices': {
                'fakepci': 'fakeif',
            },
            'driver': 'fakedriver',
        }
        self.patch_object(ovn_charm.ch_core.hookenv, 'config')

        def _fake_config(x=None):
            cfg = config or {
                'enable-hardware-offload': False,
                'enable-sriov': False,
                'enable-dpdk': False,
                'bridge-interface-mappings': 'br-ex:eth0',
                'prefer-chassis-as-gw': False,
            }
            if x:
                return cfg.get(x)
            return cfg

        self.config.side_effect = _fake_config
        self.enable_openstack = mock.PropertyMock
        self.enable_openstack.return_value = False
        if release and release == 'train':
            self.target = ovn_charm.BaseTrainOVNChassisCharm()
            self.patch(
                'charms.ovn_charm.BaseTrainOVNChassisCharm.enable_openstack',
                new_callable=self.enable_openstack)
        else:
            self.target = ovn_charm.BaseUssuriOVNChassisCharm()
            self.patch(
                'charms.ovn_charm.BaseUssuriOVNChassisCharm.enable_openstack',
                new_callable=self.enable_openstack)
        # remove the 'is_flag_set' patch so the tests can use it
        self._patches['is_flag_set'].stop()
        setattr(self, 'is_flag_set', None)
        del(self._patches['is_flag_set'])
        del(self._patches_start['is_flag_set'])

        self.patch('charmhelpers.contrib.openstack.context.DPDKDeviceContext',
                   name='DPDKDeviceContext')
        self.DPDKDeviceContext.return_value = lambda: {
            'devices': {
                'fakepci': 'fakeif',
            },
            'driver': 'fakedriver',
        }

    def tearDown(self):
        super().tearDown()
        chm_core._release_selector_function = None
        chm_core._package_type_selector_function = None
        chm_core._releases = None
        chm_core._singleton = None

    def patch_target(self, attr, return_value=None):
        mocked = mock.patch.object(self.target, attr)
        self._patches[attr] = mocked
        started = mocked.start()
        started.return_value = return_value
        self._patches_start[attr] = started
        setattr(self, attr, started)


class TestTrainOVNChassisCharm(Helper):

    def setUp(self):
        super().setUp(release='train')
        self.enable_openstack.return_value = True

    def test_optional_openstack_metadata_train(self):
        self.assertEquals(self.target.packages, [
            'ovn-host', 'networking-ovn-metadata-agent', 'haproxy'
        ])
        self.assertEquals(self.target.services, [
            'ovn-host', 'networking-ovn-metadata-agent'])
        self.assertEquals(self.target.nrpe_check_services, [
            'ovn-host', 'ovs-vswitchd', 'ovsdb-server',
            'networking-ovn-metadata-agent'])


class TestUssuriOVNChassisCharm(Helper):

    def setUp(self):
        super().setUp()
        self.enable_openstack.return_value = True

    def test_optional_openstack_metadata_ussuri(self):
        self.assertEquals(self.target.packages, [
            'ovn-host', 'neutron-ovn-metadata-agent'
        ])
        self.assertEquals(self.target.services, [
            'ovn-host', 'neutron-ovn-metadata-agent'])
        self.assertDictEqual(self.target.restart_map, {
            '/etc/default/openvswitch-switch': [],
            '/etc/neutron/neutron_ovn_metadata_agent.ini': [
                'neutron-ovn-metadata-agent'],
            '/etc/openvswitch/system-id.conf': [],
        })
        self.assertEquals(self.target.nrpe_check_services, [
            'ovn-controller', 'ovs-vswitchd', 'ovsdb-server',
            'neutron-ovn-metadata-agent'])


class TestDPDKOVNChassisCharm(Helper):

    def setUp(self):
        super().setUp(config={
            'enable-hardware-offload': False,
            'enable-sriov': False,
            'enable-dpdk': True,
            'dpdk-bond-mappings': ('dpdk-bond0:a0:36:9f:dd:37:a4 '
                                   'dpdk-bond0:a0:36:9f:dd:3e:9c'),
            'bridge-interface-mappings': 'br-ex:eth0 br-data:dpdk-bond0',
            'ovn-bridge-mappings': (
                'provider:br-ex other:br-data'),
            'prefer-chassis-as-gw': False,
        })

    def test__init__(self):
        self.assertEquals(self.target.packages, [
            'ovn-host', 'openvswitch-switch-dpdk'])
        self.assertDictEqual(self.target.restart_map, {
            '/etc/default/openvswitch-switch': [],
            '/etc/dpdk/interfaces': ['dpdk'],
            '/etc/openvswitch/system-id.conf': [],
        })

    def test_configure_bridges(self):
        self.patch_object(ovn_charm.os_context, 'BridgePortInterfaceMap')
        dict_bpi = {
            'br-ex': {     # bridge
                'eth0': {  # port
                           # interface(s) with data
                    'eth0': {'data': 'fake'},
                },
            },
            'br-data': {
                'dpdk-xxx': {
                    'if0': {'fake': 'data'},
                    'if1': {'fake': 'data'}
                },
            },
            'br-int': {
                'someport': {
                    'someport': {'data': 'fake'},
                },
            },
        }
        mock_bpi = mock.MagicMock()
        mock_bpi.items.return_value = dict_bpi.items()
        mock_bpi.__iter__.return_value = dict_bpi.__iter__()
        mock_bpi.__contains__.side_effect = dict_bpi.__contains__
        mock_bpi.__getitem__.side_effect = lambda x: dict_bpi.__getitem__(x)
        mock_bpi.get_ifdatamap.side_effect = lambda x, y: {
            k: v for k, v in dict_bpi[x][y].items()}
        self.BridgePortInterfaceMap.return_value = mock_bpi
        self.patch_object(ovn_charm.os_context, 'BondConfig')
        mock_bondconfig = mock.MagicMock()
        mock_bondconfig.get_ovs_portdata.return_value = 'fakebondconfig'
        self.BondConfig.return_value = mock_bondconfig
        self.patch_object(ovn_charm.ch_ovsdb, 'SimpleOVSDB')

        ovsdb = mock.MagicMock()
        ovsdb.bridge.find.side_effect = [
            [
                {'name': 'delete-bridge'},
                {'name': 'br-int'},
            ],
            StopIteration,
        ]
        ovsdb.port.find.return_value = [{'name': 'delete-port'}]
        self.SimpleOVSDB.return_value = ovsdb

        self.patch_object(ovn_charm.ch_ovs, 'del_bridge')
        self.patch_object(ovn_charm.ch_ovs, 'del_bridge_port')
        self.patch_object(ovn_charm.ch_ovs, 'add_bridge')
        self.patch_object(ovn_charm.ch_ovs, 'get_bridge_ports')
        self.get_bridge_ports().__iter__.return_value = []
        self.patch_object(ovn_charm.ch_ovs, 'add_bridge_bond')
        self.patch_object(ovn_charm.ch_ovs, 'add_bridge_port')
        self.patch_target('check_if_paused')
        self.check_if_paused.return_value = ('some', 'reason')
        self.target.configure_bridges()
        self.BridgePortInterfaceMap.assert_not_called()
        self.check_if_paused.return_value = (None, None)
        self.target.configure_bridges()
        self.BridgePortInterfaceMap.assert_called_once_with(
            bridges_key='bridge-interface-mappings')
        # br-int should not be deleted when not in config, even when managed
        self.del_bridge.assert_called_once_with('delete-bridge')
        # since we manage it we will delete non-existant managed ports in it
        self.del_bridge_port.assert_has_calls([
            mock.call('br-int', 'delete-port'),
        ])
        # br-int will always be added/updated regardless of presence in config
        self.add_bridge.assert_has_calls([
            mock.call(
                'br-int',
                brdata={
                    'external-ids': {'charm-ovn-chassis': 'managed'},
                    'datapath-type': 'netdev',
                    'protocols': 'OpenFlow13,OpenFlow15',
                    'fail-mode': 'secure',
                    'other-config': {'disable-in-band': 'true'},
                }),
            mock.call(
                'br-data',
                brdata={
                    'external-ids': {'charm-ovn-chassis': 'managed'},
                    'datapath-type': 'netdev',
                    'protocols': 'OpenFlow13,OpenFlow15',
                    'fail-mode': 'standalone',
                }),
            mock.call(
                'br-ex',
                brdata={
                    'external-ids': {'charm-ovn-chassis': 'managed'},
                    'datapath-type': 'netdev',
                    'protocols': 'OpenFlow13,OpenFlow15',
                    'fail-mode': 'standalone',
                }),
        ], any_order=True)
        self.add_bridge_bond.assert_called_once_with(
            'br-data', 'dpdk-xxx', ['if0', 'if1'], 'fakebondconfig', {
                'if0': {
                    'fake': 'data',
                    'external-ids': {'charm-ovn-chassis': 'br-data'}},
                'if1': {
                    'fake': 'data',
                    'external-ids': {'charm-ovn-chassis': 'br-data'}},
            })
        self.add_bridge_port.assert_called_once_with(
            'br-ex', 'eth0', ifdata={
                'data': 'fake',
                'external-ids': {'charm-ovn-chassis': 'br-ex'}},
            linkup=False, promisc=None, portdata={
                'external-ids': {'charm-ovn-chassis': 'br-ex'}}),
        ovsdb.open_vswitch.set.assert_called_once_with(
            '.', 'external_ids:ovn-bridge-mappings',
            'other:br-data,provider:br-ex')
        ovsdb.open_vswitch.remove.assert_called_once_with(
            '.', 'external_ids', 'ovn-cms-options=enable-chassis-as-gw')


class TestOVNChassisCharm(Helper):

    def setUp(self):
        super().setUp(config={
            'enable-hardware-offload': False,
            'enable-sriov': False,
            'enable-dpdk': False,
            'bridge-interface-mappings': (
                'br-provider:00:01:02:03:04:05 br-other:eth5'),
            'ovn-bridge-mappings': (
                'provider:br-provider other:br-other'),
            'prefer-chassis-as-gw': True,
        })

    def test_optional_openstack_metadata(self):
        self.assertEquals(self.target.packages, ['ovn-host'])
        self.assertEquals(self.target.services, ['ovn-host'])

    def test_run(self):
        self.patch_object(ovn_charm.subprocess, 'run')
        self.patch_object(ovn_charm.ch_core.hookenv, 'log')
        self.target.run('some', 'args')
        self.run.assert_called_once_with(
            ('some', 'args'),
            stdout=ovn_charm.subprocess.PIPE,
            stderr=ovn_charm.subprocess.STDOUT,
            check=True,
            universal_newlines=True)

    def test_get_certificate_requests(self):
        self.patch_target('get_ovs_hostname')
        self.get_ovs_hostname.return_value = 'fake-ovs-hostname'
        self.assertDictEqual(
            self.target.get_certificate_requests(),
            {'fake-ovs-hostname': {'sans': []}})

    def test_configure_tls(self):
        self.patch_target('get_certs_and_keys')
        self.get_certs_and_keys.return_value = [
            {
                'cert': 'notformefakecert',
                'key': 'notformefakekey',
                'cn': 'notformefakecn',
                'ca': 'notformefakeca',
                'chain': 'notformefakechain',
            },
            {
                'cert': 'fakecert',
                'key': 'fakekey',
                'cn': 'fakecn',
                'ca': 'fakeca',
                'chain': 'fakechain',
            }
        ]
        self.patch_target('ovn_sysconfdir')
        self.ovn_sysconfdir.return_value = '/etc/path'
        self.patch_target('get_ovs_hostname')
        self.get_ovs_hostname.return_value = 'fakecn'
        with mock.patch('builtins.open', create=True) as mocked_open:
            mocked_file = mock.MagicMock(spec=io.FileIO)
            mocked_open.return_value = mocked_file
            self.target.configure_cert = mock.MagicMock()
            self.target.run = mock.MagicMock()
            self.target.configure_tls()
            mocked_open.assert_called_once_with(
                '/etc/path/charmname.crt', 'w')
            mocked_file.__enter__().write.assert_called_once_with(
                'fakeca\nfakechain')
            self.target.configure_cert.assert_called_once_with(
                '/etc/path',
                'fakecert',
                'fakekey',
                cn='host')

    def test_configure_tls_not_ready(self):
        self.patch_target('get_certs_and_keys')
        self.get_certs_and_keys.return_value = None
        self.target.configure_cert = mock.MagicMock()
        self.target.configure_tls()
        self.target.configure_cert.assert_not_called()

    def test__format_addr(self):
        self.assertEquals('1.2.3.4', self.target._format_addr('1.2.3.4'))
        self.assertEquals(
            '[2001:db8::42]', self.target._format_addr('2001:db8::42'))
        with self.assertRaises(ValueError):
            self.target._format_addr('999.999.999.999')
        with self.assertRaises(ValueError):
            self.target._format_addr('2001:db8::g')

    def test_get_data_ip(self):
        self.patch_object(ovn_charm.ch_core.hookenv, 'network_get')
        self.network_get.return_value = {
            'bind-addresses': [
                {
                    'mac-address': 'fa:16:3e:68:e7:dd',
                    'interface-name': 'ens3',
                    'addresses': [
                        {
                            'hostname': '',
                            'address': '10.5.0.102',
                            'cidr': '10.5.0.0/16',
                        }
                    ]
                }
            ]
        }
        self.assertEquals(self.target.get_data_ip(), '10.5.0.102')

    def test_get_ovs_hostname(self):
        self.patch_object(ovn_charm.ch_ovsdb, 'SimpleOVSDB')
        opvs = mock.MagicMock()
        opvs.open_vswitch.__iter__.return_value = [
            {'external_ids': {'hostname': 'fake-ovs-hostname'}}]
        self.SimpleOVSDB.return_value = opvs
        self.assertEquals(self.target.get_ovs_hostname(), 'fake-ovs-hostname')

    def test_configure_ovs(self):
        self.patch_target('run')
        self.patch_object(ovn_charm.OVNConfigurationAdapter, 'ovn_key')
        self.patch_object(ovn_charm.OVNConfigurationAdapter, 'ovn_cert')
        self.patch_object(ovn_charm.OVNConfigurationAdapter, 'ovn_ca_cert')
        self.patch_object(ovn_charm.ch_core.host, 'service_restart')
        self.patch_target('get_data_ip')
        self.get_data_ip.return_value = 'fake-data-ip'
        self.patch_target('get_ovs_hostname')
        self.get_ovs_hostname.return_value = 'fake-ovs-hostname'
        self.patch_target('check_if_paused')
        self.check_if_paused.return_value = ('some', 'reason')
        self.target.configure_ovs('fake-sb-conn-str', True)
        self.run.assert_not_called()
        self.service_restart.assert_not_called()
        self.check_if_paused.return_value = (None, None)
        self.target.configure_ovs('fake-sb-conn-str', False)
        self.run.assert_has_calls([
            mock.call('ovs-vsctl', '--no-wait', 'set-ssl',
                      mock.ANY, mock.ANY, mock.ANY),
            mock.call('ovs-vsctl', 'set', 'open', '.',
                      'external-ids:ovn-encap-type=geneve', '--',
                      'set', 'open', '.',
                      'external-ids:ovn-encap-ip=fake-data-ip', '--',
                      'set', 'open', '.',
                      'external-ids:system-id=fake-ovs-hostname'),
            mock.call('ovs-vsctl', 'set', 'open', '.',
                      'external-ids:ovn-remote=fake-sb-conn-str'),
        ])
        self.service_restart.assert_not_called()
        self.run.reset_mock()
        self.enable_openstack.return_value = True
        self.patch_object(ovn_charm.ch_ovsdb, 'SimpleOVSDB')
        managers = mock.MagicMock()
        self.SimpleOVSDB.return_value = managers
        self.target.configure_ovs('fake-sb-conn-str', True)
        managers.manager.find.assert_called_once_with(
            'target="ptcp:6640:127.0.0.1"')
        self.run.assert_has_calls([
            mock.call('ovs-vsctl', '--no-wait', 'set-ssl',
                      mock.ANY, mock.ANY, mock.ANY),
            mock.call('ovs-vsctl', 'set', 'open', '.',
                      'external-ids:ovn-encap-type=geneve', '--',
                      'set', 'open', '.',
                      'external-ids:ovn-encap-ip=fake-data-ip', '--',
                      'set', 'open', '.',
                      'external-ids:system-id=fake-ovs-hostname'),
            mock.call('ovs-vsctl', 'set', 'open', '.',
                      'external-ids:ovn-remote=fake-sb-conn-str'),
            mock.call('ovs-vsctl', '--id', '@manager',
                      'create', 'Manager', 'target="ptcp:6640:127.0.0.1"',
                      '--', 'add', 'Open_vSwitch', '.', 'manager_options',
                      '@manager'),
        ])
        assert self.service_restart.called

    def test_render_nrpe(self):
        self.patch_object(ovn_charm.nrpe, 'NRPE')
        self.patch_object(ovn_charm.nrpe, 'add_init_service_checks')
        self.target.render_nrpe()
        self.add_init_service_checks.assert_has_calls([
            mock.call().add_init_service_checks(
                mock.ANY,
                ['ovn-controller', 'ovs-vswitchd', 'ovsdb-server'],
                mock.ANY
            ),
        ])
        self.NRPE.assert_has_calls([
            mock.call().write(),
        ])

    def test_configure_bridges(self):
        self.patch_object(ovn_charm.os_context, 'BridgePortInterfaceMap')
        dict_bpi = {
            'br-provider': {  # bridge
                'eth0': {     # port
                              # interface(s) with interface data
                    'eth0': {'data': 'fake'},
                },
            },
            'br-other': {
                'eth5': {
                    'eth5': {'data': 'fake'},
                },
            },
            'br-int': {
                'someport': {
                    'someport': {'data': 'fake'},
                },
            },
        }
        mock_bpi = mock.MagicMock()
        mock_bpi.items.return_value = dict_bpi.items()
        mock_bpi.__iter__.return_value = dict_bpi.__iter__()
        mock_bpi.__contains__.side_effect = dict_bpi.__contains__
        mock_bpi.__getitem__.side_effect = lambda x: dict_bpi.__getitem__(x)
        mock_bpi.get_ifdatamap.side_effect = lambda x, y: {
            k: v for k, v in dict_bpi[x][y].items()}
        self.BridgePortInterfaceMap.return_value = mock_bpi
        self.patch_object(ovn_charm.os_context, 'BondConfig')
        self.patch_object(ovn_charm.ch_ovsdb, 'SimpleOVSDB')

        ovsdb = mock.MagicMock()
        ovsdb.bridge.find.side_effect = [
            [
                {'name': 'delete-bridge'},
                {'name': 'br-other'},
                {'name': 'br-int'},
            ],
            StopIteration,
        ]
        ovsdb.port.find.return_value = [{'name': 'delete-port'}]
        self.SimpleOVSDB.return_value = ovsdb

        self.patch_object(ovn_charm.ch_ovs, 'del_bridge')
        self.patch_object(ovn_charm.ch_ovs, 'del_bridge_port')
        self.patch_object(ovn_charm.ch_ovs, 'add_bridge')
        self.patch_object(ovn_charm.ch_ovs, 'get_bridge_ports')
        self.get_bridge_ports().__iter__.return_value = []
        self.patch_object(ovn_charm.ch_ovs, 'add_bridge_port')
        self.patch_target('check_if_paused')
        self.check_if_paused.return_value = ('some', 'reason')
        self.target.configure_bridges()
        self.BridgePortInterfaceMap.assert_not_called()
        self.check_if_paused.return_value = (None, None)
        self.target.configure_bridges()
        self.BridgePortInterfaceMap.assert_called_once_with(
            bridges_key='bridge-interface-mappings')
        # br-int should not be deleted when not in config, even when managed
        self.del_bridge.assert_called_once_with('delete-bridge')
        # since we manage it we will delete non-existant managed ports in it
        self.del_bridge_port.assert_has_calls([
            mock.call('br-other', 'delete-port'),
            mock.call('br-int', 'delete-port'),
        ])
        # br-int will always be added/updated regardless of presence in config
        self.add_bridge.assert_has_calls([
            mock.call(
                'br-int',
                brdata={
                    'external-ids': {'charm-ovn-chassis': 'managed'},
                    'datapath-type': 'system',
                    'protocols': 'OpenFlow13,OpenFlow15',
                    'fail-mode': 'secure',
                    'other-config': {'disable-in-band': 'true'},
                }),
            mock.call(
                'br-provider',
                brdata={
                    'external-ids': {'charm-ovn-chassis': 'managed'},
                    'datapath-type': 'system',
                    'protocols': 'OpenFlow13,OpenFlow15',
                    'fail-mode': 'standalone',
                }),
            mock.call(
                'br-other',
                brdata={
                    'external-ids': {'charm-ovn-chassis': 'managed'},
                    'datapath-type': 'system',
                    'protocols': 'OpenFlow13,OpenFlow15',
                    'fail-mode': 'standalone',
                }),
        ], any_order=True)
        self.add_bridge_port.assert_has_calls([
            mock.call(
                'br-provider', 'eth0', ifdata={
                    'data': 'fake',
                    'external-ids': {'charm-ovn-chassis': 'br-provider'}},
                linkup=True, promisc=None, portdata={
                    'external-ids': {'charm-ovn-chassis': 'br-provider'}}),
            mock.call(
                'br-other', 'eth5', ifdata={
                    'data': 'fake',
                    'external-ids': {'charm-ovn-chassis': 'br-other'}},
                linkup=True, promisc=None, portdata={
                    'external-ids': {'charm-ovn-chassis': 'br-other'}}),
        ], any_order=True)
        ovsdb.open_vswitch.set.assert_has_calls([
            mock.call('.', 'external_ids:ovn-bridge-mappings',
                      'other:br-other,provider:br-provider'),
            mock.call('.', 'external_ids:ovn-cms-options',
                      'enable-chassis-as-gw'),
        ], any_order=True)

    def test_states_to_check(self):
        self.maxDiff = None
        expect = collections.OrderedDict([
            ('certificates', [
                ('certificates.available', 'blocked',
                 "'certificates' missing"),
                ('certificates.server.certs.available',
                 'waiting',
                 "'certificates' awaiting server certificate data")]),
            ('ovsdb', [
                ('ovsdb.connected', 'blocked', "'ovsdb' missing"),
                ('ovsdb.available', 'waiting', "'ovsdb' incomplete")]),

        ])
        self.assertDictEqual(self.target.states_to_check(), expect)

    def test_resume(self):
        self.patch_target('run_pause_or_resume')
        self.patch_object(ovn_charm.os, 'execl')
        self.patch_object(ovn_charm.ch_core.hookenv, 'charm_dir')
        self.charm_dir.return_value = '/some/path'
        self.target.resume()
        self.execl.assert_called_once_with(
            '/usr/bin/env', 'python3', '/some/path/hooks/config-changed')


class TestSRIOVOVNChassisCharm(Helper):

    def setUp(self):
        super().setUp(config={
            'enable-hardware-offload': False,
            'enable-sriov': True,
            'enable-dpdk': False,
            'bridge-interface-mappings': 'br-ex:eth0',
            'ovn-bridge-mappings': 'physnet2:br-ex',
        }, is_flag_set_return_value=True)
        self.enable_openstack.return_value = True

    def test__init__(self):
        self.maxDiff = None
        self.assertEquals(self.target.packages, [
            'ovn-host',
            'sriov-netplan-shim',
            'neutron-sriov-agent',
            'neutron-ovn-metadata-agent',
        ])
        self.assertDictEqual(self.target.restart_map, {
            '/etc/sriov-netplan-shim/interfaces.yaml': [],
            '/etc/default/openvswitch-switch': [],
            '/etc/neutron/neutron.conf': ['neutron-sriov-agent'],
            '/etc/neutron/plugins/ml2/sriov_agent.ini': [
                'neutron-sriov-agent'],
            '/etc/openvswitch/system-id.conf': [],
            '/etc/neutron/neutron_ovn_metadata_agent.ini': [
                'neutron-ovn-metadata-agent']
        })
        self.assertEquals(self.target.group, 'neutron')
        self.assertEquals(
            self.target.required_relations,
            ['certificates', 'ovsdb', 'amqp'])

    def test_install(self):
        self.patch_target('configure_source')
        self.patch_target('run')
        self.patch_target('update_api_ports')
        self.patch_target('render_configs')
        self.patch_object(ovn_charm.ch_core.host, 'service_restart')
        self.patch_object(ovn_charm.reactive, 'is_flag_set',
                          return_value=False)
        self.patch_object(ovn_charm.ch_core.hookenv, 'config')
        self.config.return_value = None
        self.target.install()
        self.configure_source.assert_called_once_with(
            'networking-tools-source')
        self.render_configs.assert_called_once_with(
            ['/etc/default/openvswitch-switch'])
        self.service_restart.assert_called_once_with(
            'openvswitch-switch')


class TestHWOffloadChassisCharm(Helper):

    def setUp(self):
        super().setUp(config={
            'enable-hardware-offload': True,
            'enable-sriov': False,
            'enable-dpdk': False,
            'bridge-interface-mappings': 'br-ex:eth0',
            'ovn-bridge-mappings': 'physnet2:br-ex',
        })

    def test__init__(self):
        self.assertEquals(self.target.packages, [
            'ovn-host',
            'sriov-netplan-shim',
            'mlnx-switchdev-mode',
        ])
        self.assertDictEqual(self.target.restart_map, {
            '/etc/sriov-netplan-shim/interfaces.yaml': [],
            '/etc/default/openvswitch-switch': [],
            '/etc/openvswitch/system-id.conf': [],
        })
        self.assertEquals(self.target.group, 'root')

    def test_install(self):
        self.patch_target('configure_source')
        self.patch_target('run')
        self.patch_target('update_api_ports')
        self.target.install()
        self.configure_source.assert_called_once_with(
            'networking-tools-source')

    def test_configure_ovs_hw_offload(self):
        self.patch_object(ovn_charm.ch_ovsdb, 'SimpleOVSDB')
        ovsdb = mock.MagicMock()
        ovsdb.open_vswitch.__iter__.return_value = [
            dict([('other_config:hw-offload', 'true'),
                  ('other_config:max-idle', '30000')]),
        ]
        self.SimpleOVSDB.return_value = ovsdb
        self.assertFalse(self.target.configure_ovs_hw_offload())
        ovsdb.open_vswitch.set.assert_not_called()
        ovsdb.open_vswitch.__iter__.return_value = [
            dict([('other_config:hw-offload', 'false'),
                  ('other_config:max-idle', '30000')]),
        ]
        self.assertTrue(self.target.configure_ovs_hw_offload())
        ovsdb.open_vswitch.set.assert_called_once_with(
            '.', 'other_config:hw-offload', 'true')
        ovsdb.open_vswitch.__iter__.return_value = [
            dict([('other_config:hw-offload', 'true'),
                  ('other_config:max-idle', '42')]),
        ]
        ovsdb.open_vswitch.set.reset_mock()
        self.assertTrue(self.target.configure_ovs_hw_offload())
        ovsdb.open_vswitch.set.assert_called_once_with(
            '.', 'other_config:max-idle', '30000')
