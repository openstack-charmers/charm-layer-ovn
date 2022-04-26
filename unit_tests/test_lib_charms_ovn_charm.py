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
import copy
import io
import textwrap
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


class TestOVNConfigurationAdapterSerial(test_utils.PatchHelper):

    def setUp(self):
        super().setUp()
        self.charm_instance = mock.MagicMock()
        self.patch_object(ovn_charm.ch_core.hookenv, 'config')

        def _config_side_effect(k=None):
            opts = {
                'enable-hardware-offload': False,
                'enable-sriov': False,
                'enable-dpdk': False,
                'vpd-device-spec':
                '[{"bus": "pci", "vendor_id": "b3ef", "device_id": "caf3"}]',
            }
            return opts[k] if k else opts

        self.config.side_effect = _config_side_effect

        self.target = ovn_charm.OVNConfigurationAdapter(
            charm_instance=self.charm_instance)

    def test_card_serial_no_serial_in_lspci(self):
        self.patch_object(ovn_charm.subprocess, 'check_output')
        self.check_output.return_value = ''
        self.assertIsNone(self.target.card_serial_number)

    def test_card_serial_valid_serial(self):
        self.patch_object(ovn_charm.subprocess, 'check_output')
        self.check_output.return_value = r'''
03:00.1 Ethernet controller: Ubuntu DPU Super Series
	Subsystem: Ubuntu network controller
	Control: I/O- Mem+ BusMaster+ SpecCycle- MemWINV- VGASnoop- ParErr-
	Status: Cap+ 66MHz- UDF- FastB2B- ParErr- DEVSEL=fast >TAbort- <TAbort-
	Latency: 0
	Interrupt: pin A routed to IRQ 78
	Region 0: Memory at e202000000 (64-bit, prefetchable) [size=32M]
	Expansion ROM at e000100000 [disabled] [size=1M]
	Capabilities: [48] Vital Product Data
		Product Name: Ubuntu DPU Super Series
		Read-only fields:
			[PN] Part number: jammy-jellyfish
			[EC] Engineering changes: B1
			[SN] Serial number: deadbeefcafe
			[V3] Vendor specific: 22.04
			[V0] Vendor specific: PCIeGen4 x8
			[RV] Reserved: checksum good, 1 byte(s) reserved
		End
        '''  # noqa: W191, E101  to represent the real-world lspci output.
        self.assertEquals(self.target.card_serial_number, 'deadbeefcafe')

    def test_card_serial_no_spec(self):
        def _config_side_effect(k=None):
            opts = {
                'enable-hardware-offload': False,
                'enable-sriov': False,
                'enable-dpdk': False,
                'vpd-device-spec': ''
            }
            return opts[k] if k else opts

        self.config.side_effect = _config_side_effect

        self.target = ovn_charm.OVNConfigurationAdapter(
            charm_instance=self.charm_instance)

        self.assertIsNone(self.target.card_serial_number)

    def test_card_serial_invalid_spec(self):
        invalid_specs = [
            '{', '{}',
            # Not a JSON array:
            '{"bus": "pci", "vendor_id": "beef", "device_id": "cafe"}',
            # Bus isn't specified:
            '["vendor_id": "beef", "device_id": "cafe"}]',
            # Invalid device key:
            '{"bus": "pci", "vendor_id": "beef", "device": "cafe"}]',
            # Invalid device value:
            '[{"bus": "pci", "vendor_id": "beef", "device_id": 3453}]',
            # Invalid vendor key:
            '[{"bus": "pci", "vendor": "beef", "device_id": "cafe"}]',
            # Invalid vendor value:
            '[{"bus": "pci", "vendor": 6334, "device_id": "cafe"}]',
            # Missing device key:
            '[{"bus": "pci", "vendor_id": "beef"}]',
            # Missing vendor key:
            '[{"bus": "pci", "device_id": "cafe"}]',
        ]

        for invalid_spec in invalid_specs:
            def _config_side_effect(k=None):
                opts = {
                    'enable-hardware-offload': False,
                    'enable-sriov': False,
                    'enable-dpdk': False,
                    'vpd-device-spec': invalid_spec
                }
                return opts[k] if k else opts

            self.config.side_effect = _config_side_effect
            self.target = ovn_charm.OVNConfigurationAdapter(
                charm_instance=self.charm_instance)
            self.assertIsNone(self.target.card_serial_number)


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
                'vpd-device-spec':
                '[{"bus": "pci", "vendor_id": "beef", "device_id": "cafe"}]',
            }
            if x:
                return cfg.get(x)
            return cfg

        self.config.side_effect = _fake_config
        self.enable_openstack = mock.PropertyMock
        self.enable_openstack.return_value = False
        self.target = ovn_charm.BaseOVNChassisCharm()
        self.patch(
            'charms.ovn_charm.BaseOVNChassisCharm.enable_openstack',
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


class TestOVNChassisCharmWithOpenStack(Helper):

    def setUp(self):
        super().setUp()
        self.enable_openstack.return_value = True

    def test_optional_openstack_metadata(self):
        self.assertEquals(self.target.packages, [
            'ovn-host', 'neutron-ovn-metadata-agent',
        ])
        self.assertEquals(self.target.services, [
            'ovn-host', 'neutron-ovn-metadata-agent'])
        self.assertDictEqual(self.target.restart_map, {
            '/etc/default/openvswitch-switch': [],
            '/etc/netplan/150-charm-ovn.yaml': [],
            '/etc/neutron/neutron_ovn_metadata_agent.ini': [
                'neutron-ovn-metadata-agent'],
            '/etc/openvswitch/system-id.conf': [],
        })
        self.assertEquals(self.target.nrpe_check_services, [
            'ovn-controller', 'ovs-vswitchd', 'ovsdb-server',
            'neutron-ovn-metadata-agent'])


class TestDPDKOVNChassisCharmExtraLibs(Helper):

    def setUp(self):
        self.local_config = {
            'enable-hardware-offload': False,
            'enable-sriov': False,
            'enable-dpdk': True,
            'dpdk-bond-mappings': ('dpdk-bond0:a0:36:9f:dd:37:a4 '
                                   'dpdk-bond0:a0:36:9f:dd:3e:9c'),
            'bridge-interface-mappings': 'br-ex:eth0 br-data:dpdk-bond0',
            'ovn-bridge-mappings': (
                'provider:br-ex other:br-data'),
            'prefer-chassis-as-gw': False,
            'dpdk-runtime-libraries': '',
            'vpd-device-spec': '',
        }
        super().setUp(config=self.local_config)

        self.run = mock.Mock()
        self.patch('charms.ovn_charm.BaseOVNChassisCharm.run',
                   new_callable=self.run)
        self.run.start()
        self.called_process = self.run.return_value
        self.called_process.returncode = 0

    def test_single_match(self):
        apt_cache_output = textwrap.dedent(
        """
        librte-net-hinic21:
          Installed: 20.11.3-0ubuntu0.21.04.2
          Candidate: 20.11.3-0ubuntu0.21.04.2
          Version table:
         *** 20.11.3-0ubuntu0.21.04.2 500
                500 http://us.archive.ubuntu.com/ubuntu hirsute-updates/universe amd64 Packages
                100 /var/lib/dpkg/status
             20.11.1-1 500
                500 http://us.archive.ubuntu.com/ubuntu hirsute/universe amd64 Packages
        """  # noqa
        )
        self.called_process.stdout = apt_cache_output

        self.local_config['dpdk-runtime-libraries'] = 'hinic'
        target = ovn_charm.BaseOVNChassisCharm()
        self.assertEquals(target.additional_dpdk_libraries, [
            'librte-net-hinic21'])
        self.assertEquals(target.packages, [
            'ovn-host', 'openvswitch-switch-dpdk', 'librte-net-hinic21'])

    def test_multiple_matches(self):
        apt_cache_output = textwrap.dedent(
        """
        librte-net-mlx5-21:
          Installed: 20.11.3-0ubuntu0.21.04.2
          Candidate: 20.11.3-0ubuntu0.21.04.2
          Version table:
         *** 20.11.3-0ubuntu0.21.04.2 500
                500 http://us.archive.ubuntu.com/ubuntu hirsute-updates/main amd64 Packages
                100 /var/lib/dpkg/status
             20.11.1-1 500
                500 http://us.archive.ubuntu.com/ubuntu hirsute/main amd64 Packages
        librte-regex-mlx5-21:
          Installed: 20.11.3-0ubuntu0.21.04.2
          Candidate: 20.11.3-0ubuntu0.21.04.2
          Version table:
         *** 20.11.3-0ubuntu0.21.04.2 500
                500 http://us.archive.ubuntu.com/ubuntu hirsute-updates/universe amd64 Packages
                100 /var/lib/dpkg/status
             20.11.1-1 500
                500 http://us.archive.ubuntu.com/ubuntu hirsute/universe amd64 Packages
        librte-common-mlx5-21:
          Installed: 20.11.3-0ubuntu0.21.04.2
          Candidate: 20.11.3-0ubuntu0.21.04.2
          Version table:
         *** 20.11.3-0ubuntu0.21.04.2 500
                500 http://us.archive.ubuntu.com/ubuntu hirsute-updates/main amd64 Packages
                100 /var/lib/dpkg/status
             20.11.1-1 500
                500 http://us.archive.ubuntu.com/ubuntu hirsute/main amd64 Packages
        librte-vdpa-mlx5-21:
          Installed: 20.11.3-0ubuntu0.21.04.2
          Candidate: 20.11.3-0ubuntu0.21.04.2
          Version table:
         *** 20.11.3-0ubuntu0.21.04.2 500
                500 http://us.archive.ubuntu.com/ubuntu hirsute-updates/universe amd64 Packages
                100 /var/lib/dpkg/status
             20.11.1-1 500
                500 http://us.archive.ubuntu.com/ubuntu hirsute/universe amd64 Packages
        """  # noqa
        )
        self.called_process.stdout = apt_cache_output

        self.local_config['dpdk-runtime-libraries'] = 'mlx5'
        target = ovn_charm.BaseOVNChassisCharm()
        self.assertEquals(target.additional_dpdk_libraries, [
            'librte-net-mlx5-21', 'librte-regex-mlx5-21',
            'librte-common-mlx5-21', 'librte-vdpa-mlx5-21'])

    def test_specific_package(self):
        self.local_config['dpdk-runtime-libraries'] = 'librte-net-mlx5-21'
        target = ovn_charm.BaseOVNChassisCharm()
        self.assertEquals(target.additional_dpdk_libraries, [
            'librte-net-mlx5-21'])
        self.run.assert_not_called()

    def test_none_package(self):
        self.local_config['dpdk-runtime-libraries'] = 'None'
        target = ovn_charm.BaseOVNChassisCharm()
        self.assertEquals(target.additional_dpdk_libraries, [])
        self.run.assert_not_called()

    def test_multiple_packages(self):
        process1 = mock.Mock()
        process1.stdout = textwrap.dedent(
        """
        librte-net-hinic21:
          Installed: 20.11.3-0ubuntu0.21.04.2
          Candidate: 20.11.3-0ubuntu0.21.04.2
          Version table:
         *** 20.11.3-0ubuntu0.21.04.2 500
                500 http://us.archive.ubuntu.com/ubuntu hirsute-updates/universe amd64 Packages
                100 /var/lib/dpkg/status
             20.11.1-1 500
                500 http://us.archive.ubuntu.com/ubuntu hirsute/universe amd64 Packages
        """  # noqa
        )
        process2 = mock.Mock()
        process2.stdout = textwrap.dedent(
        """
        librte-net-mlx5-21:
          Installed: 20.11.3-0ubuntu0.21.04.2
          Candidate: 20.11.3-0ubuntu0.21.04.2
          Version table:
         *** 20.11.3-0ubuntu0.21.04.2 500
                500 http://us.archive.ubuntu.com/ubuntu hirsute-updates/main amd64 Packages
                100 /var/lib/dpkg/status
             20.11.1-1 500
                500 http://us.archive.ubuntu.com/ubuntu hirsute/main amd64 Packages
        librte-regex-mlx5-21:
          Installed: 20.11.3-0ubuntu0.21.04.2
          Candidate: 20.11.3-0ubuntu0.21.04.2
          Version table:
         *** 20.11.3-0ubuntu0.21.04.2 500
                500 http://us.archive.ubuntu.com/ubuntu hirsute-updates/universe amd64 Packages
                100 /var/lib/dpkg/status
             20.11.1-1 500
                500 http://us.archive.ubuntu.com/ubuntu hirsute/universe amd64 Packages
        librte-common-mlx5-21:
          Installed: 20.11.3-0ubuntu0.21.04.2
          Candidate: 20.11.3-0ubuntu0.21.04.2
          Version table:
         *** 20.11.3-0ubuntu0.21.04.2 500
                500 http://us.archive.ubuntu.com/ubuntu hirsute-updates/main amd64 Packages
                100 /var/lib/dpkg/status
             20.11.1-1 500
                500 http://us.archive.ubuntu.com/ubuntu hirsute/main amd64 Packages
        librte-vdpa-mlx5-21:
          Installed: 20.11.3-0ubuntu0.21.04.2
          Candidate: 20.11.3-0ubuntu0.21.04.2
          Version table:
         *** 20.11.3-0ubuntu0.21.04.2 500
                500 http://us.archive.ubuntu.com/ubuntu hirsute-updates/universe amd64 Packages
                100 /var/lib/dpkg/status
             20.11.1-1 500
                500 http://us.archive.ubuntu.com/ubuntu hirsute/universe amd64 Packages
        """  # noqa
        )

        self.run.side_effect = [process1, process2]

        self.local_config['dpdk-runtime-libraries'] = 'hinic mlx'
        target = ovn_charm.BaseOVNChassisCharm()
        self.assertEquals(target.additional_dpdk_libraries, [
            'librte-net-hinic21', 'librte-net-mlx5-21', 'librte-regex-mlx5-21',
            'librte-common-mlx5-21', 'librte-vdpa-mlx5-21'])

    def test_package_not_found(self):
        # Missing packages don't have output via this command
        self.called_process.stdout = ''
        self.local_config['dpdk-runtime-libraries'] = 'missing'
        target = ovn_charm.BaseOVNChassisCharm()
        self.assertEquals(target.additional_dpdk_libraries, ['missing'])


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
            'dpdk-runtime-libraries': '',
            'vpd-device-spec': '',
        })

    def test__init__(self):
        self.assertEquals(self.target.packages, [
            'ovn-host', 'openvswitch-switch-dpdk'])
        self.assertDictEqual(self.target.restart_map, {
            '/etc/default/openvswitch-switch': [],
            '/etc/dpdk/interfaces': ['dpdk'],
            '/etc/netplan/150-charm-ovn.yaml': [],
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
            mock.call('br-int', 'delete-port', linkdown=False),
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
            '.', 'external_ids', 'ovn-cms-options')

    def test_dpdk_eal_allow_devices(self):
        self.patch_object(ovn_charm.ch_core.host, 'cmp_pkgrevno')
        single_device = {'0000:42:01.0': ('eth0', '00:53:00:00:42:01')}
        devices = copy.copy(single_device)
        devices.update({'0000:42:02.0': ('eth1', '00:53:00:00:42:02')})

        # DPDK 20.11.3 or newer
        self.cmp_pkgrevno.return_value = 0
        self.assertEquals(
            self.target.dpdk_eal_allow_devices(single_device),
            '-a 0000:42:01.0')
        self.assertEquals(
            self.target.dpdk_eal_allow_devices(devices),
            '-a 0000:42:01.0 -a 0000:42:02.0')

        # Older DPDK releases
        self.cmp_pkgrevno.return_value = -1
        self.assertEquals(
            self.target.dpdk_eal_allow_devices(single_device),
            '-w 0000:42:01.0')
        self.assertEquals(
            self.target.dpdk_eal_allow_devices(devices),
            '-w 0000:42:01.0 -w 0000:42:02.0')

    def test_configure_ovs_dpdk(self):
        dpdk_context = mock.MagicMock()
        self.patch_object(ovn_charm.os_context, 'OVSDPDKDeviceContext',
                          return_value=dpdk_context)
        self.patch_target('dpdk_eal_allow_devices')
        self.patch_object(ovn_charm.ch_ovsdb, 'SimpleOVSDB')
        opvs = mock.MagicMock()
        self.SimpleOVSDB.return_value = opvs

        # No existing config, confirm restart and values set as expected
        opvs.open_vswitch.__iter__.return_value = [
            {'other_config': {}}]
        dpdk_context.cpu_mask.return_value = '0x42'
        dpdk_context.socket_memory.return_value = '1024,1024'
        self.dpdk_eal_allow_devices.return_value = '-a 0000:42:01.0'
        self.assertTrue(self.target.configure_ovs_dpdk())
        opvs.open_vswitch.set.assert_has_calls([
            mock.call('.', 'other_config:dpdk-lcore-mask', '0x42'),
            mock.call('.', 'other_config:dpdk-socket-mem', '1024,1024'),
            mock.call('.', 'other_config:dpdk-init', 'true'),
            mock.call('.', 'other_config:dpdk-extra', '-a 0000:42:01.0'),
        ])

        # Existing config, confirm no restart nor values set
        opvs.open_vswitch.__iter__.return_value = [
            {'other_config': {
                'dpdk-lcore-mask': '0x42',
                'dpdk-socket-mem': '1024,1024',
                'dpdk-init': 'true',
                'dpdk-extra': '-a 0000:42:01.0',
            }}]
        opvs.open_vswitch.reset_mock()
        self.assertFalse(self.target.configure_ovs_dpdk())

        # Existing config, confirm restart and values updated as expected
        opvs.open_vswitch.__iter__.return_value = [
            {'other_config': {
                'dpdk-lcore-mask': '0x51',
                'dpdk-socket-mem': '1024,1024',
                'dpdk-init': 'true',
                'dpdk-extra': '-a 0000:42:01.0',
            }}]
        self.assertTrue(self.target.configure_ovs_dpdk())
        opvs.open_vswitch.set.assert_called_once_with(
            '.', 'other_config:dpdk-lcore-mask', '0x42')

    def test_purge_packages(self):
        self.assertEquals(
            self.target.purge_packages,
            [
                'mlnx-switchdev-mode',
                'sriov-netplan-shim',
            ])

    def test_install(self):
        self.patch_target('configure_source')
        self.patch_target('run')
        self.patch_target('update_api_ports')
        self.patch_target('render_configs')
        self.patch_target('remove_obsolete_packages')
        self.patch_object(ovn_charm.ch_core.host, 'service_restart')
        self.patch_object(ovn_charm.reactive, 'is_flag_set', return_value=True)
        self.patch_object(ovn_charm.os.path, 'exists', return_value=False)
        self.enable_openstack.return_value = False
        self.target.install()
        self.run.assert_called_once_with(
            'update-alternatives', '--set', 'ovs-vswitchd',
            '/usr/lib/openvswitch-switch-dpdk/ovs-vswitchd-dpdk')

        # Confirm that vhost-user directory is setup when OpenStack enabled
        self.run.reset_mock()
        self.enable_openstack.return_value = True
        self.target.install()
        self.run.assert_has_calls([
            mock.call('update-alternatives', '--set', 'ovs-vswitchd',
                      '/usr/lib/openvswitch-switch-dpdk/ovs-vswitchd-dpdk'),
            mock.call('systemd-tmpfiles', '--create'),
        ])


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
            'vpd-device-spec':
            '[{"bus": "pci", "vendor_id": "beef", "device_id": "cafe"}]',
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
            mock.call(
                'ovs-vsctl',
                '--', 'set', 'open-vswitch', '.',
                'external-ids:ovn-encap-type=geneve',
                '--', 'set', 'open-vswitch', '.',
                'external-ids:ovn-encap-ip=fake-data-ip',
                '--', 'set', 'open-vswitch', '.',
                'external-ids:system-id=fake-ovs-hostname',
                '--', 'set', 'open-vswitch', '.',
                'external-ids:ovn-remote=fake-sb-conn-str',
                '--', 'set', 'open-vswitch', '.',
                'external_ids:ovn-match-northd-version=true',
            ),
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
            mock.call(
                'ovs-vsctl',
                '--', 'set', 'open-vswitch', '.',
                'external-ids:ovn-encap-type=geneve',
                '--', 'set', 'open-vswitch', '.',
                'external-ids:ovn-encap-ip=fake-data-ip',
                '--', 'set', 'open-vswitch', '.',
                'external-ids:system-id=fake-ovs-hostname',
                '--', 'set', 'open-vswitch', '.',
                'external-ids:ovn-remote=fake-sb-conn-str',
                '--', 'set', 'open-vswitch', '.',
                'external_ids:ovn-match-northd-version=true',
            ),
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

        self.patch_object(ovn_charm.OVNConfigurationAdapter,
                          'card_serial_number', new_callable=mock.PropertyMock)
        self.card_serial_number.return_value = 'c4rd-53r14l'

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
            mock.call('br-other', 'delete-port', linkdown=True),
            mock.call('br-int', 'delete-port', linkdown=True),
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
                      'enable-chassis-as-gw,card-serial-number=c4rd-53r14l'),
        ], any_order=True)

    def test_wrong_configure_bridges(self):
        self.patch_object(ovn_charm.os_context, 'BridgePortInterfaceMap')
        self.BridgePortInterfaceMap.side_effect = ValueError()
        self.patch_target('check_if_paused')
        self.check_if_paused.return_value = (None, None)
        self.assertEqual(self.target.custom_assess_status_last_check(),
                         (None, None))
        self.target.configure_bridges()
        self.BridgePortInterfaceMap.assert_called_once_with(
            bridges_key='bridge-interface-mappings')

        expected_msg = ('"Wrong format for bridge-interface-mappings. '
                        'Expected format is space-delimited list of '
                        'key-value pairs. Ex: "br-internet:00:00:5e:00:00:42 '
                        'br-provider:enp3s0f0""')

        self.assertEqual(
            self.target.custom_assess_status_last_check(),
            ('blocked', f'{self.target.bridges_key}: {expected_msg}'))

    def test_wrong_vpd_spec(self):
        self.target.options.vpd_device_spec = '{'
        self.patch_target('check_if_paused')
        self.check_if_paused.return_value = (None, None)
        self.assertEqual(self.target.custom_assess_status_last_check(),
                         (None, None))
        self.assertIsNone(self.target.options.card_serial_number)

        self.assertEqual(
            self.target.custom_assess_status_last_check(),
            ('blocked',
             'vpd-device-spec: "Invalid JSON provided for VPD device spec: {"')
        )

    def test_wrong_multiple(self):
        """Test rendering of multiple config validation errors"""
        self.target.options.vpd_device_spec = '{'
        self.patch_target('check_if_paused')
        self.check_if_paused.return_value = (None, None)
        self.assertEqual(self.target.custom_assess_status_last_check(),
                         (None, None))
        self.assertIsNone(self.target.options.card_serial_number)

        self.patch_object(ovn_charm.os_context, 'BridgePortInterfaceMap')
        self.BridgePortInterfaceMap.side_effect = ValueError()
        self.target.configure_bridges()

        self.assertEqual(
            self.target.custom_assess_status_last_check(),
            ('blocked',
             'vpd-device-spec: "Invalid JSON provided for VPD device spec: {",'
             ' bridge-interface-mappings: "Wrong format for'
             ' bridge-interface-mappings. Expected format is space-delimited'
             ' list of key-value pairs. Ex: "br-internet:00:00:5e:00:00:42'
             ' br-provider:enp3s0f0""')
        )

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

    def test_purge_packages(self):
        self.assertEquals(
            self.target.purge_packages,
            [
                'mlnx-switchdev-mode',
                'sriov-netplan-shim',
                'openvswitch-switch-dpdk',
            ])

    def test_install(self):
        self.patch_target('configure_source')
        self.patch_target('run')
        self.patch_target('update_api_ports')
        self.patch_target('render_configs')
        self.patch_target('remove_obsolete_packages')
        self.patch_object(ovn_charm.ch_core.host, 'service_restart')
        self.patch_object(ovn_charm.reactive, 'is_flag_set',
                          side_effect=[False, True])
        self.target.install()
        self.render_configs.assert_called_once_with(
            ['/etc/default/openvswitch-switch'])
        self.service_restart.assert_called_once_with(
            'openvswitch-switch')

        # Check that Open vSwitch is restarted when DPDK is disabled
        self.remove_obsolete_packages.return_value = True
        self.patch_object(ovn_charm.reactive, 'is_flag_set',
                          side_effect=[False, True])
        self.service_restart.reset_mock()
        self.target.install()
        self.service_restart.assert_has_calls([
            mock.call('openvswitch-switch'),
            mock.call('openvswitch-switch'),
        ])

    def test_configure_ovs_hw_offload(self):
        # Confirm that config is removed when HW offload is disabled
        self.patch_object(ovn_charm.ch_ovsdb, 'SimpleOVSDB')
        ovsdb = mock.MagicMock()
        ovsdb.open_vswitch.__iter__.return_value = [{
            'other_config': {
                'hw-offload': 'true',
                'max-idle': '30000',
            },
        }]
        self.SimpleOVSDB.return_value = ovsdb
        self.assertTrue(self.target.configure_ovs_hw_offload())
        ovsdb.open_vswitch.remove.assert_has_calls([
            mock.call('.', 'other_config', 'hw-offload'),
            mock.call('.', 'other_config', 'max-idle'),
        ])

        # Confirm that we don't request restart when nothing changed
        ovsdb.open_vswitch.__iter__.return_value = [{
            'other_config': {'some-other-key-we-dont-care-about': 42}}]
        self.assertFalse(self.target.configure_ovs_hw_offload())

    def test_configure_ovs_dpdk(self):
        # Confirm that config is removed when DPDK is disabled
        self.patch_object(ovn_charm.ch_ovsdb, 'SimpleOVSDB')
        opvs = mock.MagicMock()
        self.SimpleOVSDB.return_value = opvs

        # Existing config, confirm restart and values removed as expected
        opvs.open_vswitch.__iter__.return_value = [
            {'other_config': {
                'dpdk-lcore-mask': '0x42',
                'dpdk-socket-mem': '1024,1024',
                'dpdk-init': 'true',
                'dpdk-extra': '-a 0000:42:01.0',
            }}]
        self.assertTrue(self.target.configure_ovs_dpdk())
        opvs.open_vswitch.remove.assert_has_calls([
            mock.call('.', 'other_config', 'dpdk-lcore-mask'),
            mock.call('.', 'other_config', 'dpdk-socket-mem'),
            mock.call('.', 'other_config', 'dpdk-init'),
            mock.call('.', 'other_config', 'dpdk-extra'),
        ])

        opvs.open_vswitch.__iter__.return_value = [{
            'other_config': {'some-other-key-we-dont-care-about': 42}}]
        self.assertFalse(self.target.configure_ovs_dpdk())


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
            'neutron-sriov-agent',
            'neutron-ovn-metadata-agent',
        ])
        self.assertDictEqual(self.target.restart_map, {
            '/etc/netplan/150-charm-ovn.yaml': [],
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
        self.patch_target('remove_obsolete_packages')
        self.patch_object(ovn_charm.ch_core.host, 'service_restart')
        self.patch_object(ovn_charm.reactive, 'is_flag_set',
                          return_value=False)
        self.patch_object(ovn_charm.ch_core.hookenv, 'config')
        self.config.return_value = None
        self.target.install()
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
        ])
        self.assertDictEqual(self.target.restart_map, {
            '/etc/netplan/150-charm-ovn.yaml': [],
            '/etc/default/openvswitch-switch': [],
            '/etc/openvswitch/system-id.conf': [],
        })
        self.assertEquals(self.target.group, 'root')

    def test_install(self):
        self.patch_target('configure_source')
        self.patch_target('run')
        self.patch_target('update_api_ports')
        self.target.install()

    def test_configure_ovs_hw_offload(self):
        self.patch_object(ovn_charm.ch_ovsdb, 'SimpleOVSDB')
        ovsdb = mock.MagicMock()
        ovsdb.open_vswitch.__iter__.return_value = [{
            'other_config': {
                'hw-offload': 'true',
                'max-idle': '30000',
            },
        }]
        self.SimpleOVSDB.return_value = ovsdb
        self.assertFalse(self.target.configure_ovs_hw_offload())
        ovsdb.open_vswitch.set.assert_not_called()
        ovsdb.open_vswitch.__iter__.return_value = [{
            'other_config': {
                'hw-offload': 'false',
                'max-idle': '30000',
            },
        }]
        self.assertTrue(self.target.configure_ovs_hw_offload())
        ovsdb.open_vswitch.set.assert_called_once_with(
            '.', 'other_config:hw-offload', 'true')
        ovsdb.open_vswitch.__iter__.return_value = [{
            'other_config': {
                'hw-offload': 'true',
                'max-idle': '42',
            },
        }]
        ovsdb.open_vswitch.set.reset_mock()
        self.assertTrue(self.target.configure_ovs_hw_offload())
        ovsdb.open_vswitch.set.assert_called_once_with(
            '.', 'other_config:max-idle', '30000')
