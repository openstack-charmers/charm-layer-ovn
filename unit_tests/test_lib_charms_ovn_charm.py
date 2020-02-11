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

import io
import mock
import os

import charms_openstack.test_utils as test_utils

import charms.ovn_charm as ovn_charm


class TestOVNConfigProperties(test_utils.PatchHelper):

    def test_ovn_key(self):
        self.assertEquals(ovn_charm.ovn_key(None),
                          os.path.join(ovn_charm.OVS_ETCDIR, 'key_host'))

    def test_ovn_cert(self):
        self.assertEquals(ovn_charm.ovn_cert(None),
                          os.path.join(ovn_charm.OVS_ETCDIR, 'cert_host'))

    def test_ovn_ca_cert(self):
        cls = mock.MagicMock()
        cls.charm_instance.name = mock.PropertyMock().return_value = 'name'
        self.assertEquals(ovn_charm.ovn_ca_cert(cls),
                          os.path.join(ovn_charm.OVS_ETCDIR, 'name.crt'))


class Helper(test_utils.PatchHelper):

    def setUp(self):
        super().setUp()
        self.patch_release(ovn_charm.BaseOVNChassisCharm.release)
        self.patch_object(ovn_charm.reactive, 'is_flag_set',
                          return_value=False)
        self.patch_object(
            ovn_charm.charms_openstack.adapters, '_custom_config_properties')
        self._custom_config_properties.side_effect = {}
        self.target = ovn_charm.BaseOVNChassisCharm()
        # remove the 'is_flag_set' patch so the tests can use it
        self._patches['is_flag_set'].stop()
        setattr(self, 'is_flag_set', None)
        del(self._patches['is_flag_set'])
        del(self._patches_start['is_flag_set'])

    def patch_target(self, attr, return_value=None):
        mocked = mock.patch.object(self.target, attr)
        self._patches[attr] = mocked
        started = mocked.start()
        started.return_value = return_value
        self._patches_start[attr] = started
        setattr(self, attr, started)


class TestOVNChassisCharm(Helper):

    def test_optional_openstack_metadata(self):
        self.assertEquals(self.target.packages, ['ovn-host'])
        self.assertEquals(self.target.services, ['ovn-host'])
        self.patch_object(
            ovn_charm.charms_openstack.adapters, '_custom_config_properties')
        self._custom_config_properties.side_effect = {}
        self.patch_object(ovn_charm.reactive, 'is_flag_set',
                          return_value=True)
        c = ovn_charm.BaseOVNChassisCharm()
        self.assertEquals(c.packages, [
            'ovn-host', 'networking-ovn-metadata-agent', 'haproxy'
        ])
        self.assertEquals(c.services, [
            'ovn-host', 'networking-ovn-metadata-agent'])

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

    def test_get_certificate_request(self):
        self.patch_target('get_ovs_hostname')
        self.get_ovs_hostname.return_value = 'fake-ovs-hostname'
        self.assertDictEqual(
            self.target.get_certificate_request(),
            {'fake-ovs-hostname': {'sans': []}})

    def test_configure_tls(self):
        self.patch_target('get_certs_and_keys')
        self.get_certs_and_keys.return_value = [{
            'cert': 'fakecert',
            'key': 'fakekey',
            'cn': 'fakecn',
            'ca': 'fakeca',
            'chain': 'fakechain',
        }]
        with mock.patch('builtins.open', create=True) as mocked_open:
            mocked_file = mock.MagicMock(spec=io.FileIO)
            mocked_open.return_value = mocked_file
            self.target.configure_cert = mock.MagicMock()
            self.target.run = mock.MagicMock()
            self.target.configure_tls()
            mocked_open.assert_called_once_with(
                '/etc/openvswitch/charmname.crt', 'w')
            mocked_file.__enter__().write.assert_called_once_with(
                'fakeca\nfakechain')
            self.target.configure_cert.assert_called_once_with(
                ovn_charm.OVS_ETCDIR,
                'fakecert',
                'fakekey',
                cn='host')

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
        self.patch_object(ovn_charm.ovn, 'SimpleOVSDB')
        opvs = mock.MagicMock()
        opvs.__iter__.return_value = [
            {'external_ids': {'hostname': 'fake-ovs-hostname'}}]
        self.SimpleOVSDB.return_value = opvs
        self.assertEquals(self.target.get_ovs_hostname(), 'fake-ovs-hostname')

    def test_configure_ovs(self):
        self.patch_target('run')
        self.patch_object(ovn_charm, 'ovn_key')
        self.patch_object(ovn_charm, 'ovn_cert')
        self.patch_object(ovn_charm, 'ovn_ca_cert')
        self.patch_target('get_data_ip')
        self.get_data_ip.return_value = 'fake-data-ip'
        self.patch_target('get_ovs_hostname')
        self.get_ovs_hostname.return_value = 'fake-ovs-hostname'
        self.target.configure_ovs('fake-sb-conn-str')
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
        self.run.reset_mock()
        self.target.enable_openstack = True
        self.patch_object(ovn_charm.ovn, 'SimpleOVSDB')
        managers = mock.MagicMock()
        self.SimpleOVSDB.return_value = managers
        self.target.configure_ovs('fake-sb-conn-str')
        managers.find.assert_called_once_with(
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

    def test_configure_bridges(self):
        self.patch_object(ovn_charm.os_context, 'NeutronPortContext')
        npc = mock.MagicMock()

        def _fake_resolve_ports(mac_or_if):
            result = []
            for entry in mac_or_if:
                if ':' in entry:
                    result.append('eth0')
                    continue
                result.append(entry)
            return result

        npc.resolve_ports.side_effect = _fake_resolve_ports
        self.NeutronPortContext.return_value = npc
        self.patch_target('config')
        self.config.__getitem__.side_effect = [
            'br-provider:00:01:02:03:04:05 br-other:eth5',
            'provider:br-provider other:br-other']
        self.patch_object(ovn_charm.ovn, 'SimpleOVSDB')
        bridges = mock.MagicMock()
        bridges.find.side_effect = [
            [
                {'name': 'delete-bridge'},
                {'name': 'br-other'}
            ],
            StopIteration,
        ]
        ports = mock.MagicMock()
        ports.find.side_effect = [[{'name': 'delete-port'}]]
        opvs = mock.MagicMock()
        self.SimpleOVSDB.side_effect = [bridges, ports, opvs]
        self.patch_object(ovn_charm.ovn, 'del_br')
        self.patch_object(ovn_charm.ovn, 'del_port')
        self.patch_object(ovn_charm.ovn, 'add_br')
        self.patch_object(ovn_charm.ovn, 'list_ports')
        self.list_ports().__iter__.return_value = []
        self.patch_object(ovn_charm.ovn, 'add_port')
        self.patch_target('run')
        self.target.configure_bridges()
        npc.resolve_ports.assert_has_calls([
            mock.call(['00:01:02:03:04:05']),
            mock.call(['eth5']),
        ], any_order=True)
        bridges.find.assert_has_calls([
            mock.call('name=br-provider'),
            mock.call('name=br-other'),
        ], any_order=True)
        self.del_br.assert_called_once_with('delete-bridge')
        self.del_port.assert_called_once_with('br-other', 'delete-port')
        self.add_br.assert_has_calls([
            mock.call('br-provider', ('charm-ovn-chassis', 'managed')),
            mock.call('br-other', ('charm-ovn-chassis', 'managed')),
        ], any_order=True)
        self.add_port.assert_has_calls([
            mock.call(
                'br-provider', 'eth0', ifdata={
                    'external-ids': {'charm-ovn-chassis': 'br-provider'}}),
            mock.call(
                'br-other', 'eth5', ifdata={
                    'external-ids': {'charm-ovn-chassis': 'br-other'}}),
        ], any_order=True)
        self.run.assert_has_calls([
            mock.call('ip', 'link', 'set', 'eth0', 'up'),
            mock.call('ip', 'link', 'set', 'eth5', 'up'),
        ], any_order=True)
        opvs.set.assert_has_calls([
            mock.call('.', 'external_ids:ovn-bridge-mappings',
                      'other:br-other,provider:br-provider'),
            mock.call('.', 'external_ids:ovn-cms-options',
                      'enable-chassis-as-gw'),
        ])
