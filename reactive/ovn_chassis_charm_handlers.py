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
import os

import charmhelpers.core as ch_core

import charms.reactive as reactive

import charms_openstack.bus
import charms_openstack.charm as charm


charms_openstack.bus.discover(os.path.join('lib', 'charms'))
OVN_CHASSIS_ENABLE_HANDLERS_FLAG = 'charm.ovn.chassis.enable-handlers'


@reactive.when(OVN_CHASSIS_ENABLE_HANDLERS_FLAG)
def enable_chassis_reactive_code():
    charm.use_defaults(
        'charm.installed',
        'config.changed',
        'update-status',
        'upgrade-charm',
        'certificates.available',
    )


@reactive.when(OVN_CHASSIS_ENABLE_HANDLERS_FLAG)
@reactive.when_not('nova-compute.connected')
def disable_metadata():
    reactive.clear_flag('charm.ovn-chassis.enable-openstack-metadata')


@reactive.when(OVN_CHASSIS_ENABLE_HANDLERS_FLAG, 'nova-compute.connected')
def enable_metadata():
    reactive.set_flag('charm.ovn-chassis.enable-openstack-metadata')
    nova_compute = reactive.endpoint_from_flag('nova-compute.connected')
    nova_compute.publish_shared_secret()
    with charm.provide_charm_instance() as charm_instance:
        charm_instance.install()
        charm_instance.render_with_interfaces(nova_compute)
        charm_instance.assess_status()


@reactive.when(OVN_CHASSIS_ENABLE_HANDLERS_FLAG, 'charm.installed')
@reactive.when_any('config.changed.ovn-bridge-mappings',
                   'config.changed.interface-bridge-mappings',
                   'run-default-upgrade-charm')
def configure_bridges():
    with charm.provide_charm_instance() as charm_instance:
        charm_instance.configure_bridges()
        reactive.clear_flag('config.changed.ovn-bridge-mappings')
        reactive.clear_flag('config.changed.interface-bridge-mappings')
        charm_instance.assess_status()


@reactive.when(OVN_CHASSIS_ENABLE_HANDLERS_FLAG,
               'ovsdb.available',
               'certificates.available',
               'endpoint.certificates.changed')
def configure_ovs():
    ovsdb = reactive.endpoint_from_flag('ovsdb.available')
    with charm.provide_charm_instance() as charm_instance:
        charm_instance.configure_ovs(ovsdb)
        reactive.clear_flag('endpoint.certificates.changed')
        charm_instance.assess_status()
