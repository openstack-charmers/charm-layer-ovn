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
import contextlib

import charmhelpers.core as ch_core

import charms.reactive as reactive

import charms_openstack.bus
import charms_openstack.charm as charm

from charms.layer import snap

charms_openstack.bus.discover()
OVN_CHASSIS_ENABLE_HANDLERS_FLAG = 'charm.ovn.chassis.enable-handlers'


@reactive.when(OVN_CHASSIS_ENABLE_HANDLERS_FLAG)
def enable_chassis_reactive_code():
    charm.use_defaults(
        'charm.installed',
        'config.changed',
        'config.rendered',
        'update-status',
        'upgrade-charm',
        'certificates.available',
    )


@reactive.when_none('charm.installed', 'charm.paused')
@reactive.when(OVN_CHASSIS_ENABLE_HANDLERS_FLAG, 'config.set.new-units-paused')
def pause_unit_from_config():
    with charm.provide_charm_instance() as instance:
        instance.pause()
        instance.assess_status()


# Note that RabbitMQ is only used for the Neutron SR-IOV agent
@reactive.when_none('charm.paused', 'is-update-status-hook')
@reactive.when(OVN_CHASSIS_ENABLE_HANDLERS_FLAG, 'amqp.connected')
def amqp_connection():
    amqp = reactive.endpoint_from_flag('amqp.connected')
    with charm.provide_charm_instance() as instance:
        amqp.request_access(username='neutron', vhost='openstack')
        instance.assess_status()


@reactive.when_none('charm.paused', 'is-update-status-hook',
                    'nova-compute.connected')
@reactive.when(OVN_CHASSIS_ENABLE_HANDLERS_FLAG)
def disable_openstack():
    reactive.clear_flag('charm.ovn-chassis.enable-openstack')


@reactive.when_none('charm.paused', 'is-update-status-hook')
@reactive.when(OVN_CHASSIS_ENABLE_HANDLERS_FLAG, 'nova-compute.connected')
def enable_openstack():
    reactive.set_flag('charm.ovn-chassis.enable-openstack')
    nova_compute = reactive.endpoint_from_flag('nova-compute.connected')
    nova_compute.publish_shared_secret()
    with charm.provide_charm_instance() as charm_instance:
        charm_instance.install()
        charm_instance.assess_status()


@reactive.when_none('charm.paused', 'is-update-status-hook')
@reactive.when(OVN_CHASSIS_ENABLE_HANDLERS_FLAG,
               'ovsdb.available',
               'certificates.available')
def configure_ovs():
    ovsdb = reactive.endpoint_from_flag('ovsdb.available')
    with charm.provide_charm_instance() as charm_instance:
        if reactive.is_flag_set('config.changed.enable-dpdk'):
            # Install required packages and/or run update-alternatives
            charm_instance.install()
        charm_instance.render_with_interfaces(
            charm.optional_interfaces((ovsdb,),
                                      'nova-compute.connected',
                                      'amqp.connected'))
        charm_instance.configure_ovs(
            ','.join(ovsdb.db_sb_connection_strs),
            reactive.is_flag_set('config.changed.disable-mlockall'))
        reactive.set_flag('config.rendered')
        charm_instance.configure_bridges()
        charm_instance.assess_status()


@reactive.when_none('charm.paused', 'is-update-status-hook')
@reactive.when(OVN_CHASSIS_ENABLE_HANDLERS_FLAG, 'config.rendered')
@reactive.when_any('config.changed.nagios_context',
                   'config.changed.nagios_servicegroups',
                   'endpoint.nrpe-external-master.changed',
                   'nrpe-external-master.available')
def configure_nrpe():
    """Handle config-changed for NRPE options."""
    with charm.provide_charm_instance() as charm_instance:
        charm_instance.render_nrpe()


@reactive.when_none('charm.paused', 'is-update-status-hook')
@reactive.when(OVN_CHASSIS_ENABLE_HANDLERS_FLAG,
               'ovsdb-subordinate.available',
               'ovn.certs.changed')
def provide_chassis_certificates_to_principal():
    ovsdb_subordinate = reactive.endpoint_from_flag(
        'ovsdb-subordinate.available')
    try:
        # Support for passing a Tuple with multiple expressions to with
        # appeared in Python 3.9, until the versions up to 3.9 go out of
        # support we can use the ExitStack.
        with contextlib.ExitStack() as es:
            charm_instance = es.enter_context(
                charm.provide_charm_instance())
            ovn_ca_cert = es.enter_context(
                open(charm_instance.options.ovn_ca_cert, 'r'))
            ovn_cert = es.enter_context(
                open(charm_instance.options.ovn_cert, 'r'))
            ovn_key = es.enter_context(
                open(charm_instance.options.ovn_key, 'r'))
            ovsdb_subordinate.publish_chassis_certificates(
                    ovn_ca_cert.read(),
                    ovn_cert.read(),
                    ovn_key.read())
    except OSError as e:
        ch_core.hookenv.log('Unable to provide principal with '
                            'chassis certificates: "{}"'.format(str(e)),
                            level=ch_core.hookenv.WARNING)

    reactive.clear_flag('ovn.certs.changed')


@reactive.when_any('config.changed.ovs-exporter-channel',
                   'snap.installed.prometheus-ovs-exporter')
def reassess_exporter():
    is_installed = snap.is_installed('prometheus-ovs-exporter')
    channel = None
    with charm.provide_charm_instance() as instance:
        channel = instance.options.ovs_exporter_snap_channel

    if channel is None:
        # Attempt to remove the snap if it is present, the snap command
        # returns 0 if the snap is not installed.
        snap.remove('prometheus-ovs-exporter')
        return

    if is_installed:
        snap.refresh('prometheus-ovs-exporter', channel=channel,
                devmode=True)
    else:
        snap.install('prometheus-ovs-exporter', channel=channel,
                devmode=True)
