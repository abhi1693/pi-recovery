"""Escalate a confirmed failed reboot of a PoE-only worker with stranded storage."""
import copy
import json
import os
import time
from datetime import datetime

from policy import exporter_instance, require

OUT_OF_SERVICE = 'node.kubernetes.io/out-of-service'
CONTROL_ROLES = {'node-role.kubernetes.io/control-plane', 'node-role.kubernetes.io/master',
                 'node-role.kubernetes.io/etcd'}
LH = '/apis/longhorn.io/v1beta2/namespaces/longhorn-system/'


def ready(node):
    return any(c['type'] == 'Ready' and c['status'] == 'True' for c in node['status']['conditions'])


def worker_context(backend, name, action):
    nodes = backend.kube('/api/v1/nodes')[0]['items']
    require({n['metadata']['name'] for n in nodes} == set(backend.config['nodes']), 'inventory_changed')
    target = next(n for n in nodes if n['metadata']['name'] == name)
    require(not CONTROL_ROLES.intersection(target['metadata']['labels']), 'worker_fencing_only')
    require(target['metadata']['uid'] == action['uid'] and target['status']['nodeInfo']['bootID'] == action['boot'],
            'fence_target_changed')
    require(not target['spec'].get('unschedulable') and not target['metadata'].get('deletionTimestamp')
            and not any(n['metadata'].get('annotations', {}).get(backend.config.get('maintenance_annotation', os.getenv('PI_RECOVERY_MAINTENANCE_KEY', 'pi-recovery.io/maintenance'))) == 'true'
                        or n['spec'].get('unschedulable') for n in nodes), 'maintenance_active')
    require(any(c['type'] == 'Ready' and c['status'] == 'Unknown' for c in target['status']['conditions'])
            and all(ready(n) for n in nodes if n is not target), 'isolated_failure_required')
    peers = [n for n in nodes if n is not target]
    require(sum(bool(CONTROL_ROLES.intersection(n['metadata']['labels'])) for n in peers) >= 3,
            'control_plane_quorum_unhealthy')
    lease = backend.kube('/apis/coordination.k8s.io/v1/namespaces/kube-node-lease/leases/' + name)[0]
    renewed = datetime.fromisoformat(lease['spec']['renewTime'].replace('Z', '+00:00')).timestamp()
    require(renewed <= action['at'], 'worker_renewed_after_cycle')
    require(time.time() - max(renewed, action['at']) >= 900, 'waiting_for_worker_recovery')
    address = backend.config['nodes'][name]['address']
    require(any(a['type'] == 'InternalIP' and a['address'] == address for a in target['status']['addresses']),
            'fence_address_changed')
    require(all(backend.probe(address, p) == 'no_reply' for p in (22, 10250, backend.config['node_exporter_port'])),
            'worker_responding')
    require(all(backend.probe(backend.config['nodes'][n['metadata']['name']]['address'], 22) == 'responding'
                for n in peers), 'peer_probe_failed')
    selector = 'up{job="node-exporter",instance=' + json.dumps(exporter_instance(backend.config, name)) + '}'
    require(backend.scalar('max_over_time(' + selector + '[5m])') == 0
            and 0 <= backend.scalar('time()-timestamp(' + selector + ')') <= 90, 'target_scrape_not_down')
    return target, {n['metadata']['name'] for n in peers}


def database_quorum(backend, peers):
    clusters = backend.kube('/apis/postgresql.cnpg.io/v1/clusters')[0]['items']
    require(bool(clusters), 'database_quorum_unconfirmed')
    for cluster in clusters:
        status = cluster['status']
        primary = status.get('currentPrimary')
        require(primary and status.get('targetPrimary', primary) == primary
                and status.get('readyInstances', 0) > cluster['spec']['instances'] // 2,
                'database_quorum_unconfirmed')
        pod = backend.kube('/api/v1/namespaces/' + cluster['metadata']['namespace'] + '/pods/' + primary)[0]
        require(pod['spec'].get('nodeName') in peers and ready(pod) and not pod['metadata'].get('deletionTimestamp')
                and any(owner['uid'] == cluster['metadata']['uid'] for owner in pod['metadata']['ownerReferences']),
                'database_primary_unconfirmed')


def stranded_volumes(backend, name, peers):
    attachments = backend.kube('/apis/storage.k8s.io/v1/volumeattachments')[0]['items']
    affected = [a for a in attachments if a['spec']['nodeName'] == name and a['status'].get('attached')]
    require(bool(affected), 'no_stranded_volumes')
    require(all(a['spec']['attacher'] == 'driver.longhorn.io' for a in affected), 'unverified_storage_driver')
    engines = backend.kube(LH + 'engines')[0]['items']
    replicas = {r['metadata']['name']: r for r in backend.kube(LH + 'replicas')[0]['items']}
    for a in affected:
        pv = a['spec']['source']['persistentVolumeName']
        volume = backend.kube('/api/v1/persistentvolumes/' + pv)[0]['spec']['csi']
        require(volume['driver'] == 'driver.longhorn.io', 'unverified_storage_driver')
        handle = volume['volumeHandle']
        active = [e for e in engines if e['spec']['volumeName'] == handle and e['spec']['active']]
        require(len(active) == 1, 'ambiguous_volume_engine')
        modes = active[0]['status'].get('replicaModeMap') or {}
        require(any(mode == 'RW' and key in replicas and replicas[key]['spec']['nodeID'] in peers
                    and replicas[key]['spec']['volumeName'] == handle and not replicas[key]['spec'].get('failedAt')
                    and replicas[key]['status']['currentState'] == 'running' for key, mode in modes.items()),
                'no_surviving_rw_replica')


def physical_port(backend, name):
    cfg = backend.config
    expected = cfg['nodes'][name]
    require(backend.unifi('/integration/v1/info')['applicationVersion'] == cfg['unifi_application_version'],
            'controller_version_changed')
    d = backend.unifi('/integration/v1/sites/' + cfg['site_id'] + '/devices/' + cfg['switch_id'])
    require(d['id'] == cfg['switch_id'] and d['macAddress'] == cfg['switch_mac'] and d['state'] == 'ONLINE',
            'switch_identity_changed')
    devices = backend.unifi('/api/s/default/stat/device')
    require(devices['meta']['rc'] == 'ok', 'switch_telemetry_unavailable')
    switch, = [s for s in devices['data'] if s['_id'] == cfg['switch_legacy_id'] and s['mac'] == cfg['switch_mac']]
    require(switch['state'] == 1 and -5 <= time.time() - switch['last_seen'] <= 75, 'stale_switch_evidence')
    port, = [p for p in switch['port_table'] if p['port_idx'] == expected['port']]
    public, = [p for p in d['interfaces']['ports'] if p['idx'] == expected['port']]
    override, = [o for o in switch['port_overrides'] if o['port_idx'] == expected['port']]
    require(override['port_security_enabled'] and override['port_security_mac_address'] == [expected['mac']]
            and port['port_security_mac_address'] == [expected['mac']] and not port['is_uplink']
            and port['mac_table_count'] in (0, 1) and port.get('last_connection', {}).get('mac') == expected['mac'],
            'fence_port_identity_unconfirmed')
    return switch, override, port, public


def off(sample):
    _, override, port, public = sample
    return (override['poe_mode'] == 'off' and port['poe_mode'] == 'off' and port['up'] is False
            and port['poe_enable'] is False and port['poe_good'] is False and float(port['poe_power']) == 0
            and public['state'] == 'DOWN' and public['poe']['enabled'] is False and public['poe']['state'] == 'DOWN')


def disable_power(backend, name, initial):
    switch, override, port, public = physical_port(backend, name)
    require(switch['cfgversion'] == initial['cfgversion'] and switch['port_overrides'] == initial['port_overrides'],
            'switch_configuration_changed')
    require(override['poe_mode'] == 'auto' and public['poe']['enabled'] and port['poe_good']
            and float(port['poe_power']) > 0, 'unverified_power_source')
    overrides = copy.deepcopy(switch['port_overrides'])
    next(p for p in overrides if p['port_idx'] == override['port_idx'])['poe_mode'] = 'off'
    result = backend.unifi('/api/s/default/rest/device/' + backend.config['switch_legacy_id'],
                           'PUT', {'port_overrides': overrides})
    require(result['meta']['rc'] == 'ok', 'power_off_not_accepted')


def reconcile(backend, ledger, node, wait, event):
    if node not in json.loads(os.environ.get('POE_ONLY_FENCE_WORKERS', '[]')):
        return False
    _, state = ledger.read()
    incident = state.get('unresolved', {}).get(node)
    if not incident or not incident.get('verified_cycle_failed'):
        return False
    target = backend.node(node)
    if target['metadata']['uid'] != incident['uid'] or target['status']['nodeInfo']['bootID'] != incident['boot']:
        return False
    if any(t['key'] == OUT_OF_SERVICE for t in target['spec'].get('taints', [])):
        return True
    lease = backend.kube('/apis/coordination.k8s.io/v1/namespaces/kube-node-lease/leases/' + node)[0]
    renewed = datetime.fromisoformat(lease['spec']['renewTime'].replace('Z', '+00:00')).timestamp()
    if renewed > incident['at']:
        return False
    _, peers = worker_context(backend, node, incident)
    database_quorum(backend, peers)
    stranded_volumes(backend, node, peers)
    initial = physical_port(backend, node)
    if not incident.get('power_off_requested'):
        require(not off(initial), 'unexpected_power_off')
        worker_context(backend, node, incident)
        ledger.mark_fence(node, incident['id'])
        disable_power(backend, node, initial[0])
        event('worker_power_off_requested', node=node, action_id=incident['id'])
    # A lost reply or restart resumes observation only. Never resend the write.
    first = None
    for _ in range(9):
        require(not wait(10), 'shutting_down')
        sample = physical_port(backend, node)
        if not off(sample):
            first = None
            continue
        seen = sample[0]['last_seen']
        if first is None:
            first = seen
        if seen - first >= 30:
            break
    else:
        require(False, 'persistent_power_off_unconfirmed')
    target, peers = worker_context(backend, node, incident)
    database_quorum(backend, peers)
    stranded_volumes(backend, node, peers)
    ledger.assert_fence_owner(node, incident['id'])
    require(off(physical_port(backend, node)), 'persistent_power_off_unconfirmed')
    taints = target['spec'].get('taints', [])
    require(not any(t['key'] == OUT_OF_SERVICE for t in taints), 'already_out_of_service')
    patch = [{'op': 'test', 'path': '/metadata/resourceVersion', 'value': target['metadata']['resourceVersion']},
             {'op': 'test', 'path': '/metadata/uid', 'value': incident['uid']},
             {'op': 'add', 'path': '/spec/taints', 'value': taints + [
                 {'key': OUT_OF_SERVICE, 'effect': 'NoExecute', 'value': 'nodeshutdown'}]}]
    backend.kube('/api/v1/nodes/' + node, 'PATCH', patch)
    event('worker_fenced', node=node, action_id=incident['id'])
    return True
