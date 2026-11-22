import copy
import os
import unittest
from unittest.mock import Mock, patch
from datetime import datetime, timezone

import fencing
from policy import Blocked

NOW = 10_000
NAME = 'worker8'
ACTION = {'id': 'failed', 'verified_cycle_failed': True, 'boot': 'boot', 'uid': 'uid', 'at': NOW-1200}
TAINT = {'key': 'preserve', 'effect': 'NoSchedule', 'value': 'yes'}


class FencingTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {'POE_ONLY_FENCE_WORKERS': '["worker8"]'})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.b = Mock()
        self.b.config = {'nodes': {NAME: {'address': '192.0.2.8', 'port': 8, 'mac': 'pinned'}},
                         'node_exporter_port': 9796, 'switch_legacy_id': 'legacy'}
        self.node = {'metadata': {'uid': 'uid', 'resourceVersion': 'rv', 'labels': {}, 'name': NAME},
                     'status': {'nodeInfo': {'bootID': 'boot'},
                                'conditions': [{'type': 'Ready', 'status': 'Unknown'}],
                                'addresses': [{'type': 'InternalIP', 'address': '192.0.2.8'}]},
                     'spec': {'taints': [TAINT]}}
        self.b.scalar.return_value = 0
        self.b.node.return_value = self.node
        self.incident = dict(ACTION)
        self.ledger = Mock(spec=['read', 'mark_fence', 'assert_fence_owner'])
        self.ledger.read.return_value = ({}, {'unresolved': {NAME: self.incident}})
        self.b.kube.return_value = ({'spec': {'renewTime': '1970-01-01T00:00:00Z'}}, NOW)
        self.ports = [{'port_idx': 1, 'name': 'untouched'}, {'port_idx': 8, 'poe_mode': 'auto'}]
        self.initial = ({'cfgversion': 'v', 'port_overrides': self.ports, 'last_seen': NOW},
                        self.ports[1], {'poe_good': True, 'poe_power': '4.0'}, {'poe': {'enabled': True}})
        self.b.unifi.return_value = {'meta': {'rc': 'ok'}}

    def off_sample(self, seen):
        return ({'last_seen': seen}, {'poe_mode': 'off'},
                {'poe_mode': 'off', 'up': False, 'poe_enable': False, 'poe_good': False, 'poe_power': '0.00'},
                {'state': 'DOWN', 'poe': {'enabled': False, 'state': 'DOWN'}})

    def run_case(self, samples):
        with patch.object(fencing, 'worker_context', return_value=(self.node, {'peer'})), \
                patch.object(fencing, 'database_quorum'), patch.object(fencing, 'stranded_volumes') as storage, \
                patch.object(fencing, 'physical_port', side_effect=samples):
            result = fencing.reconcile(self.b, self.ledger, NAME, lambda _: False, Mock())
        return result, storage

    def test_power_off_then_resource_version_fenced_taint(self):
        samples = [self.initial, self.initial] + [self.off_sample(t) for t in (NOW, NOW+30, NOW+30)]
        result, storage = self.run_case(samples)
        self.assertTrue(result)
        self.assertEqual(storage.call_count, 2)
        self.ledger.mark_fence.assert_called_once_with(NAME, 'failed')
        self.assertEqual(self.b.unifi.call_args.args[2]['port_overrides'],
                         [self.ports[0], {'port_idx': 8, 'poe_mode': 'off'}])
        self.assertEqual(self.ports[1]['poe_mode'], 'auto')
        path, method, patch_ops = self.b.kube.call_args.args
        self.assertEqual((path, method), ('/api/v1/nodes/worker8', 'PATCH'))
        self.assertEqual([p['value'] for p in patch_ops[:2]], ['rv', 'uid'])
        self.assertEqual(patch_ops[-1]['value'], [TAINT, {'key': fencing.OUT_OF_SERVICE,
                                                          'effect': 'NoExecute', 'value': 'nodeshutdown'}])

    def test_ambiguous_write_is_never_reissued_or_treated_as_power_off(self):
        self.incident['power_off_requested'] = True
        with self.assertRaisesRegex(Blocked, 'persistent_power_off_unconfirmed'):
            self.run_case([self.initial] * 10)
        self.b.unifi.assert_not_called()
        self.assertFalse(any(len(call.args) > 1 for call in self.b.kube.call_args_list))

    def test_resumes_from_verified_off_after_restart(self):
        self.incident['power_off_requested'] = True
        self.run_case([self.off_sample(t) for t in (NOW, NOW, NOW+40, NOW+40)])
        self.b.unifi.assert_not_called()
        self.assertEqual(self.b.kube.call_args.args[1], 'PATCH')

    def test_cached_telemetry_and_nonzero_wattage_do_not_fence(self):
        sample = self.off_sample(NOW)
        self.incident['power_off_requested'] = True
        for watts in ('0.00', '0.10'):
            sample[2]['poe_power'] = watts
            with self.assertRaisesRegex(Blocked, 'persistent_power_off_unconfirmed'):
                self.run_case([sample] * 10)
            self.assertFalse(any(len(c.args) > 1 for c in self.b.kube.call_args_list))

    def test_changed_port_configuration_stops_write(self):
        changed = copy.deepcopy(self.initial)
        changed[0]['cfgversion'] = 'new'
        with self.assertRaisesRegex(Blocked, 'switch_configuration_changed'):
            self.run_case([self.initial, changed])
        self.b.unifi.assert_not_called()

    def test_legacy_failure_and_changed_boot_cannot_trigger_fence(self):
        self.incident.pop('verified_cycle_failed')
        self.assertFalse(self.run_case([])[0])
        self.incident.update(ACTION)
        self.node['status']['nodeInfo']['bootID'] = 'rebooted'
        self.assertFalse(self.run_case([])[0])
        self.b.unifi.assert_not_called()

    def test_worker_and_peer_guards(self):
        peers = []
        for i in range(3):
            n = copy.deepcopy(self.node)
            n['metadata'].update(name=str(i), labels={'node-role.kubernetes.io/control-plane': 'true'})
            n['status']['conditions'][0]['status'] = 'True'
            peers.append(n)
            self.b.config['nodes'][str(i)] = {'address': str(i)}
        renewed = datetime.fromtimestamp(ACTION['at']-2, timezone.utc).isoformat()
        self.b.kube.side_effect = lambda path: ({'items': [self.node]+peers} if path.endswith('/nodes')
                                                 else {'spec': {'renewTime': renewed}}, NOW)
        self.b.probe.side_effect = lambda ip, port: 'no_reply' if ip == '192.0.2.8' else 'responding'
        with patch('fencing.time.time', return_value=NOW):
            self.assertEqual(fencing.worker_context(self.b, NAME, ACTION)[1], {'0', '1', '2'})
            self.node['metadata']['labels']['node-role.kubernetes.io/etcd'] = 'true'
            with self.assertRaisesRegex(Blocked, 'worker_fencing_only'):
                fencing.worker_context(self.b, NAME, ACTION)
            self.node['metadata']['labels'].clear()
            peers[0]['status']['conditions'][0]['status'] = 'False'
            with self.assertRaisesRegex(Blocked, 'isolated_failure_required'):
                fencing.worker_context(self.b, NAME, ACTION)

    def test_missing_surviving_replica_blocks_release(self):
        objects = {'/apis/storage.k8s.io/v1/volumeattachments': {'items': [
            {'spec': {'nodeName': NAME, 'attacher': 'driver.longhorn.io',
                      'source': {'persistentVolumeName': 'pv'}}, 'status': {'attached': True}}]},
            '/api/v1/persistentvolumes/pv': {'spec': {'csi': {'driver': 'driver.longhorn.io', 'volumeHandle': 'pv'}}},
            fencing.LH+'engines': {'items': [{'spec': {'volumeName': 'pv', 'active': True},
                                              'status': {'replicaModeMap': {'rep': 'RW'}}}]},
            fencing.LH+'replicas': {'items': [{'metadata': {'name': 'rep'}, 'spec': {'nodeID': NAME, 'volumeName': 'pv'},
                                               'status': {'currentState': 'running'}}]}}
        self.b.kube.side_effect = lambda path: (objects[path], NOW)
        with self.assertRaisesRegex(Blocked, 'no_surviving_rw_replica'):
            fencing.stranded_volumes(self.b, NAME, {'peer'})
        objects[fencing.LH+'replicas']['items'][0]['spec']['nodeID'] = 'peer'
        fencing.stranded_volumes(self.b, NAME, {'peer'})
