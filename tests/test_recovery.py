"""Exercise refusal scenarios, durable action fencing and the real HTTP receiver."""
import copy
from datetime import datetime, timezone
import http.client
import importlib.util
import json
from pathlib import Path
import sys
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1]))
import controller
from policy import Blocked, alert_target, confirm, cooldown_ok, review_required, snapshot_ok, stp_counters, validate_config

NOW = 1793286000.0


def config():
    return {'enabled': True, 'unifi_origin': 'https://192.168.3.1',
            'node_exporter_port': 9796, 'approved_kernel': 'approved-test-kernel',
            'cooldown_seconds': 300, 'max_unavailable_nodes': 2,
            'prometheus_origin': 'http://thanos-query.cattle-monitoring-system.svc:9090',
            'unifi_application_version': '10.6.109', 'site_id': '00000000-0000-0000-0000-000000000001',
            'switch_id': '00000000-0000-0000-0000-000000000002', 'switch_legacy_id': 'a' * 24,
            'unifi_certificate_sha256': 'a' * 64, 'webhook_token': 'unit-test-token-' * 4,
            'sample_interval_seconds': 35, 'switch_mac': '02:00:00:00:ff:01',
            'nodes': {f'k8s-rpi{i}': {'address': f'192.168.3.{100+i}',
                                    'mac': f'02:00:00:00:00:{i:02x}', 'port': i}
                      for i in range(1, 9)}}


def alert(now=NOW):
    return {'status': 'firing', 'startsAt': datetime.fromtimestamp(now-300, timezone.utc).isoformat(),
            'labels': {'alertname': 'RaspberryPiNetworkRecoveryCandidate', 'instance': '192.168.3.107:9796'}}


def sample(now=NOW, tx_toward_pi=1000):
    return {'at': now, 'api_time': now, 'observer_node': 'k8s-rpi4',
            'node_set': sorted(config()['nodes']), 'live_alert': True, 'target_ready': 'Unknown',
            'unavailable_nodes': ['k8s-rpi7'],
            'control_plane_nodes': ['k8s-rpi1', 'k8s-rpi2', 'k8s-rpi3'], 'control_plane_quorum_ok': True,
            'maintenance': False, 'kernel': config()['approved_kernel'], 'address': '192.168.3.107',
            'peers_ready': True, 'peers_scraped': True, 'peer_probes_ok': True,
            'target_probe_results': ['no_reply'] * 3, 'scrape_down': True, 'down_samples': 6,
            'pre_failure_at': now-300,
            'pre_failure_uptime': 300, 'cpu_evidence': 'rate', 'io_evidence': 'rate',
            'boot_age': 20000, 'cpu_pct': 15, 'memory_pct': 23, 'load_per_core': 0.2,
            'io_pressure_pct': 0.1, 'switch_online': True, 'switch_mac': config()['switch_mac'],
            'switch_seen': now-5, 'switch_uptime': 120000+now-NOW,
            'node_uid': 'existing-node-uid', 'boot_id': 'old-boot',
            'port': {'idx': 7, 'mac': '02:00:00:00:00:07', 'mac_count': 1, 'connected': True,
                     'up': True, 'poe_good': True, 'poe_enabled': True, 'power_watts': 6.5,
                     'stp': 'forwarding', 'uplink': False, 'rx_errors': 0, 'tx_errors': 0,
                     'rx_packets': 4000, 'tx_packets': tx_toward_pi,
                     'link_down_count': 2, 'stp_change_count': [{'change_count': 5, 'mst': 0}]}}


def samples():
    return [sample(NOW+i*35, 1000+i*100) for i in range(3)]


class PolicyTests(unittest.TestCase):
    def test_boot_averages_require_measured_uptime_and_valid_resource_values(self):
        item = sample(); item.update(cpu_evidence='boot_average', io_evidence='boot_average')
        snapshot_ok(item, 'k8s-rpi7', config(), NOW)
        item['pre_failure_uptime'] = 119
        with self.assertRaisesRegex(Blocked, 'insufficient_boot_evidence'):
            snapshot_ok(item, 'k8s-rpi7', config(), NOW)
        for key in ('cpu_pct', 'memory_pct', 'load_per_core', 'io_pressure_pct'):
            item = sample(); item[key] = -1
            with self.subTest(key=key), self.assertRaisesRegex(Blocked, 'resource_saturation'):
                snapshot_ok(item, 'k8s-rpi7', config(), NOW)

    def test_control_plane_priority_and_multi_node_health_guards(self):
        item = sample()
        item['unavailable_nodes'] = ['k8s-rpi3', 'k8s-rpi7']
        with self.assertRaisesRegex(Blocked, 'control_plane_recovery_priority'):
            snapshot_ok(item, 'k8s-rpi7', config(), NOW)
        item['address'] = config()['nodes']['k8s-rpi3']['address']
        item['port'].update(idx=3, mac=config()['nodes']['k8s-rpi3']['mac'])
        snapshot_ok(item, 'k8s-rpi3', config(), NOW)
        item['control_plane_quorum_ok'] = False
        with self.assertRaisesRegex(Blocked, 'control_plane_quorum_unhealthy'):
            snapshot_ok(item, 'k8s-rpi3', config(), NOW)
        item['control_plane_quorum_ok'] = True
        item['unavailable_nodes'].append('k8s-rpi8')
        with self.assertRaisesRegex(Blocked, 'too_many_nodes_unavailable'):
            snapshot_ok(item, 'k8s-rpi3', config(), NOW)

    def test_two_failed_workers_can_be_checked_without_weakening_other_gates(self):
        item = sample(); item['unavailable_nodes'] = ['k8s-rpi7', 'k8s-rpi8']
        snapshot_ok(item, 'k8s-rpi7', config(), NOW)
        item['peers_scraped'] = False
        with self.assertRaisesRegex(Blocked, 'other_nodes_or_observer_unhealthy'):
            snapshot_ok(item, 'k8s-rpi7', config(), NOW)

    def test_cooldown_defaults_to_five_minutes_and_can_be_changed(self):
        state = {'phase': 'completed', 'actions': [{'node': 'k8s-rpi7', 'at': NOW-299}]}
        with self.assertRaisesRegex(Blocked, 'global_cooldown'):
            cooldown_ok(state, 'k8s-rpi7', NOW)
        state['actions'][0]['at'] = NOW-300
        cooldown_ok(state, 'k8s-rpi7', NOW)
        with self.assertRaisesRegex(Blocked, 'global_cooldown'):
            cooldown_ok(state, 'k8s-rpi7', NOW, cooldown_seconds=600)

    def test_installation_settings_are_configurable_without_lab_specific_names(self):
        cfg = config()
        cfg['nodes'] = {'worker-a': {**cfg['nodes']['k8s-rpi1'], 'port': 17},
                        'worker-b': {**cfg['nodes']['k8s-rpi2'], 'port': 18}}
        cfg['unifi_origin'] = 'https://controller.example.com'
        cfg['prometheus_origin'] = 'http://prometheus.monitoring.svc:9090'
        cfg['node_exporter_port'] = 9100
        cfg['max_unavailable_nodes'] = 1
        validate_config(cfg)
        backend = controller.Backend({**cfg, 'lease_namespace': 'recovery', 'lease_name': 'recovery-lock'})
        self.assertEqual(backend.lease_path,
                         '/apis/coordination.k8s.io/v1/namespaces/recovery/leases/recovery-lock')

    def test_unreachable_alert_uses_the_allowlisted_node_not_the_metrics_exporter_address(self):
        item = alert()
        item['labels'] = {'alertname': 'KubeNodeUnreachable', 'node': 'k8s-rpi7',
                          'instance': 'metrics-exporter:8080'}
        self.assertEqual(alert_target(item, config(), NOW), 'k8s-rpi7')

    def test_newly_firing_alert_is_accepted_without_an_extra_two_minute_wait(self):
        for age in (0, 1, 119, 120):
            item = alert()
            item['startsAt'] = datetime.fromtimestamp(NOW-age, timezone.utc).isoformat()
            self.assertEqual(alert_target(item, config(), NOW), 'k8s-rpi7')
        for age in (-1, 3601):
            item = alert()
            item['startsAt'] = datetime.fromtimestamp(NOW-age, timezone.utc).isoformat()
            with self.assertRaisesRegex(Blocked, 'invalid_alert_age'):
                alert_target(item, config(), NOW)
        item = sample(); item['scrape_down'] = False
        with self.assertRaisesRegex(Blocked, 'outage_not_confirmed'):
            snapshot_ok(item, 'k8s-rpi7', config(), NOW)

    def test_observed_unifi_stp_list_passes_and_order_does_not_matter(self):
        self.assertEqual(stp_counters([{'change_count': 5, 'mst': 0}]), ((0, 5),))
        rows = samples()
        for row in rows:
            row['port']['stp_change_count'] += [{'mst': 1, 'change_count': 3}]
        rows[-1]['port']['stp_change_count'].reverse()
        self.assertEqual(confirm(rows, 'k8s-rpi7', config(), NOW+70)['boot_id'], 'old-boot')

    def test_missing_malformed_or_duplicate_stp_counters_fail_closed(self):
        for value in (None, 5, [], {}, [{'mst': 0}], [{'mst': 0, 'change_count': -1}],
                      [{'mst': True, 'change_count': 5}], [{'mst': 0, 'change_count': '5'}],
                      [{'mst': 0, 'change_count': 5}, {'mst': 0, 'change_count': 5}]):
            item = sample(); item['port']['stp_change_count'] = value
            with self.subTest(value=value), self.assertRaisesRegex(Blocked, 'invalid_stp_counters'):
                snapshot_ok(item, 'k8s-rpi7', config(), NOW)

    def test_per_instance_stp_changes_and_resets_cannot_cancel_each_other(self):
        rows = samples()
        for row in rows:
            row['port']['stp_change_count'] += [{'mst': 1, 'change_count': 3}]
        rows[-1]['port']['stp_change_count'] = [
            {'mst': 0, 'change_count': 4}, {'mst': 1, 'change_count': 4}]
        with self.assertRaisesRegex(Blocked, 'link_or_stp_changed'):
            confirm(rows, 'k8s-rpi7', config(), NOW+70)

    def test_aged_out_mac_uses_configured_port_only_with_the_full_stall_pattern(self):
        rows = samples()
        for row in rows:
            row['port'].update(mac_count=0, connected=False)
        self.assertEqual(confirm(rows, 'k8s-rpi7', config(), NOW+70)['port_identity'], 'configured_port')
        rows[-1]['port']['rx_packets'] += 1
        with self.assertRaisesRegex(Blocked, 'node_tx_not_frozen'):
            confirm(rows, 'k8s-rpi7', config(), NOW+70)
        rows[-1]['port']['rx_packets'] -= 1
        rows[-1]['port']['idx'] = 8
        with self.assertRaisesRegex(Blocked, 'port_identity_unconfirmed'):
            confirm(rows, 'k8s-rpi7', config(), NOW+70)

    def test_conflicting_or_ambiguous_port_identity_still_blocks_power(self):
        for changes in ({'mac_count': 0}, {'connected': False}, {'mac': '02:00:00:00:00:08'},
                        {'mac_count': 0, 'connected': False, 'mac': '02:00:00:00:00:08'},
                        {'mac_count': 2}, {'mac_count': None}):
            item = sample(); item['port'].update(changes)
            with self.subTest(changes=changes), self.assertRaisesRegex(Blocked, 'port_identity_unconfirmed'):
                snapshot_ok(item, 'k8s-rpi7', config(), NOW)

    def test_normal_verification_does_not_send_a_failure_alert(self):
        normal = {'phase': 'verifying', 'actions': [{'at': NOW-60}]}
        self.assertFalse(review_required(normal, NOW))
        self.assertTrue(review_required(normal, NOW+600))
        for phase in ('failed', 'uncertain'):
            self.assertTrue(review_required({'phase': phase, 'actions': []}, NOW))

    def test_matching_directional_stall_passes_but_idle_link_does_not(self):
        validate_config(config())
        self.assertEqual(confirm(samples(), 'k8s-rpi7', config(), NOW+70)['boot_id'], 'old-boot')
        rows = samples()
        for row in rows:
            row['port']['tx_packets'] = 1000
        with self.assertRaisesRegex(Blocked, 'no_inbound_traffic'):
            confirm(rows, 'k8s-rpi7', config(), NOW+70)

    def test_each_independent_safety_gate_refuses_power(self):
        changes = {
            'observer_node': 'k8s-rpi7', 'node_set': [], 'live_alert': False,
            'target_ready': 'True', 'maintenance': True, 'kernel': '7.0.0-1022-raspi',
            'address': '192.168.3.200', 'peers_ready': False, 'peers_scraped': False,
            'peer_probes_ok': False, 'target_probe_results': ['responding', 'no_reply', 'no_reply'],
            'scrape_down': False, 'down_samples': 1, 'boot_age': 100, 'cpu_pct': 99,
            'pre_failure_at': NOW-3601,
            'memory_pct': 99, 'load_per_core': 5, 'io_pressure_pct': 50,
            'switch_online': False, 'switch_mac': '02:00:00:ff:ff:ff',
            'switch_seen': NOW-300, 'switch_uptime': 50, 'api_time': NOW-120,
            'boot_id': '', 'node_uid': '',
        }
        for key, value in changes.items():
            with self.subTest(key=key):
                item = sample(); item[key] = value
                with self.assertRaises(Blocked):
                    snapshot_ok(item, 'k8s-rpi7', config(), NOW)
        port_changes = {'idx': 8, 'mac': '02:00:00:00:00:08', 'mac_count': 2,
                        'connected': False, 'up': False, 'poe_good': False, 'poe_enabled': False,
                        'power_watts': 0, 'stp': 'blocking', 'uplink': True,
                        'rx_errors': 1, 'tx_errors': 1, 'rx_packets': -1}
        for key, value in port_changes.items():
            with self.subTest(port_field=key):
                item = sample(); item['port'][key] = value
                with self.assertRaises(Blocked):
                    snapshot_ok(item, 'k8s-rpi7', config(), NOW)

    def test_incomplete_nan_and_stale_data_cannot_authorize(self):
        for value in (float('nan'), float('inf'), None, '15', True):
            item = sample(); item['cpu_pct'] = value
            with self.subTest(value=value), self.assertRaises(Blocked):
                snapshot_ok(item, 'k8s-rpi7', config(), NOW)
        with self.assertRaises(Blocked):
            snapshot_ok(sample(), 'k8s-rpi7', config(), NOW+120)
        with self.assertRaises(KeyError):
            snapshot_ok({}, 'k8s-rpi7', config(), NOW)

    def test_restart_cached_data_link_flaps_and_resumed_tx_abort_confirmation(self):
        for field, value in [('boot_id', 'new-boot'), ('node_uid', 'replacement'),
                             ('switch_seen', NOW-5), ('switch_uptime', 1000)]:
            rows = samples(); rows[-1][field] = value
            with self.subTest(field=field), self.assertRaises(Blocked):
                confirm(rows, 'k8s-rpi7', config(), NOW+70)
        for field, value in [('rx_packets', 4001), ('tx_packets', 500),
                             ('link_down_count', 3),
                             ('stp_change_count', [{'mst': 0, 'change_count': 6}])]:
            rows = samples(); rows[-1]['port'][field] = value
            with self.subTest(field=field), self.assertRaises(Blocked):
                confirm(rows, 'k8s-rpi7', config(), NOW+70)

    def test_payload_cannot_select_an_arbitrary_target_or_override_mapping(self):
        for change in [({'node': 'evil/../../node'}, None),
                       ({'node': 'k8s-rpi8'}, None), ({'instance': 'http://example.com'}, None),
                       ({'alertname': 'SmartctlExporterDown'}, None), ({}, 'resolved')]:
            item = alert(); item['labels'].update(change[0])
            if change[1]: item['status'] = change[1]
            with self.assertRaises(Blocked):
                alert_target(item, config(), NOW)
        self.assertEqual(alert_target(alert(), config(), NOW), 'k8s-rpi7')

    def test_global_cooldown_and_ambiguous_action_hold_survive_restarts(self):
        cases = [({'phase': 'uncertain', 'actions': []}, 'recovery_interlock'),
                 ({'phase': 'failed', 'actions': []}, 'recovery_interlock'),
                 ({'phase': 'reserved', 'actions': []}, 'recovery_interlock'),
                 ({'phase': 'verifying', 'actions': []}, 'recovery_interlock'),
                 ({'phase': 'completed', 'actions': [{'node': 'k8s-rpi1', 'at': NOW-100}]}, 'global_cooldown'),
                 ]
        for state, reason in cases:
            with self.subTest(reason=reason), self.assertRaisesRegex(Blocked, reason):
                cooldown_ok(copy.deepcopy(state), 'k8s-rpi7', NOW)

    def test_same_node_can_recover_again_after_the_global_cooldown(self):
        state = {'phase': 'completed', 'actions': [{'node': 'k8s-rpi7', 'at': NOW-1801}]}
        cooldown_ok(state, 'k8s-rpi7', NOW)
        for phase in ('reserved', 'verifying'):
            with self.subTest(phase=phase), self.assertRaisesRegex(Blocked, 'recovery_interlock'):
                cooldown_ok({**state, 'phase': phase}, 'k8s-rpi7', NOW)

    def test_completed_history_does_not_impose_a_node_or_cluster_daily_limit(self):
        actions = [{'node': 'k8s-rpi7', 'at': NOW-2000*(i+1)} for i in range(12)]
        cooldown_ok({'phase': 'completed', 'actions': actions}, 'k8s-rpi7', NOW)


class Clock:
    def __init__(self): self.value = NOW
    def now(self): return self.value
    def wait(self, seconds): self.value += seconds; return False


class FakeBackend:
    def __init__(self, clock):
        self.lease_path = '/test/lease'
        self.config = config(); self.clock = clock; self.holder = 'pod-one'
        self.lease = {'metadata': {'resourceVersion': '1', 'annotations': {}}, 'spec': {}}
        self.cycles = []; self.snapshots = 0; self.failure = None
        self.bad_snapshot = None; self.ambiguous_reservation = False

    def candidate_priorities(self):
        return {name: 0 if name in ('k8s-rpi1', 'k8s-rpi2', 'k8s-rpi3') else 1
                for name in self.config['nodes']}

    def kube(self, path, method='GET', body=None):
        if method == 'GET': return copy.deepcopy(self.lease), self.clock.now()
        require_version = body['metadata']['resourceVersion'] == self.lease['metadata']['resourceVersion']
        if not require_version: raise Blocked('resource_version_conflict')
        self.lease = copy.deepcopy(body)
        self.lease['metadata']['resourceVersion'] = str(int(body['metadata']['resourceVersion'])+1)
        state = json.loads(body['metadata']['annotations'].get(controller.STATE_KEY, '{}'))
        if self.ambiguous_reservation and state.get('phase') == 'reserved':
            self.ambiguous_reservation = False
            raise TimeoutError('response lost after commit')
        return copy.deepcopy(self.lease), self.clock.now()

    def snapshot(self, node):
        self.clock.value += 1
        item = sample(self.clock.now(), 1000+self.snapshots*100)
        self.snapshots += 1
        if self.bad_snapshot:
            self.bad_snapshot(item, self.snapshots)
        return item

    def cycle(self, node):
        self.cycles.append(node)
        if self.failure: raise self.failure

    def recovered(self, node, old): return True


class EngineTests(unittest.TestCase):
    def test_resource_fallback_uses_real_boot_data_and_rejects_missing_or_ambiguous_data(self):
        backend = controller.Backend(config())
        row = {'metric': {}, 'value': [NOW, '10']}
        with patch.object(backend, 'prom', side_effect=[[], [row]]):
            self.assertEqual(backend.resource_value('rate', 'boot', NOW, 'pre_failure_cpu'),
                             (10.0, 'boot_average'))
        with patch.object(backend, 'prom', return_value=[row]):
            self.assertEqual(backend.resource_value('rate', 'boot', NOW, 'pre_failure_cpu'), (10.0, 'rate'))
        with patch.object(backend, 'prom', return_value=[]):
            with self.assertRaisesRegex(Blocked, 'missing_or_ambiguous_pre_failure_cpu'):
                backend.resource_value('rate', 'boot', NOW, 'pre_failure_cpu')
        with patch.object(backend, 'prom', return_value=[row, row]):
            with self.assertRaisesRegex(Blocked, 'missing_or_ambiguous_pre_failure_cpu'):
                backend.resource_value('rate', 'boot', NOW, 'pre_failure_cpu')
    def setUp(self):
        controller.STOP.clear()
        self.clock = Clock(); self.backend = FakeBackend(self.clock)
        self.patch_time = patch.object(controller.time, 'time', self.clock.now)
        self.patch_time.start()
    def tearDown(self): self.patch_time.stop()
    def run_engine(self):
        controller.Engine(self.backend, wait=self.clock.wait).run(alert())
    def state(self):
        return json.loads(self.backend.lease['metadata']['annotations'][controller.STATE_KEY])

    def test_confirmed_case_cycles_once_and_replayed_alert_cannot_repeat(self):
        self.run_engine()
        self.assertEqual(self.backend.cycles, ['k8s-rpi7'])
        self.assertEqual(self.state()['phase'], 'completed')
        self.run_engine()
        self.assertEqual(self.backend.cycles, ['k8s-rpi7'])

    def test_configured_port_fallback_cycles_only_after_confirmation(self):
        self.backend.bad_snapshot = lambda item, count: item['port'].update(mac_count=0, connected=False)
        self.run_engine()
        self.assertGreaterEqual(self.backend.snapshots, 4)
        self.assertEqual(self.backend.cycles, ['k8s-rpi7'])
        self.assertEqual(self.state()['phase'], 'completed')

    def test_worker_cannot_cycle_if_a_control_plane_fails_during_final_recheck(self):
        def fail_control_plane(item, count):
            if count == 4:
                item['unavailable_nodes'] = ['k8s-rpi3', 'k8s-rpi7']
        self.backend.bad_snapshot = fail_control_plane
        self.run_engine()
        self.assertEqual(self.backend.cycles, [])

    def test_configured_cooldown_applies_to_lease_acquisition(self):
        self.backend.config['cooldown_seconds'] = 900
        self.backend.lease['metadata']['annotations'][controller.STATE_KEY] = json.dumps(
            {'phase': 'completed', 'actions': [{'node': 'k8s-rpi7', 'at': NOW-600}]})
        self.run_engine()
        self.assertEqual(self.backend.cycles, [])
        self.clock.value += 301
        self.run_engine()
        self.assertEqual(self.backend.cycles, ['k8s-rpi7'])

    def test_audit_history_is_bounded_without_becoming_a_hidden_daily_quota(self):
        actions = [{'node': 'k8s-rpi7', 'at': NOW-400-i*301} for i in range(128)]
        self.backend.lease['metadata']['annotations'][controller.STATE_KEY] = json.dumps(
            {'phase': 'completed', 'actions': actions})
        self.run_engine()
        self.assertEqual(self.backend.cycles, ['k8s-rpi7'])
        self.assertEqual(len(self.state()['actions']), 128)

    def test_priorities_come_from_kubernetes_role_labels(self):
        backend = controller.Backend(config())
        nodes = [{'metadata': {'name': name, 'labels': {
            'node-role.kubernetes.io/control-plane': ''} if name == 'k8s-rpi8' else {}}}
            for name in config()['nodes']]
        with patch.object(backend, 'kube', return_value=({'items': nodes}, NOW)):
            priorities = backend.candidate_priorities()
        self.assertEqual(priorities['k8s-rpi8'], 0)
        self.assertEqual(priorities['k8s-rpi3'], 1)

    def test_progress_logs_show_lease_ownership_observations_and_completion(self):
        with patch.object(controller, 'event') as log:
            self.run_engine()
        outcomes = [c.args[0] for c in log.call_args_list]
        for outcome in ('lease_requested', 'lease_acquired', 'confirmed', 'recovered', 'lease_released'):
            self.assertIn(outcome, outcomes)
        self.assertEqual(outcomes.count('observed'), 3)
        acquired = next(c for c in log.call_args_list if c.args[0] == 'lease_acquired')
        self.assertEqual(acquired.kwargs['holder'], self.backend.holder)

    def test_waiting_for_recovery_logs_progress_at_most_once_per_minute(self):
        checks = []
        def recovering(node, old):
            checks.append(node)
            return len(checks) == 8
        self.backend.recovered = recovering
        with patch.object(controller, 'event') as log:
            self.run_engine()
        pending = [c.kwargs['elapsed_seconds'] for c in log.call_args_list
                   if c.args[0] == 'verification_pending']
        self.assertEqual(pending, [15, 75])
        self.assertEqual(self.backend.cycles, ['k8s-rpi7'])

    def test_ledger_keeps_a_full_day_of_cooldown_spaced_history_without_a_daily_quota(self):
        actions = [{'node': 'k8s-rpi7', 'at': NOW-2000*(i+1)} for i in range(12)]
        self.backend.lease['metadata']['annotations'][controller.STATE_KEY] = json.dumps(
            {'phase': 'completed', 'actions': actions})
        self.run_engine()
        self.assertEqual(self.backend.cycles, ['k8s-rpi7'])
        self.assertEqual(len(self.state()['actions']), 13)

    def test_real_switch_stp_response_reaches_the_policy_without_schema_errors(self):
        cfg = config(); backend = controller.Backend(cfg)
        port = sample()['port']
        details = {'id': cfg['switch_id'], 'macAddress': cfg['switch_mac'], 'state': 'ONLINE',
                   'interfaces': {'ports': [{'idx': 7, 'state': 'UP', 'poe': {'state': 'UP'}}]}}
        raw_port = {'port_idx': 7, 'last_connection': {'mac': port['mac'], 'connected': True},
                    'mac_table_count': 1, 'up': True, 'poe_good': True, 'poe_enable': True,
                    'poe_power': '6.5', 'stp_state': 'forwarding', 'is_uplink': False,
                    'stp_state_change_count': [{'change_count': 5, 'mst': 0}],
                    **{k: port[k] for k in ('rx_packets', 'tx_packets', 'rx_errors', 'tx_errors', 'link_down_count')}}
        raw = {'meta': {'rc': 'ok'}, 'data': [{'_id': cfg['switch_legacy_id'], 'mac': cfg['switch_mac'],
                'state': 1, 'last_seen': NOW-5, 'uptime': 120000, 'port_table': [raw_port]}]}
        with patch.object(backend, 'unifi', side_effect=[{'applicationVersion': cfg['unifi_application_version']},
                                                        details, raw]):
            observed = backend.switch('k8s-rpi7')
        item = sample(); item.update(observed)
        snapshot_ok(item, 'k8s-rpi7', cfg, NOW)

    def test_historical_prometheus_evidence_uses_the_requested_time(self):
        backend = controller.Backend(config())
        at = NOW-1800
        row = {'metric': {}, 'value': [at, '8.5']}
        with patch.object(backend.transport, 'request', return_value=(
                {'status': 'success', 'data': {'result': [row]}}, None)) as request:
            self.assertEqual(backend.scalar('cpu-query', at=at), 8.5)
            self.assertIn('time='+str(at), request.call_args.args[1])
        with self.assertRaisesRegex(Blocked, 'pre_failure_evidence_expired'):
            backend.scalar('cpu-query', at=NOW-3601)

    def test_historical_evidence_cannot_be_replaced_by_a_different_query_time(self):
        backend = controller.Backend(config())
        row = {'metric': {}, 'value': [NOW-1800, '8.5']}
        with patch.object(backend.transport, 'request', return_value=(
                {'status': 'success', 'data': {'result': [row]}}, None)):
            with self.assertRaisesRegex(Blocked, 'stale_metrics'):
                backend.scalar('cpu-query')

    def test_uncertain_power_request_is_never_retried(self):
        self.backend.failure = TimeoutError('request may have reached switch')
        self.run_engine(); self.run_engine()
        self.assertEqual(self.backend.cycles, ['k8s-rpi7'])
        self.assertEqual(self.state()['phase'], 'uncertain')

    def test_lost_reservation_response_cannot_erase_the_durable_hold(self):
        self.backend.ambiguous_reservation = True
        self.run_engine(); self.run_engine()
        self.assertEqual(self.backend.cycles, [])
        self.assertEqual(self.state()['phase'], 'uncertain')

    def test_recovered_target_during_final_recheck_never_cycles(self):
        self.backend.bad_snapshot = lambda item, count: item.update(target_ready='True') if count == 4 else None
        self.run_engine()
        self.assertEqual(self.backend.cycles, [])
        self.assertEqual(self.state()['phase'], 'idle')

    def test_observation_mode_and_another_replica_cannot_cycle(self):
        self.backend.config['enabled'] = False
        self.run_engine(); self.assertEqual(self.backend.cycles, [])
        self.backend.config['enabled'] = True
        self.backend.lease['spec'] = {'holderIdentity': 'another-pod', 'leaseDurationSeconds': 900,
                                     'renewTime': datetime.fromtimestamp(self.clock.now(), timezone.utc).isoformat()}
        self.run_engine(); self.assertEqual(self.backend.cycles, [])

    def test_resource_version_conflict_and_expired_lock_cannot_authorize_a_write(self):
        ledger = controller.Ledger(self.backend)
        stale, state = ledger.read()
        ledger.acquire('k8s-rpi7')
        with self.assertRaisesRegex(Blocked, 'resource_version_conflict'):
            ledger.write(stale, state)
        self.clock.value += 601
        with self.assertRaisesRegex(Blocked, 'expired_recovery_lock'):
            ledger.transition('reserved', 'k8s-rpi7', 'test-reservation')
        self.assertEqual(self.backend.cycles, [])

    def test_two_replicas_racing_for_the_same_lease_have_only_one_winner(self):
        shared = {'lease': copy.deepcopy(self.backend.lease), 'reads': 0}
        lock = threading.Lock(); both_read = threading.Barrier(2)
        def api(path, method='GET', body=None):
            if method == 'GET':
                with lock:
                    result = copy.deepcopy(shared['lease'])
                    shared['reads'] += 1; initial = shared['reads'] <= 2
                if initial: both_read.wait(timeout=2)
                return result, self.clock.now()
            with lock:
                if body['metadata']['resourceVersion'] != shared['lease']['metadata']['resourceVersion']:
                    raise Blocked('resource_version_conflict')
                shared['lease'] = copy.deepcopy(body)
                shared['lease']['metadata']['resourceVersion'] = str(int(body['metadata']['resourceVersion'])+1)
                return copy.deepcopy(shared['lease']), self.clock.now()
        results = []
        def acquire(holder):
            backend = FakeBackend(self.clock); backend.holder = holder; backend.kube = api
            try:
                controller.Ledger(backend).acquire('k8s-rpi7'); results.append('acquired')
            except Blocked:
                results.append('blocked')
        threads = [threading.Thread(target=acquire, args=(name,)) for name in ('pod-a', 'pod-b')]
        for thread in threads: thread.start()
        for thread in threads: thread.join(timeout=3)
        self.assertCountEqual(results, ['acquired', 'blocked'])

    def test_cached_switch_telemetry_waits_for_distinct_heartbeats(self):
        def cached_first_three(item, count):
            item['switch_seen'] = NOW-5 if count <= 3 else NOW+30*(count-3)
        self.backend.bad_snapshot = cached_first_three
        self.run_engine()
        self.assertGreaterEqual(self.backend.snapshots, 5)
        self.assertEqual(self.backend.cycles, ['k8s-rpi7'])

    def test_certificate_mismatch_cannot_send_controller_credentials(self):
        with patch.object(controller.http.client, 'HTTPSConnection') as connection:
            conn = connection.return_value
            conn.sock.getpeercert.return_value = b'wrong certificate'
            with self.assertRaisesRegex(Blocked, 'controller_certificate_changed'):
                controller.Transport().request('https://192.168.3.1', '/path',
                                               headers={'X-API-Key': 'test-only'}, pin='a'*64)
            conn.request.assert_not_called()

    def test_power_request_is_only_the_pinned_port_action(self):
        cfg = config(); cfg['unifi_api_key'] = 'test-only'
        backend = controller.Backend(cfg)
        with patch.object(backend, 'unifi', return_value={}) as api:
            backend.cycle('k8s-rpi7')
            api.assert_called_once_with('/integration/v1/sites/'+cfg['site_id']+'/devices/'+cfg['switch_id']+
                                        '/interfaces/ports/7/actions', 'POST', {'action': 'POWER_CYCLE'})

    def test_final_policy_failure_and_dependency_exception_never_power_cycle(self):
        for failure in ('wrong_port', 'cpu_saturation', 'stale_switch'):
            self.backend = FakeBackend(self.clock)
            def corrupt(item, count):
                if failure == 'wrong_port': item['port']['idx'] = 8
                if failure == 'cpu_saturation': item['cpu_pct'] = 100
                if failure == 'stale_switch': item['switch_seen'] -= 500
            self.backend.bad_snapshot = corrupt
            self.run_engine(); self.assertEqual(self.backend.cycles, [])
        self.backend = FakeBackend(self.clock)
        self.backend.snapshot = lambda node: (_ for _ in ()).throw(TimeoutError())
        self.run_engine(); self.assertEqual(self.backend.cycles, [])


class HttpTests(unittest.TestCase):
    def test_authentication_validation_and_healthy_target_never_trigger_power(self):
        controller.STOP.clear()
        backend = FakeBackend(Clock())
        def healthy(_):
            return {**sample(time.time()), 'target_ready': 'True'}
        backend.snapshot = healthy
        server = controller.make_server(config(), backend, ('127.0.0.1', 0))
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        def request(body, token=None):
            conn = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=3)
            conn.request('POST', '/webhook', body=body,
                         headers={'Authorization': 'Bearer ' + (token or 'wrong'), 'Content-Type': 'application/json'})
            result = conn.getresponse(); response = result.read(); status = result.status; conn.close()
            return status, response
        try:
            self.assertEqual(request('{}')[0], 401)
            token = config()['webhook_token']
            self.assertEqual(request('{broken', token)[0], 400)
            fresh = alert(time.time())
            fresh['startsAt'] = datetime.now(timezone.utc).isoformat()
            status, response = request(json.dumps({'alerts': [fresh]}), token)
            self.assertEqual(status, 202)
            self.assertEqual(json.loads(response)['accepted'], 1)
            for _ in range(30):
                if backend.lease.get('metadata', {}).get('annotations', {}).get(controller.STATE_KEY): break
                time.sleep(0.01)
            self.assertEqual(backend.cycles, [])
        finally:
            controller.STOP.set(); server.shutdown(); server.server_close(); thread.join(timeout=2)


if __name__ == '__main__':
    unittest.main()
