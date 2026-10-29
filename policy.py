"""Fail-closed checks for a probable macb TX stall; no network or power operations."""
from datetime import datetime
import ipaddress
import math
import os
import re
from urllib.parse import urlsplit


class Blocked(Exception):
    """A stable, non-secret reason to refuse automatic recovery."""


def require(condition, reason):
    if not condition:
        raise Blocked(reason)


def epoch(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(parsed.tzinfo is not None, 'invalid_alert_time')
    return parsed.timestamp()


def number(value):
    require(isinstance(value, (float, int)) and not isinstance(value, bool)
            and math.isfinite(value), 'invalid_evidence')
    return value


def stp_counters(value):
    """Keep each UniFi MST counter distinct, independent of response order."""
    require(isinstance(value, list) and 0 < len(value) <= 64, 'invalid_stp_counters')
    counters = {}
    for entry in value:
        require(isinstance(entry, dict), 'invalid_stp_counters')
        mst, count = entry.get('mst'), entry.get('change_count')
        require(type(mst) is int and mst >= 0 and type(count) is int and count >= 0,
                'invalid_stp_counters')
        require(mst not in counters, 'invalid_stp_counters')
        counters[mst] = count
    return tuple(sorted(counters.items()))


def port_identity(port, expected):
    require(type(port['idx']) is int and port['idx'] == expected['port'], 'port_identity_unconfirmed')
    if port['mac'] == expected['mac'] and type(port['mac_count']) is int \
            and port['mac_count'] == 1 and port['connected'] is True:
        return 'learned_mac'
    # Operator-approved fallback for a silent NIC whose learned entry aged out.
    # A foreign MAC or multiple learned devices is conflicting evidence.
    require(type(port['mac_count']) is int and port['mac_count'] == 0
            and (port['connected'] is False or port['connected'] is None)
            and port['mac'] in (None, '', expected['mac']), 'port_identity_unconfirmed')
    return 'configured_port'


def validate_config(config):
    require(type(config['enabled']) is bool, 'invalid_config')
    require(2 <= len(config['nodes']) <= 64, 'invalid_config')
    config.setdefault('node_exporter_port', int(os.environ.get('NODE_EXPORTER_PORT', '9100')))
    config.setdefault('approved_kernel', os.environ.get('APPROVED_KERNEL', ''))
    config.setdefault('cooldown_seconds', 300)
    config.setdefault('max_unavailable_nodes', min(2, len(config['nodes'])-1))
    require(type(config['cooldown_seconds']) is int and config['cooldown_seconds'] > 0, 'invalid_config')
    require(type(config['max_unavailable_nodes']) is int
            and 1 <= config['max_unavailable_nodes'] < len(config['nodes']), 'invalid_config')
    require(type(config['node_exporter_port']) is int and 1 <= config['node_exporter_port'] <= 65535,
            'invalid_config')
    require(isinstance(config['approved_kernel'], str) and 0 < len(config['approved_kernel']) <= 128,
            'invalid_config')
    ports, macs, addresses = set(), set(), set()
    for name, node in config['nodes'].items():
        require(isinstance(name, str) and len(name) <= 253
                and re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', name), 'invalid_config')
        require(ipaddress.ip_address(node['address']).is_private, 'invalid_config')
        require(re.fullmatch(r'[0-9a-f]{2}(:[0-9a-f]{2}){5}', node['mac']), 'invalid_config')
        require(type(node['port']) is int and 1 <= node['port'] <= 1024, 'invalid_config')
        require(node['port'] not in ports and node['mac'] not in macs
                and node['address'] not in addresses, 'ambiguous_mapping')
        ports.add(node['port']); macs.add(node['mac']); addresses.add(node['address'])
    require(re.fullmatch(r'[0-9a-f]{64}', config['unifi_certificate_sha256']), 'invalid_config')
    require(len(config['webhook_token']) >= 32, 'invalid_config')
    for key, schemes in [('unifi_origin', ('https',)), ('prometheus_origin', ('http', 'https'))]:
        origin = urlsplit(config[key])
        require(origin.scheme in schemes and bool(origin.hostname) and not origin.username
                and not origin.password and origin.path in ('', '/') and not origin.query
                and not origin.fragment, 'invalid_config')
    require(re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', config['unifi_application_version']), 'invalid_config')
    require(re.fullmatch(r'[0-9a-f-]{36}', config['site_id'])
            and re.fullmatch(r'[0-9a-f-]{36}', config['switch_id'])
            and re.fullmatch(r'[0-9a-f]{24}', config['switch_legacy_id']), 'invalid_config')
    require(config['sample_interval_seconds'] >= 30, 'invalid_config')


def exporter_instance(config, node):
    address = config['nodes'][node]['address']
    if ipaddress.ip_address(address).version == 6:
        address = '[' + address + ']'
    return address + ':' + str(config['node_exporter_port'])


def alert_target(alert, config, now):
    require(alert.get('status') == 'firing', 'not_firing')
    labels = alert.get('labels', {})
    require(labels.get('alertname') in ('RaspberryPiNetworkRecoveryCandidate', 'KubeNodeUnreachable'),
            'unrelated_alert')
    node = labels.get('node')
    if not node:
        matches = [name for name, item in config['nodes'].items()
                   if labels.get('instance') == exporter_instance(config, name)]
        require(len(matches) == 1, 'unknown_node')
        node = matches[0]
    require(node in config['nodes'], 'unknown_node')
    if labels.get('instance') and labels['alertname'] == 'RaspberryPiNetworkRecoveryCandidate':
        require(labels['instance'] == exporter_instance(config, node), 'conflicting_identity')
    try:
        started = epoch(alert['startsAt'])
    except (ValueError, TypeError, KeyError):
        raise Blocked('invalid_alert_time') from None
    # Alertmanager startsAt is the firing time, after the rule's own two-minute
    # wait. snapshot_ok independently requires two minutes of failed scrapes.
    require(0 <= now - started <= 3600, 'invalid_alert_age')
    return node


def snapshot_ok(snapshot, node, config, now):
    """Every observation must pass; incomplete information never authorizes power."""
    expected = config['nodes'][node]
    require(0 <= now - number(snapshot['at']) <= 30, 'stale_observation')
    require(abs(number(snapshot['api_time']) - now) <= 15, 'clock_skew')
    require(snapshot['observer_node'] != node, 'observer_is_target')
    require(snapshot['node_set'] == sorted(config['nodes']), 'inventory_changed')
    require(snapshot['live_alert'] is True, 'alert_cleared')
    require(snapshot['target_ready'] == 'Unknown', 'node_not_unreachable')
    require(snapshot['maintenance'] is False, 'maintenance')
    require(snapshot['kernel'] == config['approved_kernel'], 'kernel_not_approved')
    require(snapshot['address'] == expected['address'], 'conflicting_identity')
    unavailable = snapshot['unavailable_nodes']
    require(isinstance(unavailable, list) and node in unavailable
            and len(set(unavailable)) == len(unavailable)
            and set(unavailable) <= set(config['nodes'])
            and len(unavailable) <= config.get('max_unavailable_nodes', 2), 'too_many_nodes_unavailable')
    control_planes = snapshot['control_plane_nodes']
    require(set(control_planes) <= set(config['nodes']), 'invalid_control_plane_inventory')
    require(node in control_planes or not set(unavailable).intersection(control_planes),
            'control_plane_recovery_priority')
    require(snapshot['control_plane_quorum_ok'] is True, 'control_plane_quorum_unhealthy')
    require(snapshot['peers_ready'] is True and snapshot['peers_scraped'] is True
            and snapshot['peer_probes_ok'] is True, 'other_nodes_or_observer_unhealthy')
    require(snapshot['target_probe_results'] == ['no_reply'] * 3, 'target_responds_or_probe_error')
    require(snapshot['scrape_down'] is True and number(snapshot['down_samples']) >= 2,
            'outage_not_confirmed')
    require(0 <= now - number(snapshot['pre_failure_at']) <= 3600, 'pre_failure_evidence_expired')
    require(number(snapshot['boot_age']) >= 900, 'recent_boot')
    require(number(snapshot['cpu_pct']) < 80 and number(snapshot['memory_pct']) < 85
            and number(snapshot['load_per_core']) < 2
            and number(snapshot['io_pressure_pct']) < 20, 'resource_saturation')
    require(snapshot['switch_online'] is True and snapshot['switch_mac'] == config['switch_mac'],
            'switch_unhealthy_or_wrong')
    require(-15 <= now - number(snapshot['switch_seen']) <= 90
            and number(snapshot['switch_uptime']) >= 3600, 'stale_or_restarted_switch')
    port = snapshot['port']
    port_identity(port, expected)
    require(port['up'] is True and port['poe_good'] is True and port['poe_enabled'] is True
            and number(port['power_watts']) > 1 and port['stp'] == 'forwarding'
            and port['uplink'] is False, 'port_or_power_unhealthy')
    require(port['rx_errors'] == 0 and port['tx_errors'] == 0, 'physical_port_errors')
    for field in ('rx_packets', 'tx_packets', 'link_down_count'):
        require(number(port[field]) >= 0, 'invalid_port_counters')
    stp_counters(port['stp_change_count'])
    require(bool(snapshot['node_uid']) and bool(snapshot['boot_id']), 'missing_node_identity')


def confirm(samples, node, config, now):
    require(len(samples) >= 3, 'insufficient_observations')
    for sample in samples:
        snapshot_ok(sample, node, config, sample['at'])
    first, last = samples[0], samples[-1]
    require(60 <= last['at'] - first['at'] <= 240, 'invalid_confirmation_window')
    require(0 <= now - last['at'] <= 15, 'stale_final_check')
    require(len({s['switch_seen'] for s in samples}) >= 3, 'cached_switch_samples')
    for previous, current in zip(samples, samples[1:]):
        require(current['at'] > previous['at'] and current['switch_seen'] >= previous['switch_seen']
                and current['switch_uptime'] >= previous['switch_uptime'], 'counter_or_clock_reset')
        require(current['node_uid'] == first['node_uid'] and current['boot_id'] == first['boot_id'],
                'node_restarted_or_replaced')
        require(current['port']['rx_packets'] == first['port']['rx_packets'], 'node_tx_not_frozen')
        require(current['port']['tx_packets'] >= previous['port']['tx_packets'], 'counter_or_clock_reset')
        require(current['port']['link_down_count'] == first['port']['link_down_count']
                and stp_counters(current['port']['stp_change_count'])
                == stp_counters(first['port']['stp_change_count']),
                'link_or_stp_changed')
    # Switch RX is traffic FROM the Pi. Switch TX is traffic TOWARD the Pi.
    require(last['port']['tx_packets'] - first['port']['tx_packets'] >= 10, 'no_inbound_traffic')
    return {'node': node, 'node_uid': last['node_uid'], 'boot_id': last['boot_id'],
            'port_identity': port_identity(last['port'], config['nodes'][node])}


def cooldown_ok(state, node, now, acknowledge='', cooldown_seconds=300):
    if state.get('phase') in ('reserved', 'verifying', 'failed', 'uncertain'):
        require(bool(acknowledge) and acknowledge == state.get('action_id'), 'recovery_interlock')
    actions = state.get('actions', [])
    require(all(0 <= now - number(a['at']) for a in actions), 'clock_skew')
    require(not any(now - a['at'] < cooldown_seconds for a in actions), 'global_cooldown')


def review_required(state, now):
    if state.get('phase') in ('failed', 'uncertain'):
        return True
    if state.get('phase') in ('reserved', 'verifying') and state.get('actions'):
        return now - state['actions'][-1]['at'] > 600
    return False
