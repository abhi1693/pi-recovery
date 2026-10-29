"""Small Alertmanager receiver. Power writes require policy checks and a durable fence."""
import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import errno
import hashlib
import hmac
import itertools
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import queue
import re
import signal
import socket
import ssl
import threading
import time
import urllib.parse
import uuid

from policy import Blocked, alert_target, confirm, cooldown_ok, epoch, exporter_instance, number, port_identity, require, review_required, snapshot_ok, validate_config

STATE_KEY = os.environ.get('PI_RECOVERY_STATE_KEY', 'pi-recovery.io/state')
STOP = threading.Event()
COUNTERS = {}
COUNTER_LOCK = threading.Lock()


def event(outcome, **fields):
    with COUNTER_LOCK:
        COUNTERS[outcome] = COUNTERS.get(outcome, 0) + 1
    print(json.dumps({'event': 'pi_recovery', 'outcome': outcome,
                      'observer_node': os.environ.get('NODE_NAME', ''),
                      'pod': os.environ.get('HOSTNAME', ''), **fields}), flush=True)


def is_control_plane(node):
    labels = node['metadata'].get('labels', {})
    return any(key in labels for key in ('node-role.kubernetes.io/control-plane', 'node-role.kubernetes.io/master'))


def load_per_core_query(instance):
    selector = '{instance=' + json.dumps(instance) + '}'
    cpu = '{instance=' + json.dumps(instance) + ',mode="idle"}'
    return 'node_load1' + selector + '/scalar(count(node_cpu_seconds_total' + cpu + '))'


class Transport:
    def request(self, origin, path, method='GET', body=None, headers=None, ca=None, pin=None):
        parsed = urllib.parse.urlsplit(origin)
        require(parsed.scheme in ('http', 'https') and not parsed.username, 'invalid_origin')
        require(path.startswith('/') and not path.startswith('//'), 'invalid_path')
        if parsed.scheme == 'https':
            context = ssl._create_unverified_context() if pin else ssl.create_default_context(cafile=ca)
            conn = http.client.HTTPSConnection(parsed.hostname, parsed.port, timeout=5, context=context)
        else:
            conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=5)
        try:
            conn.connect()
            # Pin before sending API credentials. No redirects and no automatic retries.
            if pin:
                require(hmac.compare_digest(hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest(), pin),
                        'controller_certificate_changed')
            payload = json.dumps(body).encode() if body is not None else None
            request_headers = {'Accept': 'application/json', **(headers or {})}
            if payload is not None:
                request_headers['Content-Type'] = 'application/json'
            conn.request(method, path, body=payload, headers=request_headers)
            response = conn.getresponse()
            data = response.read(4 * 1024 * 1024 + 1)
            require(len(data) <= 4 * 1024 * 1024, 'oversized_dependency_response')
            require(200 <= response.status < 300, 'dependency_http_error')
            return json.loads(data) if data else {}, response.getheader('Date')
        finally:
            conn.close()


class Backend:
    def __init__(self, config, transport=None):
        self.config = config
        self.transport = transport or Transport()
        self.kube_origin = 'https://' + os.environ.get('KUBERNETES_SERVICE_HOST', 'kubernetes.default.svc') + ':' + os.environ.get('KUBERNETES_SERVICE_PORT', '443')
        self.sa = Path('/var/run/secrets/kubernetes.io/serviceaccount')
        self.holder = os.environ.get('POD_UID', str(uuid.uuid4()))
        self.observer = os.environ.get('NODE_NAME', '')
        namespace = config.get('lease_namespace', os.environ.get('POD_NAMESPACE', 'default'))
        name = config.get('lease_name', 'pi-recovery-lock')
        require(all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?', value)
                    for value in (namespace, name)), 'invalid_lease_identity')
        self.lease_path = '/apis/coordination.k8s.io/v1/namespaces/' + namespace + '/leases/' + name

    def kube(self, path, method='GET', body=None):
        token = (self.sa / 'token').read_text().strip()
        data, date = self.transport.request(self.kube_origin, path, method, body,
                                           {'Authorization': 'Bearer ' + token}, ca=str(self.sa / 'ca.crt'))
        require(bool(date) and abs(parsedate_to_datetime(date).timestamp() - time.time()) <= 15, 'clock_skew')
        return data, parsedate_to_datetime(date).timestamp()

    def unifi(self, path, method='GET', body=None):
        return self.transport.request(self.config['unifi_origin'], '/proxy/network' + path, method, body,
                                      {'X-API-Key': self.config['unifi_api_key']},
                                      pin=self.config['unifi_certificate_sha256'])[0]

    def prom(self, query, at=None):
        evaluated_at = time.time() if at is None else number(at)
        require(-15 <= time.time() - evaluated_at <= 3600, 'pre_failure_evidence_expired')
        params = {'query': query, 'timeout': '4s'}
        if at is not None:
            params['time'] = at
        path = '/api/v1/query?' + urllib.parse.urlencode(params)
        data, _ = self.transport.request(self.config['prometheus_origin'], path)
        require(data.get('status') == 'success' and not data.get('warnings'), 'prometheus_unavailable')
        rows = data['data']['result']
        require(all(-15 <= evaluated_at - float(row['value'][0]) <= 30 for row in rows), 'stale_metrics')
        return rows

    def scalar(self, query, at=None):
        rows = self.prom(query, at=at)
        require(len(rows) == 1, 'missing_or_ambiguous_metrics')
        return float(rows[0]['value'][1])

    @staticmethod
    def probe(address, port):
        try:
            with socket.create_connection((address, port), timeout=2):
                return 'responding'
        except ConnectionRefusedError:
            return 'responding'  # A TCP RST proves the target can transmit.
        except OSError as error:
            return 'no_reply' if error.errno in (None, errno.ETIMEDOUT, errno.EHOSTUNREACH) else 'probe_error'

    def node(self, name):
        return self.kube('/api/v1/nodes/' + name)[0]

    def candidate_priorities(self):
        nodes, _ = self.kube('/api/v1/nodes')
        require(sorted(n['metadata']['name'] for n in nodes['items']) == sorted(self.config['nodes']),
                'inventory_changed')
        return {n['metadata']['name']: 0 if is_control_plane(n) else 1 for n in nodes['items']}

    def switch(self, node):
        cfg = self.config
        require(self.unifi('/integration/v1/info')['applicationVersion'] == cfg['unifi_application_version'],
                'controller_version_changed')
        root = '/integration/v1/sites/' + cfg['site_id'] + '/devices/' + cfg['switch_id']
        details = self.unifi(root)
        require(details['id'] == cfg['switch_id'] and details['macAddress'] == cfg['switch_mac'], 'switch_identity_changed')
        ports = [p for p in details['interfaces']['ports'] if p['idx'] == cfg['nodes'][node]['port']]
        require(len(ports) == 1 and ports[0]['state'] == 'UP'
                and ports[0].get('poe', {}).get('state') == 'UP', 'integration_port_unhealthy')
        raw = self.unifi('/api/s/default/stat/device')
        require(raw.get('meta', {}).get('rc') == 'ok', 'switch_telemetry_unavailable')
        switches = [d for d in raw['data'] if d.get('mac') == cfg['switch_mac']]
        require(len(switches) == 1, 'switch_identity_changed')
        device = switches[0]
        require(device['_id'] == cfg['switch_legacy_id'], 'switch_identity_changed')
        entries = [p for p in device['port_table'] if p['port_idx'] == cfg['nodes'][node]['port']]
        require(len(entries) == 1, 'port_identity_unconfirmed')
        p = entries[0]
        connection = p.get('last_connection', {})
        port = {'idx': p['port_idx'], 'mac': connection.get('mac'), 'connected': connection.get('connected'),
                'mac_count': p['mac_table_count'], 'up': p['up'], 'poe_good': p['poe_good'],
                'poe_enabled': p['poe_enable'], 'power_watts': float(p['poe_power']),
                'stp': p['stp_state'], 'uplink': p['is_uplink'],
                **{k: p[k] for k in ('rx_packets', 'tx_packets', 'rx_errors', 'tx_errors', 'link_down_count')},
                'stp_change_count': p['stp_state_change_count']}
        return {'switch_online': details['state'] == 'ONLINE' and device['state'] == 1,
                'switch_mac': device['mac'], 'switch_seen': device['last_seen'],
                'switch_uptime': device['uptime'], 'port': port}

    def snapshot(self, node):
        now = time.time()
        cfg = self.config
        nodes, api_time = self.kube('/api/v1/nodes')
        inventory = {n['metadata']['name']: n for n in nodes['items']}
        require(node in inventory, 'unknown_node')
        target = inventory[node]
        def ready(n):
            return next((c['status'] for c in n['status']['conditions'] if c['type'] == 'Ready'), 'Missing')
        unavailable = sorted(name for name, n in inventory.items() if ready(n) != 'True')
        healthy_peers = [name for name, n in inventory.items() if name != node and ready(n) == 'True']
        control_planes = sorted(name for name, n in inventory.items() if is_control_plane(n))
        quorum_ok = (not control_planes or
                     sum(ready(inventory[name]) == 'True' for name in control_planes) >= len(control_planes)//2+1)
        maintenance = any(n['spec'].get('unschedulable')
                          or n['metadata'].get('deletionTimestamp')
                          or n['metadata'].get('annotations', {}).get(
                              cfg.get('maintenance_annotation', os.environ.get(
                                  'PI_RECOVERY_MAINTENANCE_KEY', 'pi-recovery.io/maintenance'))) == 'true'
                          for n in inventory.values())
        ips = cfg['nodes']
        ups = self.prom('max by(instance)(up{job="node-exporter"})')
        up = {r['metric']['instance']: float(r['value'][1]) for r in ups}
        ages = self.prom('time()-max by(instance)(timestamp(up{job="node-exporter"}))')
        fresh = {r['metric']['instance']: -15 <= float(r['value'][1]) <= 90 for r in ages}
        # Service IPs and alert-provided URLs are never probe destinations.
        probe_targets = [(ips[node]['address'], p) for p in (22, cfg['node_exporter_port'], 10250)]
        probe_targets += [(ips[name]['address'], 22) for name in healthy_peers]
        with ThreadPoolExecutor(max_workers=6) as pool:
            probes = list(pool.map(lambda pair: self.probe(*pair), probe_targets))
        instance = exporter_instance(cfg, node)
        selector = '{job="node-exporter",instance="' + instance + '"}'
        device_selector = '{instance="' + instance + '"}'
        alert_selector = 'ALERTS{alertname=~"RaspberryPiNetworkRecoveryCandidate|KubeNodeUnreachable",alertstate="firing"}'
        live = self.prom(alert_selector + ' and (time()-timestamp(' + alert_selector + ') < 90)')
        live_alert = any(r['value'][1] == '1' and (r['metric'].get('node') == node or
                         r['metric'].get('instance') == instance) for r in live)
        pre_failure_at = self.scalar('max_over_time((timestamp(up' + selector + ') and (up'
                                     + selector + ' == 1))[1h:30s])')
        require(0 <= now - number(pre_failure_at) <= 3600, 'pre_failure_evidence_expired')
        sources = ('{instance="' + instance + '",__name__=~"'
                   'node_cpu_seconds_total|node_memory_MemAvailable_bytes|node_memory_MemTotal_bytes|'
                   'node_load1|node_pressure_io_waiting_seconds_total|node_boot_time_seconds"}')
        oldest_source = self.scalar('min(timestamp(label_replace(' + sources
                                    + ', "source_metric", "$1", "__name__", "(.+)")))', at=pre_failure_at)
        require(0 <= pre_failure_at - oldest_source <= 90, 'stale_pre_failure_metrics')
        cpu_selector = '{instance="' + instance + '",mode="idle"}'
        cpu = '100*(1-avg(rate(node_cpu_seconds_total' + cpu_selector + '[2m])))'
        snapshot = {'at': now, 'api_time': api_time, 'observer_node': self.observer,
                    'node_set': sorted(inventory), 'live_alert': live_alert, 'target_ready': ready(target),
                    'maintenance': maintenance, 'node_uid': target['metadata']['uid'],
                    'boot_id': target['status']['nodeInfo']['bootID'], 'kernel': target['status']['nodeInfo']['kernelVersion'],
                    'address': next(a['address'] for a in target['status']['addresses'] if a['type'] == 'InternalIP'),
                    'unavailable_nodes': unavailable, 'control_plane_nodes': control_planes,
                    'control_plane_quorum_ok': quorum_ok,
                    'peers_ready': bool(healthy_peers) and all(ready(n) in ('True', 'Unknown') for n in inventory.values()),
                    'peers_scraped': all(up.get(exporter_instance(cfg, k)) == 1 and fresh.get(exporter_instance(cfg, k))
                                         for k in healthy_peers)
                                     and all(up.get(exporter_instance(cfg, k)) == 0 and fresh.get(exporter_instance(cfg, k))
                                             for k in unavailable if k != node),
                    'peer_probes_ok': all(p == 'responding' for p in probes[3:]),
                    'target_probe_results': probes[:3],
                    'scrape_down': up.get(instance) == 0
                                   and fresh.get(instance) is True
                                   and self.scalar('max_over_time(up' + selector + '[2m])') == 0,
                    'down_samples': self.scalar('count_over_time(up' + selector + '[2m])'),
                    'pre_failure_at': pre_failure_at,
                    'boot_age': now - self.scalar('node_boot_time_seconds' + device_selector, at=pre_failure_at),
                    'cpu_pct': self.scalar(cpu, at=pre_failure_at),
                    'memory_pct': self.scalar('100*(1-node_memory_MemAvailable_bytes' + device_selector
                                               + '/node_memory_MemTotal_bytes' + device_selector + ')', at=pre_failure_at),
                    'load_per_core': self.scalar(load_per_core_query(instance), at=pre_failure_at),
                    'io_pressure_pct': self.scalar('100*rate(node_pressure_io_waiting_seconds_total'
                                                  + device_selector + '[2m])', at=pre_failure_at),
                    **self.switch(node)}
        return snapshot

    def cycle(self, node):
        cfg = self.config
        path = ('/integration/v1/sites/' + cfg['site_id'] + '/devices/' + cfg['switch_id'] +
                '/interfaces/ports/' + str(cfg['nodes'][node]['port']) + '/actions')
        self.unifi(path, 'POST', {'action': 'POWER_CYCLE'})

    def recovered(self, node, old):
        target = self.node(node)
        require(target['metadata']['uid'] == old['node_uid'], 'node_replaced_during_recovery')
        ready = any(c['type'] == 'Ready' and c['status'] == 'True' for c in target['status']['conditions'])
        up = self.scalar('up{job="node-exporter",instance="' + exporter_instance(self.config, node) + '"}')
        return ready and target['status']['nodeInfo']['bootID'] != old['boot_id'] and up == 1


class Ledger:
    def __init__(self, backend):
        self.backend = backend

    def read(self):
        lease = self.backend.kube(self.backend.lease_path)[0]
        state = json.loads(lease['metadata'].get('annotations', {}).get(STATE_KEY, '{"phase":"idle","actions":[]}'))
        require(isinstance(state, dict) and isinstance(state.get('actions'), list), 'invalid_recovery_ledger')
        require(state.get('phase') in ('idle', 'observing', 'reserved', 'verifying', 'completed', 'failed', 'uncertain')
                and len(state['actions']) <= 128, 'invalid_recovery_ledger')
        return lease, state

    def write(self, lease, state):
        updated = copy.deepcopy(lease)
        updated['metadata'].setdefault('annotations', {})[STATE_KEY] = json.dumps(state, separators=(',', ':'))
        updated.setdefault('spec', {}).update({'holderIdentity': self.backend.holder,
                                              'leaseDurationSeconds': 900,
                                              'renewTime': datetime.fromtimestamp(time.time(), timezone.utc).isoformat()})
        return self.backend.kube(self.backend.lease_path, 'PUT', updated)[0]

    def acquire(self, node):
        lease, state = self.read()
        now = time.time()
        cooldown_ok(state, node, now, self.backend.config.get('acknowledge_action_id', ''),
                    self.backend.config.get('cooldown_seconds', 300))
        spec = lease.get('spec', {})
        if spec.get('holderIdentity') and spec['holderIdentity'] != self.backend.holder:
            require(now - epoch(spec['renewTime']) > spec['leaseDurationSeconds'], 'another_recovery_running')
        state['phase'] = 'observing'
        self.write(lease, state)  # resourceVersion fences both replicas; conflicts fail closed.

    def transition(self, phase, node, action_id=None):
        lease, state = self.read()
        require(lease.get('spec', {}).get('holderIdentity') == self.backend.holder, 'lost_recovery_lock')
        require(0 <= time.time() - epoch(lease['spec']['renewTime']) < 600, 'expired_recovery_lock')
        if phase == 'reserved':
            require(state['phase'] == 'observing', 'invalid_recovery_phase')
            cooldown_ok(state, node, time.time(), cooldown_seconds=self.backend.config.get('cooldown_seconds', 300))
            state['actions'] = [a for a in state['actions'] if time.time() - a['at'] < 86400][-127:]
            state['actions'].append({'node': node, 'at': time.time(), 'id': action_id})
            state['action_id'] = action_id
        state['phase'] = phase
        self.write(lease, state)
        if phase in ('idle', 'completed'):
            lease, state = self.read()
            require(lease['spec']['holderIdentity'] == self.backend.holder, 'lost_recovery_lock')
            lease['spec']['holderIdentity'] = ''
            self.backend.kube(self.backend.lease_path, 'PUT', lease)


class Engine:
    def __init__(self, backend, ledger=None, wait=None):
        self.backend = backend
        self.ledger = ledger or Ledger(backend)
        self.wait = wait or STOP.wait

    def run(self, alert):
        node = None
        locked = reserved = False
        try:
            node = alert_target(alert, self.backend.config, time.time())
            event('lease_requested', node=node)
            self.ledger.acquire(node); locked = True
            event('lease_acquired', node=node, holder=self.backend.holder)
            samples = []
            for index in range(7):
                require(not STOP.is_set(), 'shutting_down')
                if index:
                    require(not self.wait(self.backend.config['sample_interval_seconds']), 'shutting_down')
                sample = self.backend.snapshot(node)
                snapshot_ok(sample, node, self.backend.config, time.time())
                samples.append(sample)
                event('observed', node=node, sample=len(samples),
                      port_identity=port_identity(sample['port'], self.backend.config['nodes'][node]),
                      switch_seen=sample['switch_seen'], tx_from_pi=sample['port']['rx_packets'],
                      tx_toward_pi=sample['port']['tx_packets'])
                if len(samples) >= 3:
                    try:
                        identity = confirm(samples, node, self.backend.config, time.time())
                        break
                    except Blocked as error:
                        if str(error) != 'cached_switch_samples':
                            raise
            else:
                raise Blocked('cached_switch_samples')
            # Recheck all dependencies, identity and endpoint responses immediately before reserving.
            samples.append(self.backend.snapshot(node))
            identity = confirm(samples, node, self.backend.config, time.time())
            event('confirmed', node=node, observations=len(samples), port_identity=identity['port_identity'])
            require(not STOP.is_set(), 'shutting_down')
            if not self.backend.config['enabled']:
                event('would_cycle', node=node)
                return
            action_id = str(uuid.uuid4())
            reserved = True  # An ambiguous reservation write must never be cleared in finally.
            self.ledger.transition('reserved', node, action_id)
            event('reserved', node=node, action_id=action_id, port_identity=identity['port_identity'])
            self.backend.cycle(node)
            self.ledger.transition('verifying', node)
            event('cycled', node=node, action_id=action_id)
            for attempt in range(30):
                if self.wait(15):
                    raise Blocked('shutdown_during_verification')
                try:
                    if self.backend.recovered(node, identity):
                        self.ledger.transition('completed', node)
                        event('recovered', node=node, action_id=action_id)
                        event('lease_released', node=node)
                        return
                    pending_reason = 'waiting_for_boot_ready_or_scrape'
                except Blocked as error:
                    pending_reason = str(error)
                if attempt % 4 == 0:
                    event('verification_pending', node=node, action_id=action_id,
                          elapsed_seconds=(attempt+1)*15, reason=pending_reason)
            self.ledger.transition('failed', node)
            event('failed', node=node, action_id=action_id)
        except Blocked as error:
            event('blocked', node=node, reason=str(error))
            if reserved:
                try:
                    self.ledger.transition('uncertain', node)
                except Exception:
                    pass  # The persisted reservation itself prevents another action.
        except Exception as error:
            # Never log response bodies, credentials or unbounded exception strings.
            event('error', node=node, error_type=type(error).__name__)
            if reserved:
                try:
                    self.ledger.transition('uncertain', node)
                except Exception:
                    pass
        finally:
            if locked and not reserved:
                try:
                    self.ledger.transition('idle', node)
                    event('lease_released', node=node)
                except Exception:
                    event('ledger_release_failed', node=node)


def make_server(config, backend=None, address=('0.0.0.0', 8080)):
    backend = backend or Backend(config)
    engine = Engine(backend)
    pending = queue.PriorityQueue(maxsize=8)
    sequence = itertools.count()
    def worker():
        while not STOP.is_set():
            try:
                _, _, alert = pending.get(timeout=1)
            except queue.Empty:
                continue
            engine.run(alert)
            pending.task_done()
    threading.Thread(target=worker, daemon=True).start()

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def log_message(self, *_):
            pass

        def reply(self, status, data):
            payload = data.encode()
            self.send_response(status)
            self.send_header('Content-Length', str(len(payload)))
            self.send_header('Content-Type', 'text/plain; version=0.0.4' if self.path == '/metrics' else 'text/plain; charset=utf-8')
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            if self.path in ('/healthz', '/readyz'):
                self.reply(200 if not STOP.is_set() else 503, 'ok\n')
            elif self.path == '/metrics':
                with COUNTER_LOCK:
                    lines = [f'pi_recovery_events_total{{outcome="{k}"}} {v}' for k, v in sorted(COUNTERS.items())]
                try:
                    _, state = engine.ledger.read()
                    lines += [f'pi_recovery_interlock_active {int(state.get("phase") in ("reserved", "verifying", "failed", "uncertain"))}',
                              f'pi_recovery_review_required {int(review_required(state, time.time()))}',
                              'pi_recovery_ledger_read_ok 1']
                except Exception:
                    lines += ['pi_recovery_ledger_read_ok 0']
                self.reply(200, '\n'.join(lines + [f'pi_recovery_automatic_enabled {int(config["enabled"])}']) + '\n')
            else:
                self.reply(404, 'not found\n')

        def do_POST(self):
            if self.path != '/webhook':
                self.reply(404, 'not found\n'); return
            supplied = self.headers.get('Authorization', '')
            if not hmac.compare_digest(supplied.encode('utf-8'), ('Bearer ' + config['webhook_token']).encode('utf-8')):
                self.reply(401, 'unauthorized\n'); return
            try:
                size = int(self.headers.get('Content-Length', '0'))
                require(0 < size <= 65536, 'invalid_payload_size')
                require(not self.headers.get('Transfer-Encoding'), 'unsupported_transfer_encoding')
                payload = json.loads(self.rfile.read(size))
                require(isinstance(payload, dict), 'invalid_payload')
                alerts = payload['alerts']
                require(isinstance(alerts, list) and len(alerts) <= 32, 'invalid_alerts')
                require(all(isinstance(a, dict) and isinstance(a.get('labels'), dict) for a in alerts), 'invalid_alerts')
                candidates = []
                for alert in alerts:
                    try:
                        node = alert_target(alert, config, time.time())
                    except Blocked:
                        continue
                    candidates.append((node, alert))
                priorities = backend.candidate_priorities() if candidates else {}
                for node, alert in sorted(candidates, key=lambda item: priorities[item[0]]):
                    pending.put_nowait((priorities[node], next(sequence), alert))
                self.reply(202, json.dumps({'accepted': len(candidates)}) + '\n')
            except queue.Full:
                self.reply(429, 'busy\n')
            except (ValueError, KeyError, TypeError, Blocked):
                self.reply(400, 'invalid payload\n')

    class Server(ThreadingHTTPServer):
        daemon_threads = True
        request_queue_size = 8

        def __init__(self, *args):
            self.slots = threading.BoundedSemaphore(8)
            super().__init__(*args)

        def process_request(self, request, client_address):
            if not self.slots.acquire(blocking=False):
                request.sendall(b'HTTP/1.0 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n')
                self.shutdown_request(request)
                return
            try:
                super().process_request(request, client_address)
            except Exception:
                self.slots.release()
                raise

        def process_request_thread(self, request, client_address):
            try:
                super().process_request_thread(request, client_address)
            finally:
                self.slots.release()

    return Server(address, Handler)


def serve(config):
    server = make_server(config)
    def stopping(*_):
        STOP.set()
        threading.Thread(target=server.shutdown, daemon=True).start()
    signal.signal(signal.SIGTERM, stopping)
    signal.signal(signal.SIGINT, stopping)
    event('started', automatic_enabled=config['enabled'])
    server.serve_forever(poll_interval=0.5)
    server.server_close()


if __name__ == '__main__':
    config = json.loads(Path(os.environ.get('PI_RECOVERY_CONFIG', '/etc/pi-recovery/config.json')).read_text())
    validate_config(config)
    serve(config)
