"""Evaluate the production query against labelled series with Prometheus itself."""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from controller import load_per_core_query, resource_queries

instance = '192.0.2.1:9100'
labels = 'cluster="test",instance="' + instance + '",job="node-exporter"'
series = [{'series': 'node_load1{' + labels + '}', 'values': '2 2'}]
series.extend({'series': 'node_cpu_seconds_total{' + labels + ',cpu="' + str(cpu)
                        + '",mode="idle"}', 'values': '0 60'} for cpu in range(4))
fixture = {'rule_files': [], 'evaluation_interval': '1m', 'tests': [{
    'interval': '1m', 'input_series': series,
    'promql_expr_test': [{'expr': load_per_core_query(instance), 'eval_time': '1m',
                         'exp_samples': [{'labels': '{' + labels + '}', 'value': 0.5}]}]}]}
queries = resource_queries(instance)

def boot_fixture(uptime):
    single = '_ _ _ _ _ '
    data = [{'series': 'node_time_seconds{' + labels + '}', 'values': single + str(1000+uptime)},
            {'series': 'node_boot_time_seconds{' + labels + '}', 'values': single + '1000'},
            {'series': 'node_pressure_io_waiting_seconds_total{' + labels + '}',
             'values': single + str(uptime*0.05)}]
    data.extend({'series': 'node_cpu_seconds_total{' + labels + ',cpu="' + str(cpu)
                          + '",mode="idle"}', 'values': single + str(uptime*0.9)} for cpu in range(4))
    return data

fixture['tests'].append({'interval': '1m', 'input_series': boot_fixture(300), 'promql_expr_test': [
    {'expr': queries['cpu_rate'], 'eval_time': '5m', 'exp_samples': []},
    {'expr': queries['io_rate'], 'eval_time': '5m', 'exp_samples': []},
    {'expr': queries['cpu_boot'], 'eval_time': '5m',
     'exp_samples': [{'labels': '{}', 'value': 100*(1-0.9)}]},
    {'expr': queries['io_boot'], 'eval_time': '5m',
     'exp_samples': [{'labels': '{'+labels+'}', 'value': 5}]}]})
fixture['tests'].append({'interval': '1m', 'input_series': boot_fixture(60), 'promql_expr_test': [
    {'expr': queries['cpu_boot'], 'eval_time': '5m', 'exp_samples': []},
    {'expr': queries['io_boot'], 'eval_time': '5m', 'exp_samples': []}]})
Path(sys.argv[1]).write_text(json.dumps(fixture))
