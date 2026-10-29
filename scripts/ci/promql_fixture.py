"""Evaluate the production query against labelled series with Prometheus itself."""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from controller import load_per_core_query

instance = '192.0.2.1:9100'
labels = 'cluster="test",instance="' + instance + '",job="node-exporter"'
series = [{'series': 'node_load1{' + labels + '}', 'values': '2 2'}]
series.extend({'series': 'node_cpu_seconds_total{' + labels + ',cpu="' + str(cpu)
                        + '",mode="idle"}', 'values': '0 60'} for cpu in range(4))
fixture = {'rule_files': [], 'evaluation_interval': '1m', 'tests': [{
    'interval': '1m', 'input_series': series,
    'promql_expr_test': [{'expr': load_per_core_query(instance), 'eval_time': '1m',
                         'exp_samples': [{'labels': '{' + labels + '}', 'value': 0.5}]}]}]}
Path(sys.argv[1]).write_text(json.dumps(fixture))
