# Grade the parity benchmark: token usage from each subagent transcript, correctness from its answer.
# Usage: python3 -I grade.py <map.tsv> <transcript_dir> > results.json
#   map.tsv lines: <label> <agentId>    label = p<run>-<tool>-<task>, e.g. p1-mb-t03
import json, re, sys, os, collections
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from usage import summarize  # noqa: E402

PRICE = dict(uncached_in=3.0, cache_write=3.75, cache_read=0.30, output=15.0)  # Sonnet, $ per million tokens
tasks = {t['id']: t for t in json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tasks.json')))}

def final_answer(path):
    text = ''
    for line in open(path):
        try:
            d = json.loads(line)
        except Exception:
            continue
        m = d.get('message')
        if d.get('type') == 'assistant' and isinstance(m, dict):
            for c in m.get('content') or []:
                if isinstance(c, dict) and c.get('type') == 'text' and c.get('text', '').strip():
                    text = c['text']
                elif isinstance(c, dict) and c.get('type') == 'tool_use' and c.get('name') == 'SubagentHandback':
                    text = json.dumps(c.get('input', {}))
    return text

def grade(task, answer):
    a = answer.split('NOTES:')[0]  # the answer part only
    ok = all(re.search(p, a, re.I) for p in task['expect'])
    if ok and task.get('reject'):
        ok = not any(re.search(p, a, re.I) for p in task['reject'])
    return ok

over = {}
try: over = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'overrides.json')))
except FileNotFoundError: pass
rows = []
for line in open(sys.argv[1]):
    if not line.strip():
        continue
    label, aid = line.split()
    run, tool, tid = label.split('-', 2)
    path = os.path.join(sys.argv[2], aid + '.output')
    if not os.path.exists(path):
        continue
    u = summarize(path)
    ans = final_answer(path)
    rows.append({'label': label, 'run': run, 'tool': tool, 'task': tid, 'ok': grade(tasks[tid], ans),
                 'cost': sum(u[k] * p for k, p in PRICE.items()) / 1e6, **u, 'answer': ans[-400:]})
    o = over.get(label, {})
    if 'ok' in o: rows[-1]['ok'] = o['ok']
    if o: rows[-1]['note'] = o.get('why') or o.get('workaround')
    rows[-1]['workaround'] = 'workaround' in o
json.dump(rows, sys.stdout, indent=1)
