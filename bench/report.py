# Builds the benchmark table from results/final.jsonl.
# Cost uses Sonnet list prices per million tokens: input $3, cache write $3.75, cache read $0.30, output $15.
import json, collections, sys, os

rows = [json.loads(l) for l in open(sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), 'results/final.jsonl'))]
PRICE = dict(uncached_in=3.0, cache_write=3.75, cache_read=0.30, output=15.0)
cost = lambda r: sum(r[k] * p for k, p in PRICE.items()) / 1e6
TOOLS = ['mb', 'agent-browser', 'browser-harness', 'opencode']
TASKS = [('t1', 'HN: #2 story, comments, top commenter'), ('t2', 'TodoMVC: add 3, complete 1, filter'), ('t3', 'httpbin: fill + submit pizza form')]
by = {r['run']: r for r in rows}

def line(cells, w):
    return '| ' + ' | '.join(str(c).ljust(x) for c, x in zip(cells, w)) + ' |'

out = []
for t, desc in TASKS:
    out.append(f'\n### {desc}\n')
    hdr = ['tool', 'turns', 'bash calls', 'new context (cache write)', 'tool output chars', 'output tok', 'total processed', 'cost $']
    w = [16, 5, 10, 25, 17, 10, 15, 7]
    out.append(line(hdr, w)); out.append('|' + '|'.join('-' * (x + 2) for x in w) + '|')
    for tool in TOOLS:
        r = by.get(f'{t}-{tool}')
        if not r: out.append(line([tool, '-', '-', '-', '-', '-', '-', '-'], w)); continue
        out.append(line([tool, r['turns'], r['bash_calls'], f"{r['cache_write']:,}", f"{r['tool_result_chars']:,}", r['output'], f"{r['total_processed']:,}", f'{cost(r):.4f}'], w))

out.append('\n### All three tasks\n')
hdr = ['tool', 'turns', 'new context', 'tool output chars', 'output tok', 'total processed', 'cost $', 'vs mb']
w = [16, 5, 11, 17, 10, 15, 7, 6]
out.append(line(hdr, w)); out.append('|' + '|'.join('-' * (x + 2) for x in w) + '|')
tot = {}
for tool in TOOLS:
    rs = [by[f'{t}-{tool}'] for t, _ in TASKS if f'{t}-{tool}' in by]
    s = collections.Counter(); [s.update({k: v for k, v in r.items() if k != 'run'}) for r in rs]
    tot[tool] = (s, sum(cost(r) for r in rs), len(rs))
base = tot['mb'][1]
for tool in TOOLS:
    s, c, n = tot[tool]
    out.append(line([tool + ('' if n == 3 else f' ({n}/3)'), s['turns'], f"{s['cache_write']:,}", f"{s['tool_result_chars']:,}", s['output'], f"{s['total_processed']:,}", f'{c:.4f}', f'{c / base:.2f}x'], w))
print('\n'.join(out))
