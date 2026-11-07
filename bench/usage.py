# Sums token usage from a Claude Code subagent transcript (JSONL), without printing its content.
# Usage: python3 -I usage.py <label> <transcript.jsonl> [...pairs]   -> one JSON line per run
import json, sys

def summarize(path):
    seen = set()  # streamed assistant messages repeat the same message id; count each once
    u = dict(turns=0, uncached_in=0, cache_write=0, cache_read=0, output=0, bash_calls=0, tool_result_chars=0)
    for line in open(path):
        try:
            d = json.loads(line)
        except Exception:
            continue
        m = d.get('message')
        if not isinstance(m, dict):
            continue
        if d.get('type') == 'assistant':
            mid = m.get('id')
            content = m.get('content') or []
            for c in content if isinstance(content, list) else []:
                if isinstance(c, dict) and c.get('type') == 'tool_use' and c.get('name') == 'Bash':
                    key = (mid, c.get('id'))
                    if key not in seen:
                        seen.add(key); u['bash_calls'] += 1
            us = m.get('usage')
            if us and (mid, 'usage') not in seen:
                seen.add((mid, 'usage'))
                u['turns'] += 1
                u['uncached_in'] += us.get('input_tokens', 0)
                u['cache_write'] += us.get('cache_creation_input_tokens', 0)
                u['cache_read'] += us.get('cache_read_input_tokens', 0)
                u['output'] += us.get('output_tokens', 0)
        elif d.get('type') == 'user':
            content = m.get('content')
            for c in content if isinstance(content, list) else []:
                if isinstance(c, dict) and c.get('type') == 'tool_result':
                    inner = c.get('content')
                    if isinstance(inner, list):
                        u['tool_result_chars'] += sum(len(x.get('text', '')) for x in inner if isinstance(x, dict))
                    elif isinstance(inner, str):
                        u['tool_result_chars'] += len(inner)
    u['total_processed'] = u['uncached_in'] + u['cache_write'] + u['cache_read'] + u['output']
    return u

if __name__ == '__main__':
  args = sys.argv[1:]
  for label, path in zip(args[::2], args[1::2]):
    print(json.dumps({'run': label, **summarize(path)}))
