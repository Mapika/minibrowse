# Benchmarks

- `snapshots.sh`: each tool's default "read the page" output on six sites, all in the same Chrome.
  Needs an mb session named `ocb` that has the OpenCode Browse extension loaded and paired
  (`mb start --extension <unpacked dir>`, then `browse pair`), plus `OCB_DIR` and `BU_PY` (a Python with
  `browser-use` installed). Outputs go to `out/`.
- `stealth-test.mjs`: runs the bot-detection sites against Playwright and mb; `stealth-results.txt` is the raw output.
- `usage.py`: sums real API token usage from a Claude Code subagent transcript.
- `report.py`: builds the tables from `results/final.jsonl`.
- `skills/`: the agent instructions the mb subagents read. The other tools' instructions aren't copied
  here; get them from the tools themselves: `agent-browser skills get core`, `browser-harness skill`, and
  OpenCode Browse's `skills/browse/SKILL.md` in the `@opencode/browse` npm package.
- `results/`: per-run usage (`final.jsonl`), the answers (`answers.md`) and the table (`report.md`).

Tool versions: agent-browser 0.27.0, browser-harness 0.1.13, OpenCode Browse 0.0.15-dev.100,
browser-use 0.13.14, Chrome for Testing 153. Model: Claude Sonnet (subagents), Nov 7 2026.

## What one "read the page" costs (approximate tokens, chars/4, same Chrome, Nov 7 2026)

| page | **mb** | agent-browser `snapshot -i` | agent-browser `snapshot` | OpenCode Browse `snapshot()` | browser-use DOM state |
|---|---|---|---|---|---|
| news.ycombinator.com | **1,505** (all 30 stories) | 3,280 | 6,807 | 854 (truncated at 80 items, ~13 stories) | 3,406 |
| en.wikipedia.org/wiki/Web_browser | **1,636** | 5,024 | 21,992 | 1,217 | 3,955 |
| github.com/vercel-labs/agent-browser | **1,596** | 5,734 | 11,603 | 1,108 | 6,416 |
| www.bbc.com/news | **1,302** | 5,869 | 8,783 | 2,314 | 1,839 |
| developer.mozilla.org (JS docs) | **1,558** | 1,720 | 6,129 | 1,599 | 2,142 |
| todomvc.com (React) | **74** | 181 | 475 | 76 | 229 |

Rerun with `snapshots.sh` (the header explains its setup). Outputs are in `out/`.

## Agent benchmark: Sonnet subagents, same tasks, real token usage

Each run is a Claude Sonnet subagent with the same prompt, its tool's own agent instructions (read
at the start, so they count), and a dedicated browser. Token counts come straight from the API usage
in each transcript (`usage.py`). Cost uses Sonnet list prices: $3/M input, $3.75/M cache write,
$0.30/M cache read, $15/M output. Every final answer was correct (`results/answers.md`).

| task | mb | agent-browser | browser-harness | opencode |
|---|---|---|---|---|
| HN #2 story + top commenter | 4 turns · $0.146 | 6 turns · $0.203 | 4 turns · $0.143 | 3 turns · $0.130 |
| TodoMVC | 3 turns · $0.108 | 5 turns · $0.176 | 9 turns · $0.284 | 3 turns · $0.130 |
| httpbin pizza form | 4 turns · $0.131 | 6 turns · $0.208 | 3 turns · $0.126 | 3 turns · $0.138 |
| select + JS prompt + spinner (new) | 3 turns · $0.111 | 6 turns · $0.211 | 3 turns · $0.126 | 3 turns · $0.141 |
| **all four** | **14 turns · $0.496** | **23 turns · $0.798** | **19 turns · $0.678** | **12 turns · $0.539** |
| tool output (chars) | 23,368 | 76,283 | 46,954 | 81,971 |
| vs mb | 1.00× | 1.61× | 1.37× | 1.09× |

**What we learned**
- **Turns cost more than tokens.** Every turn re-reads the agent's ~60k-token base context, so a tool
  that lets the agent finish in one or two calls wins. OpenCode Browse still takes the fewest turns
  (12, against mb's 14), because Sonnet writes whole tasks as Playwright code. mb now wins on cost,
  because each of its turns adds 3–4× less context.
- **Correctness depended on the tool.** On these tasks:
  - agent-browser's form run skipped validation with `form.submit()`;
  - browser-harness fell back to synthetic events on TodoMVC, and overrode `window.prompt` on the new task;
  - agent-browser's batched command hung on the JS prompt (214 s);
  - mb did each task through its normal path, with no workarounds.
- **Caveats.**
  - These are single runs, and one extra turn is about $0.02, so treat differences under ~10% as noise.
  - Hacker News changes during the day, so the competitors' HN row (earlier run) and mb's (later run) cover different #2 stories. The structure is the same; every answer was checked
    against the live page.
  - OpenCode Browse **auto-updated itself mid-benchmark**: it ran `npm install -g` in the background,
    and the new global `browse` broke pairing. Its new-task run was repeated on the pinned version with
    `OPENCODE_BROWSER_AUTO_UPDATE=off`.

The reach-parity benchmark (12 tasks × 4 tools × 2 runs) is in [parity/](parity).
