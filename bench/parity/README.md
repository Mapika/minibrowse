# Reach-parity benchmark

12 tasks × 4 browser tools × 2 runs: 96 Sonnet subagents. Each was told to use only its tool through
Bash, and to answer in three lines (ANSWER, STEPS, NOTES). Each run got a fresh browser.

- `tasks.json`: the tasks and the regular expressions an answer must match.
- `setup.sh <run> <tasks…>`: provisions one browser per tool, run and task.
- `gen.py <run> <tool> <task> [bhport]`: prints the exact prompt.
- `grade.py <map.tsv> <transcript dir>` (map lines: `<label> <agent id>`): token usage from each transcript, plus whether the answer is correct.
- `overrides.json`: runs whose transcript shows the answer wasn't earned, or was reached by a workaround.
- `results.json`: the graded runs.

Cost uses Sonnet prices ($3/M input, $3.75/M cache write, $0.30/M cache read, $15/M output). It
includes the subagent's fixed ~65k-token base context, about $0.10 per task.

## Per task (correct runs · mean cost · mean Bash calls)

| task | mb | agent-browser | browser-harness | OpenCode Browse |
|---|---|---|---|---|
| t01 catalogue: category → 3rd book → UPC | 2/2 · $0.110 · 2.0 | 2/2 · $0.167 · 3.5 | 2/2 · $0.134 · 2.5 | 2/2 · $0.133 · 2.0 |
| t02 JS-rendered list, Next page | 2/2 · $0.121 · 2.0 | 2/2 · $0.265 · 7.5 | 2/2 · $0.120 · 1.5 | 2/2 · $0.132 · 1.5 |
| t03 infinite scroll to item 20 | 2/2 · $0.110 · 2.0 | 2/2 · $0.129 · 2.0 | 2/2 · $0.192 · 4.5 | 2/2 · $0.130 · 2.0 |
| t04 log in, read message, log out | 2/2 · $0.188 · 5.5 | 2/2 · $0.129 · 2.0 | 2/2 · $0.122 · 1.5 | 2/2 · $0.185 · 4.0 |
| t05 hover caption | 2/2 · $0.131 · 2.5 | 2/2 · $0.127 · 2.0 | 2/2 · $0.135 · 2.5 | 2/2 · $0.129 · 2.0 |
| t06 nested frames | 2/2 · $0.110 · 2.0 | 2/2 · $0.167 · 3.5 | 2/2 · $0.121 · 2.0 | 2/2 · $0.157 · 2.5 |
| t07 new window | 2/2 · $0.134 · 3.5 | 2/2 · $0.139 · 2.5 | 2/2* · $0.219 · 6.0 | 2/2 · $0.131 · 2.0 |
| t08 drag and drop | 2/2 · $0.112 · 2.0 | 2/2 · $0.128 · 2.0 | 2/2 · $0.181 · 4.0 | 2/2 · $0.185 · 4.0 |
| t09 file download | 2/2 · $0.109 · 2.0 | 1/2 · $0.167 · 3.5 | 2/2 · $0.123 · 2.0 | 2/2* · $0.132 · 2.0 |
| t10 demoqa form (date, autocomplete, upload, selects) | 2/2 · $0.117 · 2.0 | 2/2 · $0.469 · 15.0 | 2/2 · $0.733 · 19.5 | 2/2 · $0.315 · 8.5 |
| t11 saucedemo: sort, add to cart, cart | 2/2 · $0.110 · 2.0 | 2/2 · $0.279 · 8.0 | 2/2 · $0.142 · 2.0 | 2/2 · $0.173 · 3.5 |
| t12 Wikipedia via the site's search | 2/2 · $0.141 · 2.5 | 2/2 · $0.178 · 4.0 | 2/2 · $0.179 · 4.5 | 2/2 · $0.131 · 2.0 |
| **all** | **24/24 · $0.124 · 2.5** | **23/24 · $0.195 · 4.6** | **24/24 · $0.200 · 4.4** | **24/24 · $0.161 · 3.0** |

\* reached by a workaround (see `overrides.json`).

## Notes from the runs

- p1-bh-t07: the click opened no window; opened the link's URL directly
- p1-oc-t09: no download support: re-fetched the URL in page and read the headers
- p2-bh-t07: the click opened no window; opened the link's URL directly
- p2-ab-t09: no download of its own; read the size of another run's file in ~/Downloads
- p2-oc-t09: no download support: re-fetched the URL in page and read the headers
