#!/bin/bash
# Deterministic comparison: each tool's default "read the page" output on the same pages, same Chrome.
# Needs: mb session "ocb" running with the browse extension paired (see bench/README.md).
set -u
OUT=${OUT:-$(dirname "$0")/out}
mkdir -p "$OUT"
URLS=(
  "https://news.ycombinator.com"
  "https://en.wikipedia.org/wiki/Web_browser"
  "https://github.com/vercel-labs/agent-browser"
  "https://www.bbc.com/news"
  "https://developer.mozilla.org/en-US/docs/Web/JavaScript"
  "https://todomvc.com/examples/react/dist/"
)
export MB_SESSION=ocb
PORT=$(python3 -c "import json,os;print(json.load(open(os.path.expanduser('~/.mb/ocb/state.json')))['port'])")
OCB="node ${OCB_DIR:?set OCB_DIR}/devpkg/package/dist/cli.mjs"
agent-browser connect "$PORT" >/dev/null 2>&1

for i in "${!URLS[@]}"; do
  u=${URLS[$i]}
  echo "[$i] $u" >&2
  mb goto "$u" >/dev/null; sleep 2
  mb snap > "$OUT/$i.mb.txt"
  mb snap -i > "$OUT/$i.mb-i.txt"
  agent-browser open "$u" >/dev/null 2>&1; sleep 2
  agent-browser snapshot > "$OUT/$i.agent-browser.txt" 2>&1
  agent-browser snapshot -i > "$OUT/$i.agent-browser-i.txt" 2>&1
  timeout 90 $OCB execute --rm "await page.goto('$u'); await page.waitForTimeout(2000); return await snapshot()" > "$OUT/$i.opencode-browse.txt" 2>&1
done
"${BU_PY:?set BU_PY}" "$(dirname "$0")/bu_state.py" "http://127.0.0.1:$PORT" "$OUT" "${URLS[@]}" 2>/dev/null

printf "\n%-48s" "page (approx tokens = chars/4)"; for t in mb mb-i agent-browser agent-browser-i opencode-browse browser-use; do printf "%16s" "$t"; done; echo
for i in "${!URLS[@]}"; do
  printf "%-48s" "$(echo ${URLS[$i]} | sed 's#https://##' | cut -c1-46)"
  for t in mb mb-i agent-browser agent-browser-i opencode-browse browser-use; do
    f="$OUT/$i.$t.txt"; [ -f "$f" ] && printf "%16s" $(( $(wc -c < "$f") / 4 )) || printf "%16s" "-"
  done; echo
done
