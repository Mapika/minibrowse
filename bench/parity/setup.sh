#!/bin/bash
# Provision one fresh browser per (tool, run, task). Usage: setup.sh <run> <task ids...>
# Prints, per task, the connection details the prompts need (browser-harness CDP ports).
set -u
RUN=$1; shift
for T in "$@"; do
  L="p$RUN-$T"
  # mb: what an mb agent gets on a platform: guard on, uploads from /home/user/bench-files
  MB_SESSION="mb-$L" mb start --files /home/user/bench-files >/dev/null 2>&1
  # agent-browser: its own Chrome (system Chrome binary), opened once so the session exists
  AGENT_BROWSER_EXECUTABLE_PATH=/usr/bin/google-chrome timeout 60 agent-browser --session "ab-$L" open about:blank >/dev/null 2>&1
  # browser-harness: a plain Chrome with a CDP port, no mb guard
  MB_SESSION="bh-$L" mb start --debug-port --no-guard >/dev/null 2>&1
  PORT=$(python3 -c "import json,os;print(json.load(open(os.path.expanduser('~/.mb/bh-$L/state.json')))['port'])")
  # OpenCode Browse: a named session in its paired browser
  browse session new "oc-$L" >/dev/null 2>&1
  echo "$T bhport=$PORT"
done
