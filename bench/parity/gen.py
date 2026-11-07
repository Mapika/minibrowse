# Print the benchmark prompt for one agent. Usage: python3 -I gen.py <run> <tool> <task> [bhport]
import json, os, sys
run, tool, tid = sys.argv[1:4]; port = sys.argv[4] if len(sys.argv) > 4 else ''
t = {x['id']: x for x in json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tasks.json')))}[tid]
L = f'p{run}-{tid}'
head = ('You are one run in a benchmark of browser tools for AI agents. Do the task below using ONLY the browser tool named here, '
        'through the Bash tool. Do not use curl, wget, WebFetch, WebSearch, Python HTTP libraries, Playwright directly, or any other browser tool.\n\n')
tools = {
 'mb': f'Tool: mb\nInstructions for the tool: read /home/user/minibrowse/bench/skills/mb.md first and follow it.\nHow to call it: every command must be prefixed with the session variable, e.g. `MB_SESSION=mb-{L} mb goto <url>`. A browser for this session is already running.',
 'ab': f'Tool: agent-browser\nInstructions for the tool: read /home/user/minibrowse/bench/skills/agent-browser.md first and follow it.\nHow to call it: always pass the session flag, e.g. `agent-browser --session ab-{L} open <url>`. A browser for this session is already running.',
 'bh': f'Tool: browser-harness\nInstructions for the tool: read /home/user/minibrowse/bench/skills/browser-harness.md first and follow it.\nHow to call it: every call needs both environment variables, e.g.\nBU_NAME=bh-{L} BU_CDP_URL=http://127.0.0.1:{port} browser-harness <<\'PY\'\nnew_tab("https://example.com")\nprint(page_info())\nPY\nA Chrome is already running at that address. Domain skills are off.',
 'oc': f'Tool: browse (OpenCode Browse, CLI form)\nInstructions for the tool: read /home/user/minibrowse/bench/skills/opencode-browse.md first and follow it.\nHow to call it: always pass the session, e.g. `browse execute --session oc-{L} \'await page.goto("https://example.com"); return await snapshot()\'`. The session already exists and is connected to a browser.',
}
foot = ('\n\nWork efficiently. No cleanup is needed at the end. Your final message must be exactly three lines:\n'
        'ANSWER: <the requested values>\nSTEPS: <number of Bash calls you made>\nNOTES: <one short line about any trouble, or "none">')
print(head + tools[tool] + '\n\nTask: ' + t['prompt'] + foot)
