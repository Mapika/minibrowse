# mb: a minimal browser for AI agents

[![test](https://github.com/Mapika/minibrowse/actions/workflows/test.yml/badge.svg)](https://github.com/Mapika/minibrowse/actions/workflows/test.yml)

`mb` gives an AI agent a real Chrome that it drives from the shell. It's built for platforms where
each agent runs in its own server sandbox.

- **Small output.** mb shows the agent a page as a compact list of what's on it, at most about 1.5k
  tokens. Each item has a ref (`[e12]`) the agent can act on. After an action, mb prints only what
  changed.
- **Few calls.** A whole task fits in one command: chain steps with `mb do`, or write a
  Playwright-style script with `mb run`.
- **Looks human.** It runs a visible Chrome (on a virtual display), with no automation flags and with
  real mouse and keyboard input. Common bot detectors don't flag it.
- **People can step in.** Logins, 2FA and CAPTCHAs go to a person through a live view (`mb handoff`).
- **Safe by default.** Pages can't reach private networks or the machine mb runs on. Uploads come only
  from allowed folders. mb types stored passwords without the agent seeing them. See
  [SECURITY.md](SECURITY.md).
- **Light.** mb is one file (`mb.mjs`) with no dependencies. Chrome uses about 300 MB while busy. With
  `mb start --idle 300` it shuts down after 5 idle minutes, and the next command restores it, logins
  included, in about 1 s.

## Install

mb needs Node 22+, Chrome or Chromium, and Xvfb.

```bash
npm i -g github:Mapika/minibrowse
```

**Windows:** mb needs Node 22+ and Chrome (it falls back to Edge if Chrome isn't installed; set
`MB_CHROME` to use another build). Windows has no Xvfb, so Chrome gets a real window, parked
off-screen and opened without taking keyboard focus. Pages can see that off-screen position
(`screenX` far below zero), which a bot detector could notice. `MB_USE_DISPLAY=1` puts the window on
screen at 0,0 instead, still without taking focus. `MB_FILE_ROOTS` is separated by `;` there.
`test/run.sh` runs under Git Bash.

For containers, the `Dockerfile` builds an image with Chrome, Xvfb, fonts and a non-root user:

```bash
docker build -t mb-sandbox .
docker run --rm --shm-size=1g --security-opt seccomp=<profile> mb-sandbox mb goto example.com
```

Chrome's own sandbox needs user namespaces, which Docker's default seccomp profile blocks. Use a
profile that also allows `clone`, `unshare` and `setns`, or gVisor or Firecracker. Mount a volume at
`/home/agent/.mb` to keep logins across restarts.

## Use

`mb goto` opens a page and prints it:

```bash
mb goto httpbin.org/forms/post
```
```
form [16 controls] [e1]
  textbox "Customer name:" [e2]
  radio "Medium" [e6]
  checkbox "Bacon" [e8]
  time "Preferred delivery time" [e12]
  button "Submit order" [e14]
  …
```

`mb do` then fills and submits the form in one call. The last step, `text`, returns the resulting page:

```bash
mb do 'fill e2 "Ada"; check e6; check e8; fill e12 19:30; click "text=Submit order"; text'
```

`mb run` runs a whole flow as one Playwright-style script:

```bash
mb run <<'JS'
await page.goto('https://example.com/login');
await page.getByLabel('Email').fill('ada@example.com');
await page.getByRole('button', { name: 'Continue' }).click();
return await page.locator('h1').innerText();
JS
```

Other commands:
- `mb find <text>` and `mb text` read the page.
- `mb tabs` lists tabs, and `mb downloads` lists downloaded files.
- `mb net` lists the JSON the page fetched from its own API, and `mb net <n>` prints one response.
- Cookie banners are declined automatically (the privacy-preserving answer), so the agent doesn't
  spend a step on each. Start with `--consent keep` (or set `MB_CONSENT=keep`) to leave them alone.
- `MB_DEBUG=1` logs how long actions wait, and why, to `~/.mb/<session>/daemon.log`.
- `mb handoff "Log in, then click Done"` passes the browser to a person and waits until they're done.
- `mb help` lists everything else.

`MB_SESSION=<name>` runs a separate browser with its own profile.

**Connecting your agent:** give it shell access and [SKILL.md](SKILL.md), about 1k tokens of
instructions that teach it the commands.

## How well it works

**Can agents do everything with it?** We gave the same 12 tasks to Claude Sonnet agents using mb and
three other browser tools, two runs each: 96 agents in all. The tasks:
- **Pages:** a multi-page catalogue, a JavaScript-rendered list, infinite scroll.
- **Interaction:** login and logout, hover menus, nested frames, a new window, drag and drop, a file
  download.
- **Real flows:** a long React form (date picker, autocomplete, upload), a shop and cart, a site's own
  search.

| | **mb** | agent-browser | browser-harness | OpenCode Browse |
|---|---|---|---|---|
| Correct | **24/24** | 23/24 | 24/24 (2 by workaround) | 24/24 (2 by workaround) |
| Cost per task | **$0.124** | $0.195 | $0.200 | $0.161 |
| Shell calls per task | **2.5** | 4.6 | 4.4 | 3.0 |
| Hardest task (the React form) | **$0.117, 2 calls** | $0.469, 15 calls | $0.733, 19.5 calls | $0.315, 8.5 calls |

"By workaround" means the agent got the answer some other way because the tool couldn't do the step;
for example, OpenCode Browse can't download files. Details are in [bench/parity](bench/parity).

**Page size**, in tokens to read the page once:

| | **mb** | agent-browser | browser-use |
|---|---|---|---|
| Hacker News front page | **1,505** | 3,280 | 3,406 |
| Wikipedia article | **1,636** | 5,024 | 3,955 |
| GitHub repository | **1,596** | 5,734 | 6,416 |

More pages and an earlier cost benchmark are in [bench/](bench).

**Bot detection:**

| Detector | Playwright (headless) | **mb** |
|---|---|---|
| deviceandbrowserinfo.com | bot | **human** |
| browserscan.net | robot | **normal** |
| CreepJS headless score | 100% | **0%** |

One tell remains: servers have no GPU. Large anti-bot services also check the IP address's
reputation, so use a residential proxy (`mb start --proxy URL`) where that matters. Raw results are in
[bench/stealth-results.txt](bench/stealth-results.txt).

## Tests

`test/run.sh` runs 66 checks against a local test site, covering forms, dialogs, frames, tabs, the
security controls and the script API. `node test/guard-test.mjs` tests the network guard.
