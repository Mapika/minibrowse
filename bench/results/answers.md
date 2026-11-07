# Agent answers (Sonnet subagents, Nov 7 2026)

## T2 TodoMVC (expected: alpha, gamma visible; "2 items left!")
- mb: alpha, gamma; "2 items left!" (4 Bash calls) ✅
- agent-browser: alpha, gamma; "2 items left!" (4 Bash calls; first `type` attempt replaced by click + keyboard type) ✅
- browser-harness: alpha, gamma; "2 items left!" (7 Bash calls; real Enter presses did not submit, fell back to synthetic JS events) ✅
- opencode-browse: alpha, gamma; "2 items left!" (2 Bash calls: everything batched in one execute) ✅

## T1 Hacker News (all four agents agree; run concurrently at ~16:25 UTC)
- mb: Libghostty 1.0 | 143 comments | jdorfman (4 Bash calls) ✅
- agent-browser: Libghostty 1.0 | 143 | jdorfman (4 Bash calls; first eval ran before load, retried) ✅
- browser-harness: Libghostty 1.0 | 143 | jdorfman (2 Bash calls) ✅
- opencode-browse: Libghostty 1.0 | 143 comments | jdorfman (1 Bash call) ✅

## T3 httpbin form (expected: all fields, size medium, toppings bacon+mushroom, delivery 19:30)
- mb: correct (5 Bash calls; time field needed keypress entry, first attempt left AM/PM unset) ✅
- agent-browser: correct data, but via a workaround: time-picker fill left the value empty, so it set fields in JS and called form.submit(), skipping browser validation (5 Bash calls) ⚠️
- browser-harness: correct (1 Bash call) ✅
- opencode-browse: correct (1 Bash call) ✅

## Round 2: Hacker News #2 story, all four tools at the same time (~16:45 UTC)
- all four: Need for Speed Underground 2 online in the browser | 132 | macNchz ✅
  (mb 6 Bash calls, agent-browser 5, browser-harness 3, opencode 2)

## mb re-runs after the turn-saving changes (later in the day, so HN moved on)
- v2.1 TodoMVC: alpha, gamma; "2 items left!" ✅ · v2.1 form: correct (set the time input in JS) ✅
- v3 TodoMVC: correct ✅ · v3 form: correct (time input set in JS; two eval attempts failed on shell quoting) ✅
- v3 HN: Need for Speed Underground 2… | 135 | Dathuil ✅. We checked the live page: a new comment by
  Dathuil had just landed at the top, with macNchz second.

## Round 4 (mb v4; new task 4 for all four tools)
- mb T1 (HN #2 now "The $8 Linux Computer (2022)"): 49 comments | hypercube33 (3 Bash calls). We checked the live page ✅
- mb T2 TodoMVC: alpha, gamma; "2 items left!" (2 Bash calls) ✅
- mb T3 form: correct, time field filled directly (3 Bash calls) ✅
- T4 (expected "Option 2" | "You entered: mb rocks" | "Hello World!"):
  - mb: correct (2 Bash calls) ✅
  - agent-browser: correct (5 Bash calls; the batched command hung on the JS prompt, 214 s) ✅
  - browser-harness: correct, but by overriding window.prompt in JS and setting the select through JS (2 Bash calls) ⚠️
  - opencode-browse: first run broke because its auto-updater installed a new global `browse` mid-benchmark;
    rerun on the pinned version: correct (1 Bash call) ✅
