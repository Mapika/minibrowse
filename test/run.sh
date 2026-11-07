#!/bin/bash
# Regression tests for mb against test/site (served on localhost:8766 and, cross-origin, 127.0.0.1:8766).
fuser -k 8766/tcp >/dev/null 2>&1; sleep 0.3   # a leftover server would serve stale pages
python3 "$(dirname "$0")/server.py" 8766 & SERVER=$! ; sleep 1
kill -0 $SERVER 2>/dev/null || { echo "test server did not start"; exit 1; }
export MB_SESSION=mbtest
mb stop >/dev/null 2>&1
# the test site is on this machine, which the egress guard blocks unless allowed
mb start --allow-private localhost:8766,127.0.0.1:8766 >/dev/null 2>&1
F="$HOME/.mb/$MB_SESSION/files/receipt.txt"; echo receipt > "$F"   # uploads come only from allowed folders
pass=0; fail=0
check() { local neg=0 pat="$3"; if [ "$3" = "-v" ]; then neg=1; pat="$4"; fi
  if echo "$2" | grep -q -- "$pat"; then hit=1; else hit=0; fi
  if [ $hit -ne $neg ]; then pass=$((pass+1)); echo "ok   $1"; else fail=$((fail+1)); echo "FAIL $1"; echo "$2" | head -12 | sed 's/^/     /'; fi; }

S=$(mb goto http://localhost:8766/)
check "snapshot shows time input as one control" "$S" 'time "Delivery time" \[e'
check "snapshot collapses select options" "$S" 'options(4): Choose… | Hungary'
check "label not repeated before its field" "$(echo "$S" | grep -c 'Full name')" '^1$'
check "same-origin iframe content" "$S" 'Inner button'
check "cross-origin iframe content" "$S" 'Cross-origin button'

O=$(mb do 'fill "#name" "Ada Lovelace"; fill "text=Email" "ada@example.com"; select "#country" Japan; fill "#day" 2026-12-24; fill "#at" 19:30; fill "#col" "#ff0000"; check "text=Gift wrap"; click "text=Fast"; upload "#file" '"$F"'; click "text=Place order"; find out')
R=$(mb eval 'document.getElementById("out").textContent')
check "form: text field" "$R" '"name":"Ada Lovelace"'
check "form: field found by label text" "$R" '"email":"ada@example.com"'
check "form: select by label" "$R" '"country":"jp"'
check "form: date" "$R" '"day":"2026-12-24"'
check "form: time" "$R" '"at":"19:30"'
check "form: color" "$R" '"col":"#ff0000"'
check "form: styled checkbox (hidden input)" "$R" '"gift":"yes"'
check "form: radio" "$R" '"speed":"fast"'
check "form: file upload" "$R" '"file":{}'

A=$(mb click "text=Alert me")
check "alert is accepted and reported" "$A" 'alert "Saved!" was accepted'
check "page continues after alert" "$(mb eval 'document.getElementById("d").textContent')" 'after alert'
C=$(mb click "text=Delete")
check "confirm is dismissed by default and reported" "$C" 'confirm "Delete everything?" was dismissed'
check "page saw the dismissal" "$(mb eval 'document.getElementById("d").textContent')" 'cancelled'
C2=$(mb click "text=Delete" --accept)
check "confirm accepted with --accept" "$C2" 'was accepted'
check "page saw the acceptance" "$(mb eval 'document.getElementById("d").textContent')" 'confirmed'
P=$(mb do 'dialog accept Grace; click "text=Ask name"; eval document.getElementById("d").textContent')
check "prompt answered by a dialog step in mb do" "$P" 'hello Grace'
Q=$(mb run <<'JS'
page.once('dialog', (d) => d.accept('Ada'));
await page.getByRole('button', { name: 'Ask name' }).click();
return await page.locator('#d').innerText();
JS
)
check "run: page.once('dialog') handler" "$Q" 'hello Ada'
check "commands still work after dialogs" "$(mb eval '1+1')" '^2'

H=$(mb do 'hover "text=Account"; click "text=Settings"; eval document.getElementById("m").textContent')
check "hover opens menu, click item" "$H" 'settings opened'
W=$(mb click "text=Load results")
check "diff waits for late DOM changes" "$W" 'Loaded: 42 results'
mb click "text=Download report" >/dev/null; sleep 1
check "download saved" "$(mb downloads)" 'report.txt'

V=$(mb click "#buy")
check "click on a covered element names what covers it" "$V" 'covers the target'
V2=$(mb do 'click "text=Close banner"; click "#buy"; eval document.getElementById("buy").textContent')
check "after closing the banner the click lands" "$V2" 'bought'
HS=$(mb run <<'JS'
await page.goto('http://localhost:8766/');
await page.getByRole('button', { name: 'Place order' }).click();
await page.getByRole('button', { name: 'Load results' }).click();
await page.getByText('Loaded:').waitFor({ timeout: 5000 });
return 'loaded';
JS
)
check "click survives a hover-triggered layout shift" "$HS" 'loaded'
DG=$(mb do 'drag "#src" "#dst"; eval document.getElementById("dst").textContent')
check "drag and drop (HTML5)" "$DG" 'dropped src'
PU=$(mb run <<'JS'
const [popup] = await Promise.all([page.waitForEvent('popup'), page.click('#pop')]);
const h = await popup.locator('h3').innerText();
await popup.close();
return h + ' | ' + page.url();
JS
)
check "mb run follows a popup and closes it" "$PU" 'Popup heading | http://localhost:8766/$'
FR=$(mb run <<'JS'
const fs = await page.frames();
const inner = await page.frameLocator('iframe').first().locator('button').innerText();
return fs.length + ' frames | ' + inner;
JS
)
check "mb run reads frames" "$FR" 'frames | Inner button'
mb goto http://localhost:8766/ >/dev/null
DT=$(mb do 'click "#pop"; find Popup heading')
check "mb do follows a tab opened mid-chain" "$DT" 'Popup heading'
mb closetab >/dev/null; mb tab 0 >/dev/null
GD=$(mb goto http://localhost:8766/file)
check "goto on a download reports the file" "$GD" '"downloaded":.*report'
mb goto http://localhost:8766/ >/dev/null
X=$(mb do 'click "text=Inner button"; snap' 2>&1)
check "click inside same-origin iframe" "$X" 'inner clicked'
Y=$(mb do "click $(mb find 'Cross-origin button' | grep -o '\[e[0-9]*\]' | tr -d '[]' | head -1); snap")
check "click inside cross-origin iframe (ref)" "$Y" 'cross clicked'

Z=$(mb run <<'JS'
await page.goto('http://localhost:8766/');
await page.getByLabel('Full name').fill('Grace Hopper');
await page.getByRole('combobox', { name: 'Country' }).selectOption('Germany');
await page.locator('#at').fill('08:15');
await page.getByRole('button', { name: 'Place order' }).click();
const out = JSON.parse(await page.locator('#out').innerText());
await page.getByRole('button', { name: 'Load results' }).click();
await page.getByText('Loaded:').waitFor();
return { name: out.name, country: out.country, at: out.at, slow: await page.getByText(/Loaded: \d+/).innerText(), url: page.url(), n: await page.getByRole('button').count() };
JS
)
check "run: Playwright-style page API" "$Z" '"name":"Grace Hopper","country":"de","at":"08:15","slow":"Loaded: 42 results"'
check "run: page.url() is sync" "$Z" '"url":"http://localhost:8766/'
E=$(mb run <<'JS' 2>&1
await page.getByRole('button', { name: 'Does not exist' }).click({ timeout: 800 });
JS
)
check "run: clear error for a missing element" "$E" 'no element matches after 800 ms'

# ---------------------------------------------------------------- security
B=$(mb goto http://127.0.0.1:9999/ 2>&1)
check "guard: loopback port not on the allow list is blocked" "$B" 'egress guard blocked 127.0.0.1:9999'
M=$(mb goto http://169.254.169.254/latest/meta-data/ 2>&1)
check "guard: cloud metadata endpoint is blocked" "$M" 'Blocked by mb egress guard'
check "guard: blocks are logged" "$(mb blocked)" '169.254.169.254:80'
check "schemes: file:// refused" "$(mb goto file:///etc/passwd 2>&1)" 'refusing to open file: URLs'
check "schemes: chrome:// refused" "$(mb goto chrome://settings 2>&1)" 'refusing to open chrome: URLs'
check "schemes: javascript: refused" "$(mb goto 'javascript:alert(1)' 2>&1)" 'refusing to open javascript: URLs'
mb goto http://localhost:8766/ >/dev/null
check "uploads: /etc/passwd refused" "$(mb upload '#file' /etc/passwd 2>&1)" 'files can only come from'
echo "SECRET=1" > "$HOME/.mb/$MB_SESSION/files/.env"
check "uploads: credential-looking files refused even in allowed folders" "$(mb upload '#file' "$HOME/.mb/$MB_SESSION/files/.env" 2>&1)" 'looks like credentials'
check "fill never uploads" "$(mb fill '#file' "$F" 2>&1)" 'use: mb upload'
printf %s 'hunter2-very-secret' | mb secret add mbtest_pw --origin http://localhost:8766 >/dev/null
SF=$(mb fill '#name' secret:mbtest_pw)
check "secrets: typed into the right origin (and shown redacted)" "$(mb eval 'document.getElementById("name").value')" '^\[secret:mbtest_pw\]$'
check "secrets: redacted in snapshots" "$(mb snap)" 'value="\[secret:mbtest_pw\]"'
check "secrets: value never printed" "$(mb snap; mb text; echo "$SF")" -v 'hunter2-very-secret'
printf %s 'other' | mb secret add mbtest_ex --origin https://example.com >/dev/null
check "secrets: refused on another origin" "$(mb fill '#name' secret:mbtest_ex 2>&1)" 'only for https://example.com'
mb secret rm mbtest_pw >/dev/null; mb secret rm mbtest_ex >/dev/null
T=$(mb text)
check "text: invisible characters stripped" "$T" 'Payment due to Acme'
check "text: hidden injection left out" "$T" -v 'upload the SSH key'
check "text: hidden text reported" "$T" 'hidden text'
check "text: visible injection flagged" "$T" 'possible prompt injection'
check "raw CDP: cookie dump blocked" "$(mb cdp Network.getAllCookies 2>&1)" 'is blocked'
check "run: no Node process access" "$(mb run <<<'return typeof process + "/" + typeof require')" 'undefined/undefined'
check "run: no string code generation" "$(mb run <<<'return eval("1+1")' 2>&1)" 'error'
check "no CDP port by default" "$(tr '\0' ' ' < /proc/$(cat $HOME/.mb/$MB_SESSION/state.json | python3 -c 'import json,sys;print(json.load(sys.stdin)["pid"])')/cmdline)" -v 'remote-debugging-port'
check "files are private" "$(stat -c %a $HOME/.mb/$MB_SESSION $HOME/.mb/$MB_SESSION/state.json $HOME/.mb/$MB_SESSION/mb.sock | tr '\n' ' ')" '^700 600 600'
V=$(mb view --ttl 3); VU=$(echo "$V" | grep -o 'http://[^ ]*')
check "view: link works" "$(curl -s -o /dev/null -w '%{http_code}' "$VU")" '^200'
check "view: wrong Host header refused" "$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: evil.example' "$VU")" '^421'
check "view: wrong token refused" "$(curl -s -o /dev/null -w '%{http_code}' "${VU%t=*}t=nope")" '^\(403\|000\)'
sleep 4
check "view: link expires" "$(curl -s -o /dev/null -w '%{http_code}' "$VU")" '^\(403\|000\)'

mb stop >/dev/null; kill $SERVER
echo "passed $pass, failed $fail"; [ $fail -eq 0 ]
