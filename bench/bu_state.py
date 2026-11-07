# Prints browser-use's LLM page representation (what its agent sees each step) for each URL.
# Usage: python bu_state.py <cdp_http_url> <outdir> <url>...
import asyncio, sys, os
from browser_use import BrowserSession

async def main():
    cdp, outdir, urls = sys.argv[1], sys.argv[2], sys.argv[3:]
    s = BrowserSession(cdp_url=cdp)
    await s.start()
    for i, url in enumerate(urls):
        await s.navigate_to(url)
        await asyncio.sleep(2.5)
        st = await s.get_browser_state_summary(include_screenshot=False)
        text = st.dom_state.llm_representation()
        open(os.path.join(outdir, f'{i}.browser-use.txt'), 'w').write(text)
    await s.stop()

asyncio.run(main())
