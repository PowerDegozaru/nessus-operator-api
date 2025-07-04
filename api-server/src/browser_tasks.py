from __future__ import annotations

import logging
import os
from langchain_google_genai import ChatGoogleGenerativeAI
from browser_use import Agent, BrowserProfile, BrowserSession

import conf
from models import Folder

logger = logging.getLogger(__name__)

# LangChain-Google setup – keep env var in a single place
os.environ["GOOGLE_API_KEY"] = conf.GOOGLE_API_KEY


def build_scan_prompt(target: str, scan_name: str, scan_type: str, folder: Folder) -> str:  # unchanged
    return f"""
──────────────────────────────────────────────────────────────────────────────
Nessus Essentials one-off “{scan_type}”
──────────────────────────────────────────────────────────────────────────────
Instance URL …… {conf.NESSUS_URL}
Login (if asked) … Username {conf.NESSUS_USERNAME} Password {conf.NESSUS_PASSWORD}
Target ………… "{target}"
──────────────────────────────────────────────────────────────────────────────

1. Open Scan Folder with the name: “{folder.name}”
   • URL must end with **/#/scans/folders/{folder.id}**
   • If check fails, reload that URL.

2. Bring up the template gallery
   • Click the **New Scan** control (id =`new-scan`, text “New Scan”, “＋” icon)
   • If the click doesn’t work, go to **/#/scans/reports/new**.
   • Verify the header shows **Create a New Scan**; otherwise repeat step 1.

3. In the gallery choose: **Vulnerabilities → {scan_type}**

4. Fill the settings form
   • **Name** → `{scan_name}`
   • **Targets** → `{target}`
   • Leave everything else at default.

5. **Save** and wait until the scans table returns.

6. Confirm you are back on the folder's page (folder name: **{folder.name}**).
   • If not, navigate to URL ending with **/#/scans/folders/{folder.id}**

7. Click on the **Launch** icon (▶) on the new scan (named: {scan_name})
   • Sort by “Name” in Descending order if you cannot find the scan

8. Click into the the new scan (named: {scan_name})
   • Make sure the top of the page says **{scan_name}** exactly, otherwise go back and click into the right scan

9. Make sure the **Status** column is **Running** or **Completed**.
   • Otherwise, re-attempt to launch the scan once more starting from step 6. again

10. Task complete.

Constraints:
• Do **not** touch any advanced settings unless told.
• Accept confirmation dialogs with their default *Yes/OK*.
• Work silently; surface an error only after a step fails twice.
• Each scan name must be unique (timestamped).
"""


async def scan_operator_run(
    target: str,
    scan_type: str,
    scan_name: str,
    folder: Folder,
) -> str:
    """
    Run the browser-automation “operator” that creates & launches a Nessus scan.

    Returns
    -------
    str
        Formatted run-log (repr of AgentHistoryList)
    """
    MAX_STEPS = 25
    WIDTH, HEIGHT = 1440, 736

    logger.info(
        "Launching scan operator | target=%s | type=%s | name=%s | folder_id=%s",
        target,
        scan_type,
        scan_name,
        folder.id,
    )

    llm = ChatGoogleGenerativeAI(model=conf.LLM_MODEL)
    prompt = build_scan_prompt(target, scan_name, scan_type, folder)

    browser_profile = BrowserProfile(
        headless=conf.IS_HEADLESS,
        viewport={"width": WIDTH, "height": HEIGHT},
        window_size={"width": WIDTH, "height": HEIGHT},
        ignore_https_errors=not conf.SSL_VERIFY,
        allowed_domains=[conf.NESSUS_URL],
    )
    browser_session = BrowserSession(browser_profile=browser_profile)
    agent = Agent(
        task=prompt,
        llm=llm,
        enable_memory=False,
        browser_session=browser_session,
    )

    try:
        agent_history = await agent.run(max_steps=MAX_STEPS)
        logger.info("Operator completed successfully: %s", scan_name)
        return repr(agent_history)
    except Exception:
        logger.exception("Operator failed for scan %s", scan_name)
        raise
    finally:
        # Gracefully close the browser even on failure
        try:
            await browser_session.close()  # silently ignore if not supported
        except Exception:
            logger.warning("Failed to close browser session", exc_info=True)
