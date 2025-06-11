from langchain_google_genai import ChatGoogleGenerativeAI
from browser_use import Agent, BrowserProfile, BrowserSession
from pathlib import Path
import os
import tomllib

from models import Folder

CONFIG_PATH = (Path(__file__).parent.parent / "config.toml").resolve()
with open(CONFIG_PATH, "rb") as f:
    conf = tomllib.load(f)

IS_HEADLESS = conf["dev"]["headless_operator"]
SSL_VERIFY = conf["dev"]["ssl_verify"]

NESSUS_URL = conf["nessus"]["url"]  # Actual Nessus API URL
NESSUS_USERNAME = conf["nessus"]["username"]
NESSUS_PASSWORD = conf["nessus"]["password"]

GOOGLE_API_KEY = conf["llm"]["google_api_key"]
LLM_MODEL = conf["llm"]["model"]
os.environ["GOOGLE_API_KEY"] = GOOGLE_API_KEY   # langchain_google_genai uses this


def build_scan_prompt(target: str, scan_name: str, scan_type: str, folder: Folder) -> str:
    return f"""
──────────────────────────────────────────────────────────────────────────────
Nessus Essentials one-off “{scan_type}”
──────────────────────────────────────────────────────────────────────────────
Instance URL …… {NESSUS_URL}
Login (if asked) … Username {NESSUS_USERNAME} Password {NESSUS_PASSWORD}
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

async def scan_operator_run(target: str, scan_type: str, scan_name: str, folder: Folder) -> str:
    """Start operator to run the specified scan

    Returns:
        Logs (browser-use repr of AgentHistoryList)
    """
    MAX_STEPS = 25
    WIDTH, HEIGHT = 1440, 736   # Tested to work: Smaller the better if it still works
    llm = ChatGoogleGenerativeAI(model=LLM_MODEL)
    prompt = build_scan_prompt(target, scan_name, scan_type, folder)
    browser_profile = BrowserProfile(
            headless=IS_HEADLESS,
            viewport={"width": WIDTH, "height": HEIGHT},
            window_size={"width": WIDTH, "height": HEIGHT},
            ignore_https_errors=(not SSL_VERIFY),
            allowed_domains=[NESSUS_URL],
    )
    browser_session = BrowserSession(browser_profile=browser_profile)
    agent = Agent(task=prompt,
                  llm=llm,
                  enable_memory=False,
                  browser_session=browser_session,
    )
    agent_history = await agent.run(max_steps=MAX_STEPS)
    return repr(agent_history)

