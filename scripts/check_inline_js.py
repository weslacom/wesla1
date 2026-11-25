from html.parser import HTMLParser
from pathlib import Path
import subprocess
import tempfile

class InlineScripts(HTMLParser):
    def __init__(self):
        super().__init__()
        self.inside = False
        self.current = []
        self.scripts = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "script" and not dict(attrs).get("src"):
            self.inside = True
            self.current = []

    def handle_data(self, data):
        if self.inside:
            self.current.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "script" and self.inside:
            self.scripts.append("".join(self.current))
            self.inside = False

for page in ("app/static/index.html", "app/static/control.html"):
    parser = InlineScripts()
    parser.feed(Path(page).read_text(encoding="utf-8"))
    if not parser.scripts:
        raise SystemExit(f"No inline JavaScript found in {page}")
    for number, source in enumerate(parser.scripts, 1):
        with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8") as tmp:
            tmp.write(source)
            tmp.flush()
            subprocess.run(["node", "--check", tmp.name], check=True)
    print(f"JavaScript syntax OK: {page} ({len(parser.scripts)} script block(s))")
