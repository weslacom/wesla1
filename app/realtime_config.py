import json
import os

# The anon key is intentionally public and is protected by Supabase RLS.
# Never place the service_role or secret key in this module or browser HTML.
DEFAULT_SUPABASE_URL = "https://ojxvcusprpnzooqfkojt.supabase.co"
DEFAULT_SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im9qeHZjdXNwcnBuem9vcWZrb2p0Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTUzNzkxMjYsImV4cCI6MjExMDk1NTEyNn0.xbk-Mbyq-HR2pApOrwlI1-vAzCItqKZCCSjDBeIYxFc"


def inject_realtime_config(html: str) -> str:
    url = os.getenv("SUPABASE_URL", DEFAULT_SUPABASE_URL).strip()
    anon_key = os.getenv("SUPABASE_ANON_KEY", DEFAULT_SUPABASE_ANON_KEY).strip()
    config = (
        f"window.WESLA_SUPABASE_URL={json.dumps(url)};"
        f"window.WESLA_SUPABASE_ANON_KEY={json.dumps(anon_key)};"
    )
    return html.replace("<script>", f"<script>{config}", 1)
