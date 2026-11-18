"""Explanations of what an IP is reported or observed doing, exploit naming and AI-software targeting.

Everything here describes evidence that exists in the database. Port descriptions say what a port is used for
and what attempts on it usually aim at; they are context, not proof of intent, and are labelled that way.
"""
import re

# port -> (service, what connection attempts to it usually aim at)
PORT_SERVICES = {
    21: ("FTP", "logging in to file servers with guessed passwords"),
    22: ("SSH", "guessing passwords to get a remote shell"),
    23: ("Telnet", "logging in to routers, cameras and IoT devices with default passwords (Mirai-style botnets)"),
    25: ("SMTP mail", "relaying spam or guessing mail account passwords"),
    53: ("DNS", "DNS amplification (DDoS) or resolver abuse"),
    80: ("HTTP web", "scanning for and exploiting web application vulnerabilities"),
    110: ("POP3 mail", "guessing mailbox passwords"),
    123: ("NTP", "NTP amplification (DDoS)"),
    135: ("Windows RPC", "probing Windows hosts for remote-execution flaws"),
    139: ("NetBIOS/SMB", "probing Windows file sharing"),
    143: ("IMAP mail", "guessing mailbox passwords"),
    161: ("SNMP", "reading device configuration with default community strings"),
    389: ("LDAP", "LDAP amplification (DDoS) or directory enumeration"),
    443: ("HTTPS web", "scanning for and exploiting web application vulnerabilities"),
    445: ("SMB", "Windows file-sharing exploits (EternalBlue-style worms, ransomware spread)"),
    1433: ("Microsoft SQL Server", "guessing database passwords"),
    1723: ("PPTP VPN", "guessing VPN credentials"),
    1883: ("MQTT", "taking over IoT message brokers"),
    2375: ("Docker API", "starting containers on exposed Docker hosts (often cryptominers)"),
    3306: ("MySQL", "guessing database passwords"),
    3389: ("RDP (Remote Desktop)", "guessing Windows passwords to get remote desktop access (common ransomware entry)"),
    5060: ("SIP (VoIP)", "hijacking phone systems for toll fraud"),
    5432: ("PostgreSQL", "guessing database passwords"),
    5555: ("Android Debug Bridge", "installing malware on exposed Android devices"),
    5900: ("VNC", "guessing remote-screen passwords"),
    6379: ("Redis", "writing files or SSH keys through an exposed Redis server"),
    7547: ("TR-069 (router management)", "taking over home routers"),
    8080: ("HTTP alternate / proxies", "exploiting web apps or abusing open proxies"),
    8443: ("HTTPS alternate", "exploiting web admin panels"),
    9200: ("Elasticsearch", "reading or wiping exposed data"),
    11434: ("Ollama (local AI models)", "using or abusing exposed AI model servers"),
    27017: ("MongoDB", "reading, wiping or ransoming exposed data"),
}

# blocklist.de per-service lists: id -> (what blocklist.de users reported it attacking)
BLOCKLIST_DE_LISTS = {
    "ssh": "SSH logins (password guessing)",
    "mail": "mail servers (SMTP: spam relay, login guessing)",
    "imap": "mailbox logins (IMAP/POP3/SASL password guessing)",
    "apache": "web servers (exploit attempts, file inclusion, request floods)",
    "bruteforcelogin": "website logins (WordPress, Joomla and other admin panels)",
    "ftp": "FTP logins",
    "sip": "VoIP phone systems (SIP/Asterisk)",
    "bots": "web forms and IRC (spam bots, registration abuse)",
    "strongips": "many targets over more than two months (persistent attacker)",
}

# what a listing by each source means
SOURCE_MEANING = {
    "feodo": "Runs a botnet command-and-control (C2) server: infected computers connect to it to receive "
             "commands and send stolen data.",
    "blocklist_de": "Reported by blocklist.de users (fail2ban servers) for attacking their servers in the last 48 h.",
    "cins": "Rated badly by CINS: it hit CINS Army sensors with scans or attack attempts.",
    "et_compromised": "Listed by Emerging Threats as a compromised host: likely an infected machine now used to attack others.",
    "abuseipdb": "Reported to AbuseIPDB by many independent users (high-confidence blacklist).",
}

# AbuseIPDB report categories (https://www.abuseipdb.com/categories)
ABUSEIPDB_CATEGORIES = {
    1: "DNS compromise", 2: "DNS poisoning", 3: "Fraud orders", 4: "DDoS attack", 5: "FTP brute-force",
    6: "Ping of death", 7: "Phishing", 8: "VoIP fraud", 9: "Open proxy", 10: "Web spam", 11: "Email spam",
    12: "Blog spam", 13: "VPN IP", 14: "Port scan", 15: "Hacking", 16: "SQL injection", 17: "Spoofing",
    18: "Brute-force", 19: "Bad web bot", 20: "Exploited host", 21: "Web app attack", 22: "SSH", 23: "IoT targeted",
}

_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_MS = re.compile(r"\bMS\d{2}-\d{3}\b")

# AI / machine-learning software. Matched against vendor attack names, so this flags attacks AIMED AT AI
# software (LangChain, Ollama, MLflow, ...). No source reports whether an attack was carried out using AI.
AI_SOFTWARE = re.compile(
    r"\b(LangChain|Langflow|LlamaIndex|Llama[ .]?cpp|Ollama|Open ?WebUI|AnythingLLM|Flowise|Dify|LiteLLM|vLLM|"
    r"LocalAI|privateGPT|Lollms|text-generation-webui|ChatGPT|OpenAI|LLM|MLflow|Kubeflow|Ray (?:Dashboard|Cluster|Jobs)|"
    r"Anyscale Ray|ComfyUI|Stable Diffusion|Gradio|Hugging ?Face|Transformers|TorchServe|PyTorch|TensorFlow|"
    r"Triton Inference|BentoML|Jupyter|MCP (?:Protocol|Server|Inspector)|Model Context Protocol|AI Engine|"
    r"AI Assistant|Copilot)\b", re.I)


# Network operators whose name says they rent servers. A name match only: it suggests a rented server (VPS, cloud)
# rather than a home connection, and is labelled as a guess from the name.
HOSTING = re.compile(
    r"\b(Amazon|AWS|Google Cloud|Google LLC|Microsoft|Azure|DigitalOcean|Linode|Akamai Connected Cloud|Vultr|"
    r"Choopa|OVH|Hetzner|Contabo|Scaleway|Online S\.?A\.?S|Alibaba|Aliyun|Tencent|Huawei Cloud|Oracle|IONOS|"
    r"Leaseweb|M247|Hostinger|GoDaddy|Hostwinds|Kamatera|DataCamp|Psychz|Cloudflare|Fastly|Constant Company|"
    r"Hosting|Host|Server|Servers|Cloud|Data ?Center|Datacenter|VPS|Colo)\b", re.I)


def network_kind(org):
    """'hosting' when the operator's name suggests a hosting/cloud provider, else None (unknown)."""
    return "hosting" if org and HOSTING.search(org) else None


def reverse_dns(ip, timeout=5.0):
    """PTR hostname and whether it is forward-confirmed (the hostname resolves back to this IP).
    An unconfirmed PTR can be set to anything by whoever controls the IP's reverse zone."""
    import concurrent.futures
    import socket
    ex = _rdns_pool()

    def run():
        try:
            host = socket.gethostbyaddr(ip)[0]
        except (OSError, UnicodeError):
            return {"hostname": None, "confirmed": False}
        try:
            addrs = {a[4][0] for a in socket.getaddrinfo(host, None)}
        except (OSError, UnicodeError):
            addrs = set()
        return {"hostname": host[:253], "confirmed": ip in addrs}
    try:
        return ex.submit(run).result(timeout=timeout)
    except concurrent.futures.TimeoutError:
        return {"hostname": None, "confirmed": False, "timeout": True}


_POOL = []


def _rdns_pool():
    import concurrent.futures
    if not _POOL:   # small and bounded: a slow resolver cannot pile up threads
        _POOL.append(concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="rdns"))
    return _POOL[0]


def cves(name):
    """CVE and Microsoft bulletin ids named in an attack name."""
    if not name:
        return []
    return sorted({m.upper() for m in _CVE.findall(name)} | set(_MS.findall(name)))


def ai_target(name):
    """The AI/ML product an attack name targets, or None."""
    m = AI_SOFTWARE.search(name or "")
    return m.group(1) if m else None


def port_info(port):
    if not port:
        return None
    s = PORT_SERVICES.get(int(port))
    return {"port": int(port), "service": s[0], "usual_aim": s[1]} if s else {"port": int(port), "service": None,
                                                                             "usual_aim": None}


def activity(indicators, events):
    """Plain-language list of what the evidence says this IP does. Each item names its source and
    observation type: direct observations are things this host saw; reports are claims by a third party."""
    out = []
    for r in indicators:
        src, obs = r["source"], r["observation_type"]
        status = "" if r.get("active") or obs == "direct_observation" else " (no longer listed)"
        if obs == "direct_observation":
            ports = sorted({e["port"] for e in events if e.get("source") == src and e.get("port")} |
                           ({r["port"]} if r.get("port") else set()))
            if r["category"] == "ssh_bruteforce":
                text = f"Tried to log in to this machine over SSH and failed {r.get('hits', 1)} time(s)."
            else:
                text = (f"Sent {r.get('hits', 1)} connection attempt(s) to this machine that the firewall blocked"
                        + (" (ports " + ", ".join(map(str, ports)) + ")." if ports else "."))
            out.append({"what": text, "source": src, "observation_type": obs, "kind": "observed",
                        "ports": [port_info(p) for p in ports]})
            continue
        if src in SOURCE_MEANING:
            text = SOURCE_MEANING[src]
            if src == "feodo" and r.get("malware"):
                text = (f"Runs a {r['malware']} botnet command-and-control (C2) server"
                        + (f" on port {r['port']}" if r.get("port") else "")
                        + ": computers infected with " + r["malware"] + " connect to it for commands.")
            out.append({"what": text + status, "source": src, "observation_type": obs, "kind": "reported"})
        tags = [t for t in (r.get("tags") or "").split(",") if t in BLOCKLIST_DE_LISTS]
        if tags:
            out.append({"what": "Reported attacking: " + "; ".join(BLOCKLIST_DE_LISTS[t] for t in tags) + "." + status,
                        "source": src, "observation_type": obs, "kind": "reported", "targets": tags})
    return out


TAG_SHORT = {"ssh": "SSH logins", "mail": "mail servers", "imap": "mailbox logins", "apache": "web servers",
             "bruteforcelogin": "website logins", "ftp": "FTP", "sip": "VoIP phone systems", "bots": "spam bot",
             "strongips": "persistent attacker"}


def short_activity(source, category, malware=None, port=None, tags=None):
    """One line for feed tables: what this listing says the IP does (same evidence as the IP panel)."""
    tags = [t for t in (tags or []) if t in TAG_SHORT]
    svc = (PORT_SERVICES.get(int(port)) or (None,))[0] if port else None
    if category == "botnet_c2":
        return f"Botnet C2 server{' for ' + malware if malware else ''}{f' (port {port})' if port else ''}"
    if category == "ssh_bruteforce":
        return "SSH password guessing against this machine"
    if category == "blocked_connection":
        return "Blocked connection to this machine" + (f" on port {port} ({svc})" if svc else f" on port {port}" if port else "")
    if category == "compromised_host":
        return "Compromised host used for attacks"
    attacks = [TAG_SHORT[t] for t in tags if t not in ("bots", "strongips")]
    extra = [TAG_SHORT[t] for t in tags if t in ("bots", "strongips")]
    if attacks:
        return "Attacking " + ", ".join(attacks) + ("; " + ", ".join(extra) if extra else "")
    if extra:
        return ", ".join(extra).capitalize()
    if source == "cins":
        return "Scanning / attacking CINS sensors"
    if source == "abuseipdb":
        return "Reported for abuse by many AbuseIPDB users"
    return "Reported attacker"


def summarize_abuseipdb(data, max_comments=5):
    """Reduce an AbuseIPDB /check (verbose) response to what the dashboard shows. Report comments are
    free text written by other users: returned as plain strings (rendered as text, never HTML), truncated."""
    d = data.get("data") if isinstance(data, dict) else None
    if not isinstance(d, dict):
        raise ValueError("unexpected AbuseIPDB format")
    counts = {}
    comments = []
    for rep in d.get("reports") or []:
        if not isinstance(rep, dict):
            continue
        for cat in rep.get("categories") or []:
            if isinstance(cat, int) and cat in ABUSEIPDB_CATEGORIES:
                counts[cat] = counts.get(cat, 0) + 1
        c = rep.get("comment")
        if isinstance(c, str) and c.strip() and len(comments) < max_comments:
            comments.append({"at": str(rep.get("reportedAt") or "")[:25],
                             "categories": [ABUSEIPDB_CATEGORIES[x] for x in rep.get("categories") or []
                                            if isinstance(x, int) and x in ABUSEIPDB_CATEGORIES],
                             "text": " ".join(c.split())[:300]})

    def num(k):
        v = d.get(k)
        return v if isinstance(v, int) and not isinstance(v, bool) else None

    def txt(k, n=120):
        v = d.get(k)
        return v[:n] if isinstance(v, str) else None

    return {
        "confidence": num("abuseConfidenceScore"),
        "total_reports": num("totalReports"),
        "distinct_reporters": num("numDistinctUsers"),
        "last_reported": txt("lastReportedAt", 25),
        "usage_type": txt("usageType"),
        "isp": txt("isp"),
        "domain": txt("domain"),
        "is_tor": d.get("isTor") is True,
        "categories": [{"id": k, "label": ABUSEIPDB_CATEGORIES[k], "reports": v}
                       for k, v in sorted(counts.items(), key=lambda kv: -kv[1])],
        "recent_comments": comments,
    }
