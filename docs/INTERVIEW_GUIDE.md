# mini-siem: Interview Guide

This guide is for **you, the author**. It explains every part of the project in plain English so you can talk about it confidently in a SOC/SIEM interview. Read it alongside the code. Each section names the file to open.

> **Rule #1:** be able to explain *every* line you show. Interviewers will pick a random file and ask "why did you do it this way?". If any part was written with help (a tutorial, a colleague, an AI assistant), say so honestly if asked. What they are testing is whether *you* understand it now. Change a threshold, add a rule and break a test on purpose until it all feels like yours.

---

## 1. The 30-second pitch

> "I built a mini SIEM in Python. It ingests Linux auth logs, web server access logs and JSON application logs, normalises them into one event schema loosely based on Elastic Common Schema, and stores them in SQLite. A correlation engine runs YAML detection rules: SSH brute force, brute force followed by a successful login, password spraying, web scanning, SQL injection, path traversal and XSS patterns, unusual sudo, and logins from a deny-listed IP. Each rule is mapped to MITRE ATT&CK. Alerts have severity and a triage status, and a Flask dashboard lets you filter alerts, change their status and search events. I also treated the dashboard as an attack surface, because it displays attacker-controlled log data, so it escapes all output, uses a strict CSP, CSRF tokens and parameterised SQL. It has 115 tests."

---

## 2. Walkthrough, module by module

### 2.1 `schema.py`: the normalised event

**What:** one `Event` dataclass with `timestamp, source, event_type, outcome, source_ip, user, host, raw, details`.

**Why it matters:** this is *normalisation*. auth.log says `Failed password for root from 203.0.113.45`, a JSON app says `{"client_ip": ..., "result": "failed"}`. After parsing, both become `outcome="failure", source_ip=..., user=...`. Now **one rule** (password spraying) covers SSH *and* the web app.

**Design choices to mention:**
- **Everything in UTC.** The web log is in Malaysia time (`+0800`) and auth.log is in UTC. If you don't convert, a brute force followed by a success would look 8 hours apart. Correlation depends on correct time.
- **Fixed-width timestamp string** `2026-10-14T03:15:00Z`. Alphabetical order = time order, so SQLite can sort and range-query plain text, and "events per hour" is just `substr(timestamp, 1, 13)`.
- **`raw` is always kept.** An analyst must be able to see the original evidence, not just our interpretation of it.
- **`details`** holds format-specific fields (HTTP status, sudo command), so the core schema stays small.
- Field names are *inspired by* ECS (`source.ip`, `user.name`, `event.outcome`) but flattened. Say "loosely inspired", not "ECS-compliant".

### 2.2 `parsers/`: raw line → Event

- `auth_log.py`: regexes for sshd (`Failed password`, `Accepted password|publickey`, `Invalid user`) and sudo (`USER=root ; COMMAND=...`). Classic syslog has **no year and no timezone**, so the year comes from `--year` and we assume UTC. Newer Ubuntu writes RFC 3339 timestamps, and those are handled too.
- `web_access.py`: one regex for the Apache/Nginx "combined" format. The URL is **URL-decoded up to twice** (`decode_url`) because attackers encode payloads: `%27%20OR%20...` is `' OR ...`, and `%252e%252e%252f` is double-encoded `../`.
- `json_log.py`: `FIELD_ALIASES` maps `src_ip`/`client_ip`/`source.ip` → `source_ip`, and so on. Unknown keys go into `details` so nothing is lost.

**Design choices:**
- A parser returns **`None`** for lines it doesn't understand instead of crashing. Real logs are full of noise (CRON, PAM sessions), and one malformed line must never stop ingestion. The CLI reports how many lines were skipped, so the gap is visible rather than silent.
- **IPs are validated** with Python's `ipaddress` module. Log content is attacker-controlled, so `1.2.3.4; DROP` is not an IP and is stored as null.
- **Lengths are capped** (raw line 8 KB, URL 2 KB), so a single huge malicious line can't bloat the DB or the UI.

### 2.3 `ingest.py`: getting lines in

- `ingest_file` reads the whole file and bulk-inserts the events in one transaction, which is fast.
- `follow_lines` works like `tail -f` in pure Python: it polls the file size every second and reads new bytes. Two edge cases are handled:
  - **Half-written line:** the logger flushed `"Failed passw"` and the rest comes later. We buffer until a `\n` arrives.
  - **Rotation/truncation:** if the file got *smaller*, logrotate replaced it, so we start again from byte 0.
- Files are read in **binary mode** and decoded with `errors="replace"`. Invalid UTF-8 (which attackers send on purpose) can't crash us, and `tell()` gives real byte offsets on Windows too.
- **Idempotent ingest:** each line gets a fingerprint `sha256(source | filename | byte offset | line)`, and the DB has `UNIQUE(fingerprint)`. Ingesting the same file twice adds 0 events.

### 2.4 `storage.py`: SQLite

- Two tables: `events` and `alerts`. Indexes are on timestamp, IP, user and type, the columns we search on.
- **Every query uses `?` placeholders.** Log data is attacker-controlled. A user name like `'; DROP TABLE events; --` is stored and searched as text. There is a test for exactly this (`test_search_is_safe_against_sql_injection`).
- The only dynamic SQL is the *structure* of the WHERE clause, built from a hard-coded list of column names, never from user input.
- `LIKE` wildcards (`%`, `_`) in the text search are escaped, so searching for `100%` means the literal text.
- **WAL mode** lets the dashboard read while `follow` writes.
- `save_alert` inserts a new alert, or updates the existing one with the same `dedup_key`. It **never overwrites `status`**: if an analyst closed an alert, re-running detection does not reopen it.

### 2.5 `rules.py` + `rules/*.yml`: detection content

- Rules are YAML, so an analyst can read and tune them without touching Python. This is the same idea as **Sigma**.
- Loaded with **`yaml.safe_load`**, never `yaml.load`. The unsafe loader can build arbitrary Python objects from a crafted file, which is code execution. There is a test that a `!!python/object/apply:os.system` tag is rejected.
- Filters are compiled into small Python functions once at load time, so evaluation per event is cheap.
- Rules are validated (severity, type, regex compiles, required keys). A broken rule fails loudly with the file name, instead of silently never firing. **A silently broken rule is one of the worst things in a SOC: you think you are covered and you are not.**

### 2.6 `detection.py`: the correlation engine

Events are fed **in time order** and each rule gets a detector:

| Detector | Question it answers | State it keeps |
|---|---|---|
| `MatchDetector` | "Is this single event bad?" (SQLi URL, sudo by dave) | none (except grouping) |
| `ThresholdDetector` | "Has this IP done X at least N times in T seconds?" | a sliding window (deque) per IP |
| `ThresholdDetector` + `distinct` | "Has this IP tried at least N *different users*?" (spraying) | window + set of users |
| `SequenceDetector` | "Did A happen N times and *then* B?" (failures → success) | a window of 'A' events per IP |

**Sliding window:** keep a deque of timestamps per IP. On each new event, append it, then pop from the left everything older than `window_seconds`. If `len(deque) >= threshold`, alert.

**Incident aggregation (alert-flood control):** after an alert fires for an IP, more matching events from that IP during `suppress_seconds` are **added to the same alert**: the count, `last_seen` and evidence grow. That is why the sample says "8 failed SSH logins" in *one* alert and not four alerts. This is the trade-off between **alert fatigue** (too many alerts) and **losing information** (suppressing silently).

**Deterministic `dedup_key`** = rule id + group + first event time. Running `detect` twice gives identical keys, so nothing is duplicated.

### 2.7 `web/`: the dashboard

- `app.py` uses an application factory (`create_app`), so tests can create an app on a temporary database.
- One SQLite connection per request, closed in `teardown_appcontext`, because sqlite3 connections must not be shared across threads.
- `charts.py` computes bar positions in Python, and the template draws **inline SVG**. There is **no JavaScript and no CDN**, so it works offline and fits a strict CSP. Hovering a bar shows a native tooltip (`<title>`), and a "Show as table" view gives the exact numbers for accessibility.
- Severity is always shown as a **text label** (CRITICAL/HIGH...). Colour is only an extra cue, so colour-blind analysts lose nothing.

### 2.8 Why the dashboard is safe against XSS (be ready to explain this)

The dashboard shows strings that **attackers wrote**: URLs, user names, user agents. The sample access log contains `/search?q=<script>alert(document.cookie)</script>`. If we inserted that into HTML as-is, the browser would run the script *in the analyst's browser*. That is **stored XSS against the SOC**: the attacker could close their own alerts or read data.

Defences, in layers:
1. **Output encoding (the main defence).** Jinja2 autoescaping is on for `.html` templates, so `{{ value }}` turns `<` into `&lt;`. The browser shows the text `<script>` and does not execute it. We **never** use `|safe` or `Markup()` on log data. A test checks that the raw `<script>alert` never appears in the HTML and that the escaped form does.
2. **Content-Security-Policy** `default-src 'none'; style-src 'self'; ...`. There is no `script-src`, so even if escaping were bypassed somewhere, the browser refuses to run any script. That's defence in depth.
3. Inside the SVG chart, labels are also auto-escaped, and we never build HTML by string concatenation in Python.

Related protections:
- **CSRF:** changing alert status is a `POST` with a random per-session token (`hmac.compare_digest` comparison). Without it, any website you visit could auto-submit a form to `http://127.0.0.1:5000/alerts/1/status` and close alerts. The session cookie is also `SameSite=Strict` and `HttpOnly`.
- **No state change on GET** (GET on the status URL returns 405).
- **No open redirect:** after a POST we redirect only to one of two fixed pages.
- **Bound to 127.0.0.1**, with no login. Running `serve --bind 0.0.0.0` prints a warning.
- `debug=False`: the Werkzeug debugger allows running code from the browser, so it is never on.

---

## 3. Key concepts (say these in your own words)

**Log normalisation.** Converting many log formats into one common schema so that rules, searches and dashboards work across all sources. Without it you would need one brute-force rule per log format. Examples: ECS (Elastic), CIM (Splunk), QRadar's normalised event fields.

**Correlation.** Combining multiple events, possibly from different sources and times, to reach a conclusion no single event shows. "One failed login" is noise. "Eight in 35 seconds, then a success from the same IP" is a compromised account.

**Thresholds and time windows.** A threshold rule says "N events in T seconds". *Lower N* catches more attacks but raises more false alarms. *Longer T* catches slow attacks (spraying) but needs more memory and is noisier. Spraying is designed to evade per-IP and per-account thresholds, which is why that rule counts *distinct users* over 15 minutes instead.

**False positives vs false negatives.**
- *False positive:* an alert for something benign (alice mistypes her password five times). It costs analyst time and causes alert fatigue.
- *False negative:* a real attack with no alert (a slow brute force under the threshold). It costs a breach.
- **Tuning** means moving the trade-off: thresholds, allow-lists (`sudo_unusual_user`), grouping and suppression. The test suite has *negative* tests ("a typo then success is NOT an alert", "`/search?q=O'Reilly` is NOT SQLi") to stop tuning from making rules noisy.

**Severity vs status.** Severity = how bad if true (rule author decides). Status = where the analyst is in triage (open → acknowledged → closed).

**MITRE ATT&CK.** A public knowledge base of attacker tactics (the *why*, e.g. Credential Access) and techniques (the *how*, e.g. T1110.003 Password Spraying). Mapping rules to it shows coverage gaps and gives analysts shared vocabulary.

**SIEM vs EDR (and friends).**

| | SIEM | EDR |
|---|---|---|
| Data | Logs from *everything*: servers, firewalls, apps, cloud, EDR itself | Deep telemetry from *endpoints*: processes, files, registry, network per host |
| Strength | Cross-source correlation, central search, retention, compliance | Seeing exactly what ran on a machine; can **respond** (kill process, isolate host) |
| Weakness | Only as good as the logs sent to it; usually doesn't block | Blind to things off the endpoint (network devices, SaaS) |
| Examples | Splunk ES, QRadar, Elastic Security, Microsoft Sentinel | CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne |

They complement each other: EDR alerts are often *sent into* the SIEM. **XDR** combines endpoint, network and cloud telemetry. **SOAR** automates the response playbooks.

---

## 4. Ten likely interview questions, with model answers

**Q1. Walk me through what happens when one line of auth.log is ingested.**
> "`ingest` reads the file in binary mode, decodes each line as UTF-8 with replacement, and passes it to `AuthLogParser.parse`. The parser splits off the syslog header (timestamp, host, program), and if the program is sshd it matches regexes like `Failed password for X from IP`. It returns an `Event` with `event_type=ssh_login`, `outcome=failure`, the validated IP and user, the UTC timestamp and the raw line. The event gets a SHA-256 fingerprint and is inserted with a parameterised query; duplicates are ignored by a UNIQUE constraint. Then detection re-scans events in time order, and the brute-force detector appends the event to that IP's sliding window and checks the threshold."

**Q2. How does your brute-force rule work, and how would you tune it?**
> "It's a threshold rule: failed `ssh_login` events grouped by source IP, alert at 5 within 60 seconds. I keep a deque of timestamps per IP and drop entries older than the window. To tune it, I'd look at a baseline of normal failed logins. If users with bad typing trigger it, I'd raise the threshold or exclude internal ranges. If attackers go slow, I'd add a second rule with a longer window. I'd also pair it with the 'failures then success' rule, which is the one that really matters, because it means the attack worked."

**Q3. What's the difference between brute force and password spraying, and why do they need different rules?**
> "Brute force is many passwords against one account. Spraying is one or a few common passwords against *many* accounts, slowly, to avoid account lockout and per-IP rate thresholds. A per-IP count over 60 seconds misses it, so the spraying rule counts *distinct user names* per IP over 15 minutes. In my sample the sprayer makes one attempt every 45 seconds, which never trips the brute-force rule but does trip the spraying rule."

**Q4. Your dashboard displays attacker-controlled data. How do you prevent XSS?**
> "Output encoding is the main defence: Jinja autoescaping turns `<` into `&lt;`, and I never mark log data as safe. Then defence in depth: a Content-Security-Policy with no script sources at all, so the browser would refuse to run scripts even if escaping failed. The sample logs include real XSS payloads, and a test asserts they appear escaped in the HTML. I also added CSRF tokens on the status-change form, because a local dashboard can still be attacked from a malicious website in the same browser."

**Q5. How do you avoid SQL injection?**
> "Every query uses parameter placeholders, so the database driver sends values separately from the SQL text and they are never interpreted as SQL. The only dynamic part is which WHERE clauses are included, and the column names come from a fixed list in code. I have a test that searches for `x' OR '1'='1` and stores a user called `'; DROP TABLE events; --`, and checks that nothing leaks and the table survives."

**Q6. What is a false positive in your project, and how did you reduce them?**
> "For example, a legitimate user mistyping a password and then logging in. That's 'failure then success', but my sequence rule needs at least five failures. Another one is the sudo rule: admins use sudo all the time, so there's an allow-list of expected admins. For the web rules, I match on specific patterns like `UNION SELECT` rather than just the word 'union', and I have negative tests with benign URLs like `/blog/union-station-review` and `O'Reilly`. I also group repeated hits from the same IP into one alert to avoid alert fatigue."

**Q7. Why did you normalise to UTC, and what problems do timestamps cause?**
> "Correlation is about time windows, so all sources must share one clock. My web logs are in +08:00 and auth.log in UTC, and without conversion the events would be 8 hours apart. Classic syslog has no year and no timezone, so I take the year as a parameter and assume UTC. That's a documented limitation: New Year rollovers or servers on local time would be wrong. In production I'd configure servers to log in UTC or RFC 3339 format with an offset, and keep NTP in sync."

**Q8. How does this compare with Splunk or QRadar?**
> "Same pipeline at a tiny scale. My parsers are like Splunk field extractions or QRadar DSMs. My event schema is like Splunk's CIM or Elastic's ECS. SQLite stands in for Splunk indexes or QRadar's Ariel DB. My YAML rules are like correlation searches or QRadar rules, and close in spirit to Sigma. Alerts with a status are like notable events or offenses. The real products add scale, hundreds of parsers, threat intel feeds, UEBA baselines, SOAR automation and access control."

**Q9. What happens if you ingest the same file twice, or run detection twice?**
> "Nothing is duplicated. Each line's fingerprint is a hash of the source, file name, byte offset and content, with a UNIQUE constraint, so re-ingesting inserts zero events. Each alert has a deterministic dedup key (rule, group, first-seen time), so re-running detection updates the same alerts. It also keeps the analyst's status, so a closed alert isn't reopened."

**Q10. What are the limitations, and what would you build next?**
> "The dashboard has no authentication, so it's localhost-only. Follow mode keeps detector state in memory and doesn't see events from before it started. Regex rules for web attacks are easy to evade and can't see POST bodies. SQLite won't scale to SOC volumes. Next I'd add a Windows Security event parser for 4624/4625 logons, import a subset of Sigma rules, persist detector state, and add login plus a production WSGI server for the dashboard."

**Bonus questions to prepare:** "What is MITRE ATT&CK and why map to it?", "SIEM vs EDR?" (section 3), "How would you detect lateral movement?" (Windows 4624 logon type 3/10 from unusual sources, new admin share access), "What log sources would you onboard first?" (authentication: AD/VPN/SSH, then EDR, firewall/proxy, cloud audit logs).

---

## 5. How to demo in 2 minutes

Prepare beforehand: venv activated, terminal font large, browser open, `mini-siem demo` tested once.

1. **(15 s) The problem:** "A server writes different logs in different formats. I want one place that understands them all and tells me when something bad happens."
2. **(20 s) Run** `mini-siem demo`. Point at the output: "Three log formats, 115 events, 7 noise lines skipped, 9 rules produced 11 alerts." Point at one critical line: "This IP failed 6 times then **logged in**. That's a compromised account."
3. **(25 s) Overview page:** the counts, the chart ("you can see the attack spike at 03:00 UTC"), and the top source IPs ordered by failures.
4. **(30 s) Alerts → open #5** (brute force then success): severity, MITRE T1110/T1078, and the **evidence** table with the 6 failures, the success and each raw log line. Change status to *acknowledged*: "That's the analyst workflow."
5. **(15 s) Open the XSS alert:** "This is an attacker's `<script>` payload, displayed as harmless text. The dashboard escapes everything and has a CSP that blocks all scripts."
6. **(15 s) Show a rule file** (`rules/password_spraying.yml`): "Rules are YAML, readable and tunable, mapped to ATT&CK. I count *distinct users* because spraying is designed to dodge simple thresholds."
7. **(Optional) Close:** "There are 115 tests, including negative tests to keep false positives down."

If something goes wrong live, have the screenshots in `docs/images/` ready.

---

## 6. Practise these before the interview

- [ ] Change `threshold: 5` to `10` in `ssh_bruteforce.yml`, run `mini-siem demo --no-serve`, and explain why **both** brute-force alerts disappear (those IPs made 8 and 6 attempts) while the critical "brute force then success" alert still fires (it has its own `min_count`). Is a missed alert here a false negative? Change it back afterwards.
- [ ] Add a new rule, for example "any HTTP 500 from one IP more than 3 times in 60 s", without touching Python.
- [ ] Add your own name to the sudo allow-list and explain why allow-lists need maintenance.
- [ ] Run `mini-siem follow test.log --type auth --from-start` and append lines in another terminal (`Add-Content` in PowerShell, `echo >>` in Linux) to watch live alerts.
- [ ] Break the escaping on purpose: in `src/mini_siem/web/templates/_macros.html`, change `{{ e.details.get('url_decoded', '') }}` to `{{ e.details.get('url_decoded', '')|safe }}`. Run `pytest tests/test_web.py` and watch `test_attacker_controlled_strings_are_escaped` fail, then **revert it**. (Adding `|safe` to `e.raw` would *not* trip the test, because the raw access-log line is still URL-encoded (`%3Cscript`). Explaining why is a good exercise.)
- [ ] Draw the architecture diagram from memory on paper.
- [ ] Be able to name the ATT&CK technique for each rule without looking.
