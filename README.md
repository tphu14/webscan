🔍 WebVulnScanner
A professional-grade web vulnerability scanner for security research and penetration testing — featuring a real-time web dashboard, 17 scan modules across 3 phases, CVSS scoring, and WAF detection.
⚠️ DISCLAIMER: This tool is intended for educational and authorized security testing only. Only scan systems you own or have explicit written permission to test. Unauthorized use is illegal and unethical.


📖 Project Description
WebVulnScanner is a full-stack web vulnerability scanning platform built with Python. It combines a powerful async scanning engine with a modern real-time web dashboard, allowing security professionals to discover, categorize, and track vulnerabilities across web applications.
The scanner crawls target websites automatically, then runs 17 specialized security modules covering everything from classic SQL injection and XSS to advanced threats like SSTI (Server-Side Template Injection), JWT algorithm confusion, subdomain takeover, and XXE injection. Each finding is enriched with CVSS v3.1 scores, CWE identifiers, confidence ratings, and remediation evidence.
Results are stored persistently in SQLite, viewable via a sleek dark-themed dashboard, and exportable as HTML reports or CSV files.

✨ Features
🕷️ Smart Crawling

Auto-crawls all URLs and forms up to configurable depth and page limits
Respects same-domain scope and normalizes URLs to prevent duplicate scanning

🛡️ 17 Scan Modules across 3 Phases
PhaseModuleDescription1SQL InjectionError-based SQLi via URL params and forms1XSS (Reflected)Cross-site scripting via URL params and forms1Sensitive Files.env, .git, backup files, admin panels, Swagger1Open RedirectUnvalidated redirect parameter detection1Security HeadersMissing CSP, HSTS, X-Frame-Options, etc.2Blind SQLi (Time-Based)SLEEP/WAITFOR/pg_sleep timing analysis2SSRFServer-Side Request Forgery with cloud metadata probing2CSRFMissing/weak CSRF tokens with SameSite analysis2IDORInsecure Direct Object Reference via ID enumeration2JWT Analysisalg:none bypass, weak secret brute-force, missing exp2CORSReflect-any-origin, null origin bypass, wildcard+credentials2GraphQLIntrospection enabled, error disclosure, unauthorized data2API FuzzerHidden endpoint discovery, auth bypass via headers3SSTIJinja2, Twig, FreeMarker, ERB template injection → RCE3LFI / Path TraversalLinux/Windows file read via traversal and PHP wrappers3XXE InjectionXML External Entity injection via POST endpoints3Subdomain TakeoverDNS/CNAME fingerprinting for unclaimed service subdomains
📊 Intelligence & Accuracy

WAF Detection — Fingerprints Cloudflare, ModSecurity, AWS WAF, Akamai, F5, Imperva, Sucuri
Payload Mutation — Auto-generates WAF bypass variants (case variation, comment injection, double-encoding, null bytes)
CVSS v3.1 Scoring — Automatic base score calculation for every finding
Deduplication Engine — Groups duplicate findings by type/URL/payload category, drops low-confidence false positives
Response Diffing — Similarity analysis to reduce false positives in blind detection

🖥️ Web Dashboard

Real-time scan progress via WebSocket streaming
Interactive scan history with filtering, sorting, and comparison
Side-by-side scan comparison (new vs. fixed vs. persisting findings)
CSV export of vulnerability findings
Charts: vulnerability type distribution, severity breakdown

📝 Reporting

Beautiful dark-themed HTML reports (Jinja2-rendered)
JSON export for integration with other tools
CLI output with rich formatting and progress bars


🧰 Tech Stack
LayerTechnologyLanguagePython 3.11+Web FrameworkFastAPIASGI ServerUvicornHTTP Clienthttpx (async, HTTP/2 support)DatabaseSQLite via SQLAlchemy ORMHTML ParsingBeautifulSoup4 + lxmlTemplatingJinja2CLIClickTerminal UIRich (progress bars, panels, tables)ConfigPyYAMLLoggingstructlogFrontendVanilla JS, Chart.js, CSS custom propertiesRealtimeWebSocket (native FastAPI)

1. Clone the repository
bashgit clone https://github.com/yourusername/webscan.git
cd webscan
2. Create a virtual environment
bashpython -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows
3. Install dependencies
bashpip install -r requirements.txt
4. (Optional) Configure settings
Edit config.yaml to adjust crawl depth, rate limits, timeouts, and enabled modules:
yamlscanner:
  max_depth: 3
  max_pages: 50
  timeout: 10
  rate_limit: 8.0

🚀 Usage
Option A — Web Dashboard (Recommended)
Start the dashboard server:
bashpython run.py
Then open your browser:

Dashboard: http://127.0.0.1:8000
New Scan: http://127.0.0.1:8000/scan
History: http://127.0.0.1:8000/history
API Docs: http://127.0.0.1:8000/docs

Custom port:
bashpython run.py --port 9000
python run.py --reload        # Dev mode with auto-reload

Option B — CLI Scanner
Basic scan (all modules):
bashpython main.py scan http://testphp.vulnweb.com
Quick scan (Phase 1 only):
bashpython main.py scan http://testphp.vulnweb.com --quick
Custom options:
bashpython main.py scan http://target.example.com \
  --depth 5 \
  --pages 100 \
  --timeout 15 \
  --output results.html \
  --json
Disable specific modules:
bashpython main.py scan http://target.example.com \
  --no-subdomain \
  --no-graphql \
  --no-time-sqli
Available CLI flags:
FlagDescription--depth / -dCrawl depth (default: 3)--pages / -pMax pages to crawl (default: 50)--timeout / -tRequest timeout in seconds (default: 10)--output / -oHTML report output path--jsonAlso save JSON report--quickPhase 1 modules only--no-sqliSkip SQL injection--no-xssSkip XSS--no-ssrfSkip SSRF--no-csrfSkip CSRF--no-idorSkip IDOR--no-jwtSkip JWT analysis--no-corsSkip CORS--no-graphqlSkip GraphQL--no-sstiSkip SSTI--no-lfiSkip LFI/Path Traversal--no-xxeSkip XXE--no-subdomainSkip subdomain takeover
List all modules:
bashpython main.py modules
Show safe test targets:
bashpython main.py targets

Option C — REST API
The FastAPI backend exposes a full REST API:
bash# Start a new scan
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "http://testphp.vulnweb.com", "scan_sqli": true, "scan_xss": true}'

# Get scan results
curl http://localhost:8000/api/scans/1

# List all scans
curl http://localhost:8000/api/scans

# Compare two scans
curl http://localhost:8000/api/scans/compare/1/2

# Global statistics
curl http://localhost:8000/api/stats

# Delete a scan
curl -X DELETE http://localhost:8000/api/scans/1
Real-time progress via WebSocket:
javascriptconst ws = new WebSocket('ws://localhost:8000/ws/scan/1');
ws.onmessage = (e) => console.log(JSON.parse(e.data));

🖼️ Example Output
CLI Report Summary
═══ SCAN COMPLETE (142s) ═══
Raw findings → After dedup: 31 → 24

Severity      Count
─────────────────────
CRITICAL          0
HIGH              7
MEDIUM           11
LOW               6
────────────────
TOTAL            24
RISK SCORE       79

✓ HTML Report: report.html
Sample Findings
[SQLI FORM]    http://testphp.vulnweb.com/search.php | input=searchFor
[XSS FOUND]    http://testphp.vulnweb.com/search.php | param=searchFor
[FILE EXPOSED] http://testphp.vulnweb.com/admin [200]
[CSRF]         http://testphp.vulnweb.com/userinfo.php | method=POST
[CORS]         http://testphp.vulnweb.com | reflect-any-origin with credentials
Safe Testing Targets
http://testphp.vulnweb.com       Acunetix PHP lab (SQLi, XSS, LFI)
http://dvwa.local                DVWA (docker run -p 80:80 vulnerables/web-dvwa)
http://localhost:3000            OWASP Juice Shop
http://localhost:8080/WebGoat    WebGoat

🔮 Future Improvements

 Authentication support — scan behind login forms with session management
 Headless browser integration — detect DOM-based XSS and JavaScript-rendered content
 Burp Suite integration — import/export .xml scan files
 Nuclei template support — run community-contributed detection templates
 Scheduled scans — cron-based recurring scans with delta alerting
 Multi-target batch scanning — scan lists of targets from a file
 Slack / Discord notifications — alert on critical findings in real-time
 Docker image — one-command containerized deployment
 OWASP ZAP passive proxy mode — intercept and scan traffic passively
 Rate limiting per domain — adaptive throttling based on server response codes
 CI/CD integration — GitHub Actions workflow for automated security gates


👤 Author
WebVulnScanner was built as an educational security research project.

🐙 GitHub: @yourusername
📧 Contact: your.email@example.com


📄 License
This project is intended for educational use only. Use responsibly and ethically. Always obtain proper authorization before scanning any system.
