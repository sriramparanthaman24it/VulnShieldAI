from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import requests
import uuid
import socket
import ssl
import concurrent.futures
from groq import Groq
import os

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
groq_client = Groq(api_key=GROQ_API_KEY)

app = FastAPI(title="VulnShield AI", version="4.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

scan_results = {}

class ScanRequest(BaseModel):
    url: str

def groq_guided_crawl(base_url, links):
    try:
        links_text = "\n".join(links[:20])
        response = groq_client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[{"role":"user","content":f"Pick TOP 5 URLs most likely to have vulnerabilities like SQLi, XSS from:\n{links_text}\nReply ONLY with URLs one per line."}],
            max_tokens=500
        )
        text = response.choices[0].message.content
        return [l.strip() for l in text.strip().split("\n") if l.strip().startswith("http")][:5]
    except:
        return links[:5]

def smart_crawl(base_url, max_pages=5):
    from bs4 import BeautifulSoup
    from urllib.parse import urlparse, urljoin
    visited, found = set(), []
    parsed_base = urlparse(base_url)
    try:
        resp = requests.get(base_url, timeout=10, verify=False)
        soup = BeautifulSoup(resp.text, "html.parser")
        all_links = []
        for a in soup.find_all("a", href=True):
            href = urljoin(base_url, a["href"])
            if parsed_base.netloc in href and href not in visited:
                all_links.append(href)
        selected = groq_guided_crawl(base_url, all_links)
        visited.add(base_url)
        for link in selected:
            if link not in visited:
                found.append(link)
                visited.add(link)
    except:
        pass
    return found

def check_sqli(url):
    findings = []
    payloads = ["'", "' OR '1'='1", "'; DROP TABLE users;--"]
    error_signatures = ["sql syntax","mysql_fetch","ora-","syntax error","pg_query","sqlstate"]
    test_base = url + ("&id=" if "?" in url else "?id=")
    for payload in payloads:
        try:
            resp = requests.get(test_base + payload, timeout=10, verify=False)
            body = resp.text.lower()
            for sig in error_signatures:
                if sig in body:
                    findings.append({"type":"SQL Injection","severity":"Critical","url":test_base+payload,"parameter":"id","description":f"SQL error '{sig}' found"})
                    break
        except: pass
    return findings

def check_xss(url):
    findings = []
    payloads = ["<script>alert('XSS')</script>","<img src=x onerror=alert(1)>"]
    test_base = url + ("&search=" if "?" in url else "?search=")
    for payload in payloads:
        try:
            resp = requests.get(test_base + payload, timeout=10, verify=False)
            if payload in resp.text:
                findings.append({"type":"Cross-Site Scripting (XSS)","severity":"High","url":test_base+payload,"parameter":"search","description":f"Payload reflected: {payload[:40]}"})
        except: pass
    return findings

def check_headers(url):
    findings = []
    try:
        resp = requests.get(url, timeout=10, verify=False)
        headers = resp.headers
        security_headers = {
            "X-Frame-Options":"Clickjacking protection missing",
            "X-Content-Type-Options":"MIME sniffing protection missing",
            "Content-Security-Policy":"CSP header missing",
            "Strict-Transport-Security":"HSTS missing",
        }
        for header, desc in security_headers.items():
            if header not in headers:
                findings.append({"type":"Missing Security Header","severity":"Medium","url":url,"parameter":header,"description":desc})
        if "Server" in headers:
            findings.append({"type":"Information Disclosure","severity":"Low","url":url,"parameter":"Server header","description":f"Server exposed: {headers['Server']}"})
    except: pass
    return findings

def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((host, port))
        sock.close()
        return port if result == 0 else None
    except:
        return None

def check_ports(url):
    findings = []
    try:
        from urllib.parse import urlparse
        host = urlparse(url).hostname
        common_ports = [21,22,23,25,53,80,443,3306,5432,6379,8080,8443,27017]
        risky_ports = {21:"FTP open",23:"Telnet open",3306:"MySQL exposed",5432:"PostgreSQL exposed",6379:"Redis exposed",27017:"MongoDB exposed"}
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            results = executor.map(lambda p: scan_port(host, p), common_ports)
        for port in results:
            if port:
                severity = "High" if port in risky_ports else "Low"
                findings.append({"type":"Open Port","severity":severity,"url":url,"parameter":f"Port {port}","description":risky_ports.get(port, f"Port {port} is open")})
    except: pass
    return findings

def check_ssl(url):
    findings = []
    try:
        from urllib.parse import urlparse
        import datetime
        host = urlparse(url).hostname
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(10)
            s.connect((host, 443))
            cert = s.getpeercert()
        expire_str = cert.get("notAfter", "")
        if expire_str:
            expire_date = datetime.datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (expire_date - datetime.datetime.utcnow()).days
            findings.append({"type":"SSL Certificate","severity":"High" if days_left < 30 else "Low","url":url,"parameter":"SSL","description":f"Expires in {days_left} days"})
    except:
        if url.startswith("http://"):
            findings.append({"type":"No HTTPS","severity":"High","url":url,"parameter":"SSL/TLS","description":"Site does not use HTTPS"})
    return findings

def check_subdomains(url):
    findings = []
    try:
        from urllib.parse import urlparse
        host = urlparse(url).hostname
        base_domain = host.replace("www.", "")
        wordlist = ["www","mail","ftp","admin","api","dev","staging","test","portal","vpn","blog","shop","app"]
        def check_sub(sub):
            try:
                ip = socket.gethostbyname(f"{sub}.{base_domain}")
                return (f"{sub}.{base_domain}", ip)
            except: return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            results = list(executor.map(check_sub, wordlist))
        for result in results:
            if result:
                subdomain, ip = result
                findings.append({"type":"Subdomain Found","severity":"Low","url":f"http://{subdomain}","parameter":subdomain,"description":f"Active: {subdomain} → {ip}"})
    except: pass
    return findings

def groq_analyze(url, findings):
    try:
        summary_text = "\n".join([f"- [{f['severity']}] {f['type']}: {f['description']}" for f in findings[:15]])
        response = groq_client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[{"role":"user","content":f"You are a cybersecurity expert. Analyze findings for {url}:\n{summary_text}\nGive: 1) Executive summary 2) Top 3 risks 3) Fix recommendations"}],
            max_tokens=1000
        )
        return {"summary": response.choices[0].message.content, "model": "llama-3.1-8b-instant (Groq)", "findings_analyzed": len(findings)}
    except Exception as e:
        return {"summary": f"AI unavailable: {str(e)}", "model": "Groq", "findings_analyzed": 0}

def enrich_with_cve(findings):
    CVE_MAP = {
        "SQL Injection": {"id":"CVE-2021-44228","cvss":9.8},
        "Cross-Site Scripting (XSS)": {"id":"CVE-2020-11022","cvss":6.1},
        "Missing Security Header": {"id":"CVE-2019-11043","cvss":5.3},
        "No HTTPS": {"id":"CVE-2021-27853","cvss":7.5},
    }
    for f in findings:
        if f["type"] in CVE_MAP:
            f["cve"] = CVE_MAP[f["type"]]["id"]
            f["cvss"] = CVE_MAP[f["type"]]["cvss"]
            f["cve_link"] = f"https://nvd.nist.gov/vuln/detail/{CVE_MAP[f['type']]['id']}"
    return findings

def run_scan(scan_id, url):
    scan_results[scan_id]["status"] = "running"
    all_findings = []
    try:
        pages = [url] + smart_crawl(url, max_pages=5)
    except:
        pages = [url]
    for page in pages:
        all_findings += check_headers(page)
        all_findings += check_sqli(page)
        all_findings += check_xss(page)
    all_findings += check_ports(url)
    all_findings += check_ssl(url)
    all_findings += check_subdomains(url)
    all_findings = enrich_with_cve(all_findings)
    severity_order = {"Critical":0,"High":1,"Medium":2,"Low":3}
    all_findings.sort(key=lambda x: severity_order.get(x["severity"], 4))
    ai_analysis = groq_analyze(url, all_findings)
    scan_results[scan_id].update({
        "findings": all_findings,
        "status": "complete",
        "total": len(all_findings),
        "ai_analysis": ai_analysis,
        "summary": {
            "Critical": sum(1 for f in all_findings if f["severity"]=="Critical"),
            "High": sum(1 for f in all_findings if f["severity"]=="High"),
            "Medium": sum(1 for f in all_findings if f["severity"]=="Medium"),
            "Low": sum(1 for f in all_findings if f["severity"]=="Low"),
        }
    })

@app.get("/")
def root():
    return {"message": "VulnShield AI v4.0 running ✅"}

@app.post("/scan")
def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    scan_results[scan_id] = {"scan_id":scan_id,"url":req.url,"status":"queued","findings":[],"total":0,"summary":{},"ai_analysis":{}}
    background_tasks.add_task(run_scan, scan_id, req.url)
    return {"scan_id": scan_id, "message": "Scan started"}

@app.get("/results/{scan_id}")
def get_result(scan_id: str):
    if scan_id not in scan_results:
        return {"error": "Scan not found"}
    return scan_results[scan_id]

@app.get("/results")
def get_all_results():
    return list(scan_results.values())