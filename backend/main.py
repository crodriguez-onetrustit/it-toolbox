"""
IT Toolbox Backend - Network diagnostic API
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import socket
import dns.resolver
import requests
import json
import subprocess
import ssl
import whois
from datetime import datetime
import shutil

app = FastAPI(title="IT Toolbox API")

# Check available commands
HAS_PING = shutil.which('ping') is not None
HAS_TRACEROUTE = shutil.which('traceroute') is not None

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================
# Models
# ==========================

class DNSQuery(BaseModel):
    domain: str
    record_types: list = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]

class IPLookup(BaseModel):
    ip: str = None  # If None, returns own IP

class PingRequest(BaseModel):
    host: str
    count: int = 4

class PortScan(BaseModel):
    host: str
    ports: list = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080, 8443]

class SSLCheck(BaseModel):
    domain: str
    port: int = 443

# ==========================
# DNS Tools
# ==========================

@app.post("/api/dns")
async def dns_lookup(query: DNSQuery):
    """DNS lookup for various record types"""
    results = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    
    for record_type in query.record_types:
        try:
            answers = resolver.resolve(query.domain, record_type)
            results[record_type] = [str(rdata) for rdata in answers]
        except dns.resolver.NXDOMAIN:
            results[record_type] = ["NXDOMAIN"]
        except dns.resolver.NoAnswer:
            results[record_type] = ["No records found"]
        except Exception as e:
            results[record_type] = [f"Error: {str(e)}"]
    
    return {
        "domain": query.domain,
        "records": results,
        "timestamp": datetime.now().isoformat()
    }

# ==========================
# IP Tools
# =========================>

@app.post("/api/ip")
async def ip_lookup(query: IPLookup):
    """IP lookup - returns geo info"""
    if not query.ip:
        # Return own public IP
        try:
            ip = requests.get("https://api.ipify.org", timeout=5).text
        except:
            ip = "Unable to determine"
    else:
        ip = query.ip
    
    # GeoIP lookup
    geo_data = {}
    try:
        # Use free IP API
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,isp,org,as", timeout=5)
        if r.status_code == 200:
            geo_data = r.json()
    except Exception as e:
        geo_data = {"error": str(e)}
    
    return {
        "ip": ip,
        "geo": geo_data,
        "timestamp": datetime.now().isoformat()
    }

@app.get("/api/ip/my")
async def get_my_ip():
    """Get current public IP"""
    try:
        ip = requests.get("https://api.ipify.org", timeout=5).text
        return {"ip": ip}
    except:
        return {"error": "Unable to determine IP"}

# ==========================
# Network Tools
# =========================

@app.post("/api/ping")
async def ping_host(request: PingRequest):
    """Ping a host - uses TCP connect as fallback"""
    # First try system ping
    if HAS_PING:
        try:
            result = subprocess.run(
                ["/sbin/ping", "-c", str(request.count), request.host],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                output = result.stdout
                stats = {}
                if "packets transmitted" in output:
                    for line in output.split("\n"):
                        if "packets transmitted" in line:
                            parts = line.split(",")
                            for p in parts:
                                if "received" in p:
                                    stats["received"] = p.strip().split()[0]
                                if "packet loss" in p:
                                    stats["loss"] = p.strip().split()[0]
                        if "rtt min/avg/max" in line or "min/avg/max" in line:
                            avg_line = line.split("=")[1].strip()
                            mvals = avg_line.split("/")
                            stats["min"] = mvals[0]
                            stats["avg"] = mvals[1]
                            stats["max"] = mvals[2]
                
                return {
                    "host": request.host,
                    "success": True,
                    "output": output,
                    "stats": stats,
                    "timestamp": datetime.now().isoformat()
                }
        except:
            pass
    
    # Fallback: TCP connect check
    try:
        start = datetime.now()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        port = 80
        try:
            sock.connect((request.host, port))
            sock.close()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            port = 443
            sock.connect((request.host, port))
        except:
            port = 22
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((request.host, port))
        sock.close()
        duration = (datetime.now() - start).total_seconds() * 1000
        
        return {
            "host": request.host,
            "success": True,
            "output": f"TCP connect to port {port} successful",
            "stats": {"avg": round(duration, 2), "min": round(duration, 2), "max": round(duration, 2), "loss": "0%"},
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {
            "host": request.host,
            "success": False,
            "output": f"Host unreachable: {str(e)}",
            "stats": {},
            "timestamp": datetime.now().isoformat()
        }

@app.post("/api/traceroute")
async def traceroute(request: PingRequest):
    """Traceroute to a host"""
    if not HAS_TRACEROUTE:
        return {
            "host": request.host,
            "success": False,
            "output": "Traceroute not available on this server. Use port scan to check connectivity.",
            "timestamp": datetime.now().isoformat()
        }
    
    try:
        result = subprocess.run(
            ["/sbin/traceroute", "-m", "30", request.host],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        return {
            "host": request.host,
            "success": result.returncode == 0,
            "output": result.stdout,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ==========================
# Port Scanner
# ==========================

@app.post("/api/ports")
async def port_scan(request: PortScan):
    """Scan common ports"""
    results = {}
    host = request.host
    
    # Common port descriptions
    port_info = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
        443: "HTTPS", 993: "IMAPS", 995: "POP3S",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        8080: "HTTP-Alt", 8443: "HTTPS-Alt"
    }
    
    for port in request.ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        try:
            result = sock.connect_ex((host, port))
            if result == 0:
                results[port] = {
                    "open": True,
                    "service": port_info.get(port, "Unknown")
                }
            else:
                results[port] = {"open": False, "service": port_info.get(port, "Unknown")}
        except:
            results[port] = {"open": False, "error": "Timeout"}
        finally:
            sock.close()
    
    return {
        "host": host,
        "ports": results,
        "timestamp": datetime.now().isoformat()
    }

# ==========================
# SSL Checker
# ==========================

@app.post("/api/ssl")
async def ssl_check(request: SSLCheck):
    """Check SSL certificate"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((request.domain, request.port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=request.domain) as ssock:
                cert = ssock.getpeercert()
        
        # Parse certificate
        subject = dict(x[0] for x in cert['subject'])
        issuer = dict(x[0] for x in cert['issuer'])
        
        # Get expiry date
        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        days_left = (not_after - datetime.now()).days
        
        return {
            "domain": request.domain,
            "valid": True,
            "issuer": issuer.get('commonName', 'Unknown'),
            "subject": subject.get('commonName', 'Unknown'),
            "valid_from": cert.get('notBefore', 'Unknown'),
            "valid_until": cert.get('notAfter', 'Unknown'),
            "days_until_expiry": days_left,
            "timestamp": datetime.now().isoformat()
        }
    except ssl.SSLCertVerificationError as e:
        return {
            "domain": request.domain,
            "valid": False,
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {
            "domain": request.domain,
            "valid": False,
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

# ==========================
# WHOIS
# ==========================

@app.get("/api/whois/{domain}")
async def whois_lookup(domain: str):
    """WHOIS lookup"""
    try:
        w = whois.whois(domain)
        return {
            "domain": domain,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers,
            "status": w.status,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {
            "domain": domain,
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

# ==========================
# Developer Tools
# ==========================

@app.post("/api/curl")
async def curl_builder(data: dict):
    """Build and execute a curl request"""
    url = data.get("url", "")
    method = data.get("method", "GET")
    headers = data.get("headers", {})
    body = data.get("body", None)
    
    try:
        start = datetime.now()
        if method == "GET":
            r = requests.get(url, headers=headers, timeout=30)
        elif method == "POST":
            r = requests.post(url, headers=headers, json=body, timeout=30)
        elif method == "PUT":
            r = requests.put(url, headers=headers, json=body, timeout=30)
        elif method == "DELETE":
            r = requests.delete(url, headers=headers, timeout=30)
        else:
            raise HTTPException(status_code=400, detail="Unsupported method")
        
        duration = (datetime.now() - start).total_seconds() * 1000
        
        return {
            "success": True,
            "status_code": r.status_code,
            "headers": dict(r.headers),
            "body": r.text[:10000],  # Limit body size
            "duration_ms": round(duration, 2),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

@app.post("/api/hash")
async def generate_hash(data: dict):
    """Generate hashes"""
    import hashlib
    text = data.get("text", "")
    
    return {
        "md5": hashlib.md5(text.encode()).hexdigest(),
        "sha1": hashlib.sha1(text.encode()).hexdigest(),
        "sha256": hashlib.sha256(text.encode()).hexdigest(),
        "timestamp": datetime.now().isoformat()
    }

# ==========================
# Utilities
# ==========================

@app.post("/api/uptime")
async def check_uptime(data: dict):
    """Check if a website is up"""
    url = data.get("url", "")
    if not url.startswith("http"):
        url = "https://" + url
    
    try:
        start = datetime.now()
        r = requests.get(url, timeout=10, allow_redirects=True)
        duration = (datetime.now() - start).total_seconds() * 1000
        return {
            "url": url,
            "up": r.status_code < 400,
            "status_code": r.status_code,
            "response_time_ms": round(duration, 2),
            "final_url": r.url,
            "timestamp": datetime.now().isoformat()
        }
    except requests.exceptions.Timeout:
        return {"url": url, "up": False, "error": "Timeout", "timestamp": datetime.now().isoformat()}
    except Exception as e:
        return {"url": url, "up": False, "error": str(e), "timestamp": datetime.now().isoformat()}

@app.post("/api/headers")
async def get_headers(data: dict):
    """Get HTTP headers from a URL"""
    url = data.get("url", "")
    if not url.startswith("http"):
        url = "https://" + url
    
    try:
        r = requests.head(url, timeout=10, allow_redirects=True)
        return {
            "url": url,
            "status_code": r.status_code,
            "headers": dict(r.headers),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {"url": url, "error": str(e), "timestamp": datetime.now().isoformat()}

# SSH Terminal
ssh_clients = {}

@app.post("/api/ssh/connect")
async def ssh_connect(data: dict):
    import paramiko
    host = data.get("host", "")
    port = data.get("port", 22)
    username = data.get("username", "")
    password = data.get("password", "")
    
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port=port, username=username, password=password, timeout=10)
        ssh_id = f"{host}:{port}"
        ssh_clients[ssh_id] = client
        return {"success": True, "session_id": ssh_id, "message": f"Connected to {host}"}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post("/api/ssh/exec")
async def ssh_exec(data: dict):
    command = data.get("command", "")
    session_id = data.get("session_id", "")
    if not session_id and ssh_clients:
        session_id = list(ssh_clients.keys())[0]
    try:
        client = ssh_clients.get(session_id)
        if not client:
            return {"error": "Session not found", "output": ""}
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode() + stderr.read().decode()
        return {"session_id": session_id, "output": output}
    except Exception as e:
        return {"error": str(e), "output": ""}

@app.post("/api/ssh/disconnect")
async def ssh_disconnect():
    global ssh_clients
    for client in ssh_clients.values():
        client.close()
    ssh_clients = {}
    return {"success": True}

@app.post("/api/system")
async def run_system_command(data: dict):
    """Run system command locally"""
    import subprocess
    command = data.get("command", "")
    
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        return {
            "success": True,
            "output": result.stdout + result.stderr,
            "returncode": result.returncode
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.get("/api/tools")
async def list_tools():
    """List all available tools"""
    return {
        "tools": [
            {"name": "DNS Lookup", "endpoint": "/api/dns", "method": "POST"},
            {"name": "IP Lookup", "endpoint": "/api/ip", "method": "POST"},
            {"name": "Ping", "endpoint": "/api/ping", "method": "POST"},
            {"name": "Traceroute", "endpoint": "/api/traceroute", "method": "POST"},
            {"name": "Port Scan", "endpoint": "/api/ports", "method": "POST"},
            {"name": "SSL Check", "endpoint": "/api/ssl", "method": "POST"},
            {"name": "WHOIS", "endpoint": "/api/whois/{domain}", "method": "GET"},
            {"name": "HTTP Request", "endpoint": "/api/curl", "method": "POST"},
            {"name": "Hash Generator", "endpoint": "/api/hash", "method": "POST"},
            {"name": "My IP", "endpoint": "/api/ip/my", "method": "GET"},
        ]
    }

@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8890)

# Service Management
@app.post("/api/services")
async def list_services(data: dict = {}):
    """List running services"""
    import subprocess
    try:
        if sys.platform == "win32":
            result = subprocess.run(['sc', 'query', 'state=', 'all'], capture_output=True, text=True)
        else:
            result = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=running'], capture_output=True, text=True)
        return {"success": True, "output": result.stdout}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post("/api/service")
async def service_action(data: dict):
    """Start/stop/restart a service"""
    import subprocess
    service = data.get("service", "")
    action = data.get("action", "status")  # start, stop, restart, status
    
    try:
        if sys.platform == "win32":
            result = subprocess.run(['sc', action, service], capture_output=True, text=True)
        else:
            result = subprocess.run(['sudo', 'systemctl', action, service], capture_output=True, text=True)
        return {"success": True, "output": result.stdout + result.stderr}
    except Exception as e:
        return {"success": False, "error": str(e)}

# Cron Manager
@app.get("/api/cron")
async def list_crons():
    """List user crontab"""
    import subprocess
    try:
        result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
        return {"crons": result.stdout.split('\n') if result.stdout else []}
    except:
        return {"crons": [], "error": "Cannot access crontab"}

@app.post("/api/cron")
async def add_cron(data: dict):
    """Add cron job"""
    import subprocess
    cron = data.get("cron", "")
    try:
        # Get current crontab
        result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
        current = result.stdout if result.returncode == 0 else ""
        
        # Add new cron
        new_cron = current.strip() + '\n' + cron + '\n'
        proc = subprocess.Popen(['crontab', '-'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc.communicate(input=new_cron.encode())
        
        return {"success": True, "message": "Cron job added"}
    except Exception as e:
        return {"success": False, "error": str(e)}

# Log Viewer
@app.get("/api/logs")
async def view_logs(data: dict):
    """View system logs"""
    import subprocess
    try:
        if sys.platform == "win32":
            result = subprocess.run(['powershell', 'Get-EventLog', '-LogName', 'System', '-Newest', '20'], 
                capture_output=True, text=True, shell=True)
        else:
            result = subprocess.run(['journalctl', '-n', '20', '--no-pager'], capture_output=True, text=True)
        return {"success": True, "logs": result.stdout[:5000]}
    except Exception as e:
        return {"success": False, "error": str(e), "logs": ""}

@app.get("/api/logs/auth")
async def view_auth_logs():
    """View auth logs"""
    import subprocess
    try:
        if sys.platform == "win32":
            result = subprocess.run(['powershell', 'Get-EventLog', '-LogName', 'Security', '-Newest', '20'],
                capture_output=True, text=True, shell=True)
        else:
            result = subprocess.run(['journalctl', '-u', 'ssh', '-n', '20', '--no-pager'], capture_output=True, text=True)
        return {"success": True, "logs": result.stdout[:5000]}
    except Exception as e:
        return {"success": False, "error": str(e)}
