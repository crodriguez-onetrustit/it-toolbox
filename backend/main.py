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
import sys

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
            # Network
            {"name": "DNS Lookup", "endpoint": "/api/dns", "method": "POST"},
            {"name": "IP Lookup", "endpoint": "/api/ip", "method": "POST"},
            {"name": "My IP", "endpoint": "/api/ip/my", "method": "GET"},
            {"name": "Ping", "endpoint": "/api/ping", "method": "POST"},
            {"name": "Traceroute", "endpoint": "/api/traceroute", "method": "POST"},
            {"name": "Port Scan", "endpoint": "/api/ports", "method": "POST"},
            {"name": "Speed Test", "endpoint": "/api/speedtest/local", "method": "GET"},
            {"name": "Network Interfaces", "endpoint": "/api/network/interfaces", "method": "GET"},
            {"name": "Netstat", "endpoint": "/api/netstat", "method": "GET"},
            
            # Security
            {"name": "SSL Check", "endpoint": "/api/ssl", "method": "POST"},
            {"name": "Hash Generator", "endpoint": "/api/hash", "method": "POST"},
            {"name": "HMAC Generator", "endpoint": "/api/hmac", "method": "POST"},
            {"name": "JWT Decode", "endpoint": "/api/jwt/decode", "method": "POST"},
            {"name": "JWT Encode", "endpoint": "/api/jwt/encode", "method": "POST"},
            {"name": "WHOIS", "endpoint": "/api/whois/", "method": "GET"},
            
            # Developer
            {"name": "JSON Formatter", "endpoint": "/api/json", "method": "POST", "local": True},
            {"name": "Base64 Encoder", "endpoint": "/api/base64", "method": "POST", "local": True},
            {"name": "URL Encoder", "endpoint": "/api/url", "method": "POST", "local": True},
            {"name": "cURL", "endpoint": "/api/curl", "method": "POST"},
            {"name": "HTTP Headers", "endpoint": "/api/headers", "method": "POST"},
            
            # System Monitoring
            {"name": "System Info", "endpoint": "/api/systeminfo", "method": "GET"},
            {"name": "CPU Info", "endpoint": "/api/cpu", "method": "GET"},
            {"name": "Memory Info", "endpoint": "/api/memory", "method": "GET"},
            {"name": "Disk Usage", "endpoint": "/api/disk", "method": "GET"},
            {"name": "Process List", "endpoint": "/api/processes", "method": "GET"},
            
            # Server
            {"name": "Docker", "endpoint": "/api/docker/ps", "method": "GET"},
            {"name": "Services", "endpoint": "/api/services", "method": "POST"},
            {"name": "Cron Jobs", "endpoint": "/api/cron", "method": "GET"},
            
            # Utilities
            {"name": "Password Generator", "endpoint": "/api/password", "method": "GET", "local": True},
            {"name": "UUID Generator", "endpoint": "/api/uuid/generate", "method": "GET"},
            {"name": "QR Code", "endpoint": "/api/qrcode", "method": "POST", "local": True},
            {"name": "Color Picker", "endpoint": "/api/color", "method": "POST", "local": True},
            {"name": "Timestamp", "endpoint": "/api/timestamp", "method": "POST"},
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

# Speed Test
@app.get("/api/speedtest")
async def speed_test():
    """Simple speed test using download"""
    import time
    import urllib.request
    
    try:
        start = time.time()
        # Download a small file to test
        url = "https://speed.cloudflare.com/__down?bytes=10000000"
        req = urllib.request.Request(url, method='GET')
        with urllib.request.urlopen(req, timeout=30) as response:
            data = response.read(10000000)
        duration = time.time() - start
        speed_mbps = (10000000 / 1024 / 1024) / duration
        
        return {
            "download_mbps": round(speed_mbps, 2),
            "duration_seconds": round(duration, 2),
            "bytes_downloaded": len(data)
        }
    except Exception as e:
        return {"error": str(e)}

# IP Range Scanner
@app.post("/api/scan")
async def scan_network(data: dict):
    """Scan IP range for online hosts"""
    import subprocess
    import socket
    
    base_ip = data.get("base_ip", "192.168.1")
    start = int(data.get("start", 1))
    end = int(data.get("end", 254))
    
    online = []
    for i in range(start, min(end + 1, 255)):
        ip = f"{base_ip}.{i}"
        try:
            socket.setdefaulttimeout(0.3)
            result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                capture_output=True, timeout=1)
            if result.returncode == 0:
                online.append(ip)
        except:
            pass
    
    return {"online": online, "scanned": end - start + 1}

# Docker Manager
@app.get("/api/docker/ps")
async def docker_ps():
    """List running containers"""
    import subprocess
    try:
        result = subprocess.run(['docker', 'ps', '--format', '{{.ID}}|{{.Names}}|{{.Status}}|{{.Image}}'], 
            capture_output=True, text=True)
        containers = []
        for line in result.stdout.strip().split('\n'):
            if '|' in line:
                parts = line.split('|')
                containers.append({'id': parts[0], 'name': parts[1], 'status': parts[2], 'image': parts[3]})
        return {"containers": containers}
    except Exception as e:
        return {"containers": [], "error": str(e)}

@app.post("/api/docker/{action}")
async def docker_action(action: str, data: dict = {}):
    """Container actions: start, stop, restart, remove"""
    import subprocess
    container = data.get("container", "")
    valid_actions = ["start", "stop", "restart", "rm", "logs"]
    
    if action not in valid_actions:
        return {"error": f"Invalid action. Use: {valid_actions}"}
    
    try:
        if action == "logs":
            result = subprocess.run(['docker', 'logs', '--tail', '50', container], capture_output=True, text=True)
        else:
            result = subprocess.run(['docker', action, container], capture_output=True, text=True)
        return {"success": True, "output": result.stdout + result.stderr}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.get("/api/docker/images")
async def docker_images():
    """List docker images"""
    import subprocess
    try:
        result = subprocess.run(['docker', 'images', '--format', '{{.Repository}}:{{.Tag}}|{{.Size}}'], 
            capture_output=True, text=True)
        images = []
        for line in result.stdout.strip().split('\n'):
            if '|' in line:
                parts = line.split('|')
                images.append({'name': parts[0], 'size': parts[1]})
        return {"images": images}
    except Exception as e:
        return {"images": [], "error": str(e)}

# WiFi Scanner
@app.get("/api/wifi")
async def wifi_networks():
    """List available WiFi networks (macOS)"""
    import subprocess
    try:
        if sys.platform == "darwin":
            result = subprocess.run(['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-s'], 
                capture_output=True, text=True)
            networks = []
            lines = result.stdout.strip().split('\n')[1:]  # Skip header
            for line in lines:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 7:
                        networks.append({
                            'ssid': parts[0],
                            'signal': parts[1] if len(parts) > 1 else 'N/A',
                            'security': parts[-1]
                        })
            return {"networks": networks}
        else:
            return {"networks": [], "error": "WiFi scan only available on macOS"}
    except Exception as e:
        return {"networks": [], "error": str(e)}

# System Info
@app.get("/api/systeminfo")
async def system_info():
    """Get detailed system info"""
    import platform
    import psutil
    return {
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "cpu_count": psutil.cpu_count(),
        "cpu_percent": psutil.cpu_percent(interval=1),
        "memory_total": psutil.virtual_memory().total,
        "memory_available": psutil.virtual_memory().available,
        "memory_percent": psutil.virtual_memory().percent,
        "disk_total": psutil.disk_usage('/').total,
        "disk_used": psutil.disk_usage('/').used,
        "disk_percent": psutil.disk_usage('/').percent,
    }

# Visual Traceroute
@app.post("/api/traceroute-visual")
async def traceroute_visual(data: dict):
    """Visual traceroute with hops"""
    import subprocess
    
    host = data.get("host", "google.com")
    try:
        result = subprocess.run(['traceroute', '-m', '15', host] if sys.platform != 'win32' 
            else ['tracert', host], capture_output=True, text=True, timeout=30)
        
        hops = []
        for line in result.stdout.split('\n'):
            if line.strip():
                hops.append(line.strip())
        
        return {"success": True, "host": host, "hops": hops}
    except Exception as e:
        return {"success": False, "error": str(e)}

# AWS Info
@app.get("/api/aws/status")
async def aws_status():
    """Check AWS service status"""
    import urllib.request
    try:
        url = "https://status.aws.amazon.com/data.json"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read())
        return {"success": True, "status": data}
    except Exception as e:
        return {"success": False, "error": str(e)}

# Certificate Info
@app.post("/api/certinfo")
async def cert_info(data: dict):
    """Get SSL certificate info for a domain"""
    import ssl
    import socket
    import datetime
    
    host = data.get("host", "")
    port = int(data.get("port", 443))
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        
        return {
            "success": True,
            "subject": dict(x[0] for x in cert['subject']),
            "issuer": dict(x[0] for x in cert['issuer']),
            "version": cert['version'],
            "notBefore": cert['notBefore'],
            "notAfter": cert['notAfter'],
            "serialNumber": cert['serialNumber']
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

# WiFi Scanner - Cross Platform
@app.get("/api/wifi/scan")
async def wifi_scan():
    """Scan for WiFi networks - cross platform"""
    import subprocess
    import sys
    import re
    
    networks = []
    
    try:
        if sys.platform == "darwin":
            result = subprocess.run(['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-s'], 
                capture_output=True, text=True, timeout=10)
            lines = result.stdout.strip().split('\n')[1:]
            for line in lines:
                parts = line.split()
                if len(parts) >= 2:
                    networks.append({'ssid': parts[0], 'signal': parts[1], 'security': parts[-1] if len(parts) > 2 else 'Open'})
        
        elif sys.platform == "win32":
            result = subprocess.run(['netsh', 'wlan', 'show', 'networks', 'mode=bssid'], 
                capture_output=True, text=True, timeout=15)
            current_ssid = None
            for line in result.stdout.split('\n'):
                line = line.strip()
                if 'SSID' in line and ':' in line:
                    current_ssid = line.split(':', 1)[1].strip()
                elif 'Signal' in line and ':' in line and current_ssid:
                    signal = line.split(':', 1)[1].strip().replace('%', '')
                    networks.append({'ssid': current_ssid, 'signal': signal + '%'})
                    current_ssid = None
        
        elif sys.platform == "linux":
            result = subprocess.run(['nmcli', '-t', '-f', 'SSID,SIGNAL,SECURITY', 'device', 'wifi'], 
                capture_output=True, text=True, timeout=10)
            for line in result.stdout.strip().split('\n'):
                parts = line.split(':')
                if len(parts) >= 2:
                    networks.append({'ssid': parts[0], 'signal': parts[1], 'security': parts[2] if len(parts) > 2 else 'Open'})
        
        return {"networks": networks, "platform": sys.platform}
    except Exception as e:
        return {"networks": [], "platform": sys.platform, "error": str(e)}

# Local Speed Test
@app.get("/api/speedtest/local")
async def local_speed_test():
    """Local network speed test"""
    import socket
    import time
    
    result = {"latency_ms": 0, "method": "socket"}
    
    # Measure latency to local network
    gateways = ['192.168.1.1', '10.0.0.1', '10.0.1.1', '172.16.0.1']
    
    for gateway in gateways:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            start = time.time()
            s.connect((gateway, 80))
            result['latency_ms'] = round((time.time() - start) * 1000, 2)
            result['gateway'] = gateway
            s.close()
            break
        except:
            continue
    
    return result

@app.get("/api/wifi/list")
async def wifi_list():
    """List WiFi - alternative method"""
    import subprocess
    import sys
    
    try:
        if sys.platform == "darwin":
            # Try networksetup first
            result = subprocess.run(['networksetup', '-listallhardwareports'], 
                capture_output=True, text=True, timeout=10)
            
            # Check current WiFi status
            result2 = subprocess.run(['networksetup', '-getairportnetwork', 'en0'], 
                capture_output=True, text=True, timeout=5)
            
            current = result2.stdout.strip() if result2.returncode == 0 else "Not connected"
            
            return {
                "current_network": current.replace("Current Wi-Fi Network: ", ""),
                "platform": "darwin",
                "method": "networksetup",
                "note": "WiFi scanning requires elevated permissions on macOS"
            }
    except Exception as e:
        return {"error": str(e), "platform": sys.platform}

# JWT Decoder
@app.post("/api/jwt/decode")
async def jwt_decode(data: dict):
    """Decode JWT token"""
    import base64
    import json
    
    token = data.get("token", "")
    
    if not token:
        return {"error": "Token required"}
    
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return {"error": "Invalid JWT format"}
        
        # Decode payload (second part)
        payload = parts[1]
        # Add padding if needed
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding
        
        decoded = base64.urlsafe_b64decode(payload)
        payload_data = json.loads(decoded)
        
        return {
            "valid": True,
            "payload": payload_data,
            "header": json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
        }
    except Exception as e:
        return {"valid": False, "error": str(e)}

@app.post("/api/jwt/encode")
async def jwt_encode(data: dict):
    """Encode JWT token"""
    import base64
    import json
    import time
    
    payload = data.get("payload", {})
    secret = data.get("secret", "secret")
    algorithm = data.get("algorithm", "HS256")
    
    try:
        # Create header
        header = {"alg": algorithm, "typ": "JWT"}
        
        # Add timestamp if not present
        if "iat" not in payload:
            payload["iat"] = int(time.time())
        
        import hmac
        import hashlib
        
        def b64encode(data):
            return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip('=')
        
        header_b64 = b64encode(header)
        payload_b64 = b64encode(payload)
        
        # Sign
        signature = hmac.new(secret.encode(), f"{header_b64}.{payload_b64}".encode(), hashlib.sha256).digest()
        signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
        
        return {"token": f"{header_b64}.{payload_b64}.{signature_b64}"}
    except Exception as e:
        return {"error": str(e)}

# Network Interfaces
@app.get("/api/network/interfaces")
async def network_interfaces():
    """Get network interfaces"""
    import psutil
    interfaces = {}
    for iface, addrs in psutil.net_if_addrs().items():
        interfaces[iface] = []
        for addr in addrs:
            interfaces[iface].append({
                'family': str(addr.family),
                'address': addr.address,
                'netmask': addr.netmask,
                'broadcast': addr.broadcast
            })
    return {"interfaces": interfaces}

# Process List
@app.get("/api/processes")
async def list_processes():
    """List running processes"""
    import psutil
    processes = []
    for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
        try:
            processes.append({
                'pid': p.info['pid'],
                'name': p.info['name'],
                'cpu': p.info['cpu_percent'] or 0,
                'memory': p.info['memory_percent'] or 0
            })
        except:
            pass
    return {"processes": sorted(processes, key=lambda x: x['cpu'], reverse=True)[:20]}

# Kill Process
@app.post("/api/process/kill")
async def kill_process(data: dict):
    """Kill a process by PID"""
    import psutil
    pid = data.get("pid")
    try:
        p = psutil.Process(pid)
        p.terminate()
        return {"success": True, "message": f"Process {pid} terminated"}
    except Exception as e:
        return {"success": False, "error": str(e)}

# Disk Usage
@app.get("/api/disk")
async def disk_usage():
    """Get disk usage"""
    import psutil
    partitions = []
    for part in psutil.disk_partitions():
        try:
            usage = psutil.disk_usage(part.mountpoint)
            partitions.append({
                'device': part.device,
                'mountpoint': part.mountpoint,
                'fstype': part.fstype,
                'total': usage.total,
                'used': usage.used,
                'free': usage.free,
                'percent': usage.percent
            })
        except:
            pass
    return {"disks": partitions}

# Memory Info
@app.get("/api/memory")
async def memory_info():
    """Get detailed memory info"""
    import psutil
    vm = psutil.virtual_memory()
    swap = psutil.swap_memory()
    return {
        "virtual": {
            "total": vm.total,
            "available": vm.available,
            "used": vm.used,
            "free": vm.free,
            "percent": vm.percent
        },
        "swap": {
            "total": swap.total,
            "used": swap.used,
            "free": swap.free,
            "percent": swap.percent
        }
    }

# CPU Info
@app.get("/api/cpu")
async def cpu_info():
    """Get CPU information"""
    import psutil
    return {
        "physical_cores": psutil.cpu_count(logical=False),
        "logical_cores": psutil.cpu_count(logical=True),
        "current_freq": psutil.cpu_freq().current if psutil.cpu_freq() else None,
        "usage_per_cpu": psutil.cpu_percent(interval=0.5, percpu=True),
        "total_usage": psutil.cpu_percent(interval=0.5)
    }

# Network Connections
@app.get("/api/netstat")
async def netstat():
    """Get network connections"""
    import psutil
    connections = []
    for conn in psutil.net_connections():
        if conn.laddr:
            connections.append({
                "proto": str(conn.type),
                "local": f"{conn.laddr.ip}:{conn.laddr.port}",
                "status": conn.status,
                "pid": conn.pid
            })
    return {"connections": connections[:50]}

# Timestamp Converter
@app.post("/api/timestamp")
async def timestamp_converter(data: dict):
    """Convert timestamps"""
    import time
    import datetime
    
    ts = data.get("timestamp")
    action = data.get("action", "to_iso")  # to_iso, to_unix, now
    
    try:
        if action == "now":
            now = datetime.datetime.now()
            return {
                "unix": int(now.timestamp()),
                "iso": now.isoformat(),
                "human": now.strftime("%Y-%m-%d %H:%M:%S")
            }
        elif action == "to_iso":
            # Assume unix timestamp
            dt = datetime.datetime.fromtimestamp(int(ts))
            return {
                "unix": int(ts),
                "iso": dt.isoformat(),
                "human": dt.strftime("%Y-%m-%d %H:%M:%S")
            }
        elif action == "to_unix":
            # Parse ISO date
            dt = datetime.datetime.fromisoformat(ts)
            return {
                "unix": int(dt.timestamp()),
                "iso": ts,
                "human": dt.strftime("%Y-%m-%d %H:%M:%S")
            }
    except Exception as e:
        return {"error": str(e)}

# HMAC Generator
@app.post("/api/hmac")
async def hmac_generator(data: dict):
    """Generate HMAC"""
    import hmac
    import hashlib
    
    message = data.get("message", "")
    secret = data.get("secret", "")
    algorithm = data.get("algorithm", "sha256")
    
    algorithms = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512
    }
    
    hash_func = algorithms.get(algorithm, hashlib.sha256)
    h = hmac.new(secret.encode(), message.encode(), hash_func)
    
    return {
        "message": message,
        "secret": secret,
        "algorithm": algorithm,
        "hmac": h.hexdigest()
    }

# UUID v4 Generator (client-side friendly)
@app.get("/api/uuid/generate")
async def generate_uuid():
    """Generate UUID v4"""
    import uuid
    return {"uuid": str(uuid.uuid4()), "version": "v4"}

# Environment variables config
import os

# Config
API_CONFIG = {
    "debug": os.getenv("DEBUG", "false").lower() == "true",
    "api_keys": {
        "nba": os.getenv("NBA_API_KEY", ""),
    }
}
