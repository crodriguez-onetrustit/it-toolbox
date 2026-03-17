# IT Toolbox

All-in-one network diagnostics and developer toolkit.

## Features

- **Developer Tools**: JSON Formatter, Base64, UUID, URL Encoder, Timestamp
- **Network Tools**: IP Lookup, DNS Lookup, Port Scanner, Traceroute
- **Security Tools**: Hash Generator, SSL Checker, WHOIS
- **Utilities**: Color Converter, cURL Builder

## Running Locally

### Frontend Only
```bash
cd frontend
python3 -m http.server 8895
```
Then open http://localhost:8895

### Full Stack
```bash
# Backend
cd backend
pip install -r requirements.txt
python main.py

# Frontend (separate terminal)
cd frontend
python3 -m http.server 8895
```

## Deployment

Can be deployed to Vercel (frontend) or Render/Railway (full stack).
