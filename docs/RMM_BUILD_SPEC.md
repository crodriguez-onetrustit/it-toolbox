# OneTrust RMM - Build Specification

## Vision
A full-stack Remote Monitoring & Management (RMM) platform similar to TacticalRMM, integrated with MeshCentral for remote access.

## Architecture

### Tech Stack
| Component | Technology |
|-----------|-----------|
| Backend API | Django (Python) + FastAPI |
| Frontend | Vue.js 3 + TypeScript |
| Database | PostgreSQL |
| Cache | Redis |
| Agent | Go (cross-platform) |
| Remote Access | MeshCentral |
| Real-time | WebSockets |

### System Components

```
┌─────────────────────────────────────────────────────────┐
│                    Frontend (Vue.js)                  │
│  Dashboard | Agents | Scripts | Alerts | Reports     │
└─────────────────────┬───────────────────────────────┘
                      │ REST API + WebSocket
┌─────────────────────▼───────────────────────────────┐
│                 Backend (Django)                     │
│  Auth | Agents | Tasks | Alerts | Scripts | API   │
└──────┬──────────────┬──────────────┬───────────────┘
       │              │              │
   ┌───▼───┐    ┌───▼───┐    ┌──▼────┐
   │PostgreSQL│    │ Redis │    │ Mesh │
   │   DB    │    │ Cache │    │Central│
   └────────┘    └───────┘    └──────┘
```

## Core Features

### 1. Agent Management
- [ ] Deploy agents to Windows, Mac, Linux
- [ ] Agent heartbeat/check-in system
- [ ] Online/offline status tracking
- [ ] Agent version management
- [ ] Grouping/tagging agents

### 2. Remote Access (MeshCentral)
- [ ] Web-based remote desktop
- [ ] Remote shell/terminal
- [ ] File transfer
- [ ] Session recording

### 3. Monitoring
- [ ] CPU, memory, disk monitoring
- [ ] Service monitoring
- [ ] Event log monitoring
- [ ] Custom script checks
- [ ] Threshold-based alerts

### 4. Remote Actions
- [ ] Run scripts (PowerShell, Bash, Python)
- [ ] Service management
- [ ] Process management
- [ ] Registry editing (Windows)
- [ ] Software installation

### 5. Patch Management
- [ ] Windows Update management
- [ ] Third-party patching
- [ ] Patch status reporting

### 6. Automation
- [ ] Scheduled scripts
- [ ] Automated remediation
- [ ] Task automation

### 7. Reporting
- [ ] Agent inventory
- [ ] Patch compliance
- [ ] Activity logs
- [ ] Custom reports

## Build Phases

### Phase 1: Foundation (Week 1-2)
- [ ] Django backend setup
- [ ] PostgreSQL schema
- [ ] Vue.js frontend scaffold
- [ ] User auth (JWT)
- [ ] Agent API endpoints

### Phase 2: Agent Core (Week 3-4)
- [ ] Go agent development
- [ ] Heartbeat system
- [ ] Basic system info collection
- [ ] Status dashboard

### Phase 3: Remote Access (Week 5-6)
- [ ] MeshCentral integration
- [ ] Web terminal
- [ ] File browser
- [ ] Remote desktop

### Phase 4: Management (Week 7-8)
- [ ] Script runner
- [ ] Service management
- [ ] Process management
- [ ] Alerts system

### Phase 5: Automation (Week 9-10)
- [ ] Scheduled tasks
- [ ] Patch management
- [ ] Software deployment

### Phase 6: Enterprise (Week 11-12)
- [ ] Reporting module
- [ ] Multi-tenancy
- [ ] SSO integration
- [ ] Mobile app

## Database Schema

### Core Tables
- users
- clients (organizations)
- sites
- agents
- checks (monitoring)
- alerts
- scripts
- tasks
- software
- patches

## API Endpoints

### Auth
- POST /api/auth/login
- POST /api/auth/logout
- POST /api/auth/refresh

### Agents
- GET /api/agents
- GET /api/agents/{id}
- POST /api/agents/{id}/heartbeat
- POST /api/agents/{id}/command

### Scripts
- GET /api/scripts
- POST /api/scripts
- POST /api/scripts/{id}/run

### Alerts
- GET /api/alerts
- POST /api/alerts/acknowledge

## Agent Protocol

### Check-in
```json
{
  "agent_id": "uuid",
  "hostname": "string",
  "os": "string",
  "version": "string",
  "cpu": 0-100,
  "memory": 0-100,
  "disk": 0-100
}
```

### Command Response
```json
{
  "command_id": "uuid",
  "output": "string",
  "exit_code": 0,
  "stdout": "string",
  "stderr": "string"
}
```

## MeshCentral Integration

1. Deploy MeshCentral server
2. Configure agent mesh agent
3. Use mesh TLS certificates
4. Integrate via MeshCentral API

## Implementation Notes

### Performance
- Use Redis for real-time agent communication
- Batch agent heartbeats
- Use WebSocket for live terminal

### Security
- TLS for all agent communication
- Agent API keys
- Audit logging
- RBAC for users

### Scalability
- Microservices architecture
- Message queue for tasks
- Horizontal agent scaling
