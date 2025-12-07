# 🛡️ Project Sentinel: DevSecOps Orchestration Engine

## ⚠️ **Ethical Use & Legal Disclaimer**

> **⚠️ CAUTION — READ BEFORE USING**

**Project Sentinel** is a powerful **security auditing and DevSecOps orchestration tool**.  
It is intended **solely for educational purposes, research, and authorized professional security testing**.

### 🚫 Unauthorized Use is Strictly Prohibited

Running this tool against any system, application, or network **without explicit, written permission** from the owner is **illegal** and **unethical**.  
Such activity may violate local, national, or international laws, and could result in **criminal prosecution**.

### ⚖️ Responsibility & Liability

The **authors**, **contributors**, and **maintainers** of this project:

- Are **not responsible** for any misuse, damage, data loss, or legal consequences resulting from improper or unauthorized use.
- Provide this software **"as is"**, without any warranty or guarantee of fitness for any purpose.

By using **Project Sentinel**, **you agree to take full responsibility** for your actions and to use this tool **ethically, lawfully, and responsibly**.

---

> 💡 **Reminder:** Always perform security testing within a **legally authorized scope** and with **written consent** from the target system owner.

---

**Project Sentinel** is an enterprise-grade **security orchestration platform** that automates the entire **DevSecOps lifecycle**.  
It transforms security scanning from a manual, fragmented process into a centralized, **API-driven**, and **automated workflow**, creating a **closed-loop system** for vulnerability management.

---

## 🏗️ Architecture Overview

Project Sentinel is built on a **modern, decoupled, and scalable microservices architecture**.

All external traffic is routed through a **hardened NGINX reverse proxy** providing **WAF capabilities** and forwarding legitimate requests to the secure **FastAPI backend**.  
The backend handles authentication and offloads long-running scan jobs to a **Celery task queue**, which are then picked up by one or more scalable **scanner workers**.

### 🔹 Core Components

| Component | Description |
|------------|-------------|
| **NGINX Reverse Proxy (`proxy/`)** | The public-facing gateway and firewall. Handles SSL/TLS termination, rate limiting, and serves the frontend. |
| **Secure Backend API (`app/`)** | The core FastAPI backend. Handles user management, authentication (JWT), and scan orchestration. |
| **Task Queue (Redis)** | Asynchronous message broker that decouples the API from the scanners. |
| **Scanner Workers (`scanner/`)** | The workhorses — Celery containers that execute the **LangGraph scanning orchestrator**. |
| **Frontend (`frontend/`)** | A modern **React + Vite + TypeScript** dashboard for interacting with the API. |
| **CLI (`cli/`)** | A **Python-based command-line tool** for automation and power users. |

---

## ✨ Key Features

- **🔐 Multi-Layered Security:**  
  Secure by default — includes reverse proxy, WAF, rate limiting, and JWT authentication.

- **⚡ Asynchronous Scanning:**  
  A robust Celery task queue ensures the API remains fast and responsive even during long scans.

- **🎯 Profile-Based Scanning:**  
  Run custom scan profiles (`developer`, `web`, `full`) to deliver the right insights at the right stage.

- **🧩 Holistic Analysis:**  
  Combines multiple security tools into one unified workflow:  
  **SAST**, **SCA**, **DAST**, **Resilience**, **Container**, and **IaC Scanning**.

- **🧠 AI-Powered Reporting:**  
  Uses **Gemini** to generate human-readable **PDF reports** with prioritized remediation steps.

- **🕸️ AI Attack Path Modeling:**  
  Uses a local **LLM (Ollama)** to analyze and simulate how vulnerabilities could be chained together.

- **Authenticated Scanning:**
 Supports deep "grey-box" scanning using session cookies.

- **Automated Scheduling:**
 Built-in CRON scheduler for recurring security audits.

- **Architectural Resilience:**
 Checks for CDN usage (Cloudflare/Akamai) and Rate Limiting.

---

## ⚙️ Prerequisites

Make sure the following are installed on your system:

- **Docker & Docker Compose** — for containerized deployment.
- **Ollama** — for local AI modeling.
- **Pulled Ollama Model:**  
  Recommended lightweight model:

  ```bash
  ollama pull gemma:2b
  ```

## 🚀 How to Run This Project

### 1️⃣ Configure Your Environment

Before running the application, you must create a .env file to store your secrets.

Copy the Template

```bash
cp .env.example .env
```

Edit the .env File

Open .env in your text editor and fill in the required values:

```bash
SECRET_KEY=Generate a new key: openssl rand -hex 32
GEMINI_API_KEY=Get it from Google AI Studio

FIRST_ADMIN_EMAIL=Admin email for login
FIRST_ADMIN_PASSWORD=Admin password for login
```

### 2️⃣ Launch the Application

Make sure Docker Desktop is running and your .env file is configured.
Then run the following from the project root:

```bash
docker-compose up --build
```

This will:

- Build the proxy, backend, and worker images.
- Start all four services: proxy, backend, worker, and redis.
- Watch the logs and wait until backend-1 and worker-1 show they are ready.

### 3️⃣ Test with the CLI

Open a new terminal window once the stack is up and running.

Authenticate and Get a Token

```bash
python cli/cli.py -u "your-admin-email@from.env" -p "your-admin-password" get-token
```

💡 The CLI also supports built-in authentication in the scan command itself.

Run Your First Scan

```bash
python cli/cli.py \
  -u "your-admin-email@from.env" \
  -p "your-admin-password" \
  start-scan \
  --profile web \
  --url "https://example.com"
```

### 4️⃣ View the Frontend

While the backend is running, start the frontend development server.

```bash
cd frontend
npm install   # first-time setup
npm run dev
```

Then visit the local development URL (usually **http://localhost:5173**
) to access the dashboard.

## 📘 Summary

| Component        | Tech Stack                      |
| ---------------- | ------------------------------- |
| **Proxy**        | NGINX (Reverse Proxy, WAF, SSL) |
| **Backend**      | FastAPI + Celery + Redis        |
| **Frontend**     | React + Vite + TypeScript       |
| **AI Reporting** | Gemini API                      |
| **AI Modeling**  | Ollama (gemma:2b)               |
| **Deployment**   | Docker Compose                  |

## 🧩 Future Enhancements

- Role-based access control (RBAC)
- Multi-tenant organization support
- Automated Slack/email alerting
- Vulnerability risk scoring dashboard
- Integration with commercial scanning APIs

© 2025 Project Sentinel — Built for secure, intelligent DevSecOps automation.
