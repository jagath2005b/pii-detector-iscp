# 🚀 Real-time PII Detector and Redactor

## 📌 Overview
This project implements a **high-performance, real-time Personally Identifiable Information (PII) detector and redactor** designed to scan streaming JSON data embedded in CSV records.  
It identifies and masks sensitive fields such as **phone numbers, Aadhaar IDs, passports, UPI IDs, email addresses, names, and IP addresses**, ensuring **data privacy and compliance**.

---

## 🔎 Approach

### 🔹 Detection Methods
- Uses **regular expression patterns** for standalone PII identification with high accuracy.  
- Employs **combinatorial detection logic** that requires correlated fields (e.g., *name + email*, *address + IP*) to reduce false positives and enhance context-aware detection.  

### 🔹 Masking & Redaction
- Implements **flexible masking strategies** including **partial redaction** (e.g., showing only a few characters) and **full masking** with placeholders.  
- Supports **dynamic configuration** of mask formats to suit compliance and business requirements.  

### 🔹 Integration & Deployment
- Designed as an **embeddable plugin** deployable in **API gateways** (Envoy, Kong, NGINX) as a WASM/Lua filter.  
- Enables inline redaction at **ingress/egress points** without changing existing microservices code.  
- **Sidecar deployment** option to redact verbose logs before sending to central log aggregation.  
- Optional **client-side browser extension** for masking PII within internal UI tools.  

### 🔹 Performance and Reliability
- Utilizes **streaming JSON parsing** and **incremental state maintenance** to ensure **low latency** and **real-time processing capability**.  
- Implements **fail-safe fall-through handling** to avoid request disruption during errors.  

### 🔹 Observability and Compliance
- Provides **telemetry metrics** (detection counts, latency, false positive samples).  
- Maintains **secure, masked audit logs** for tuning, compliance audits, and investigations.  
- Allows **centralized management** of field allow/deny lists and configuration flags.  

---

## ⚡ Usage
- Run the included **detector script** on JSON-in-CSV datasets to **identify and redact PII**.  
- Produces a **redacted output file** with flagged records.  
- Follow deployment guides to configure and enable plugins in **API gateways** or **sidecars**.  
- Use the **browser extension** for client-side masking when applicable.  

---

## 🤝 Contributions
Contributions, issues, and feature requests are welcome via **GitHub Issues** and **Pull Requests**.  
This project aims to **evolve collaboratively**, addressing **emerging PII detection needs** and **integration environments**.

---

## 🏁 Flag (for ISCP Challenge)
Once uploaded to GitHub, the **flag format** will be:  
