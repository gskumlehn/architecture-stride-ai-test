# Threat Modeling API — STRIDE via Vertex AI (Gemini) + FastAPI

A REST API that generates a **STRIDE** threat model from:
1) a **system architecture image** (PNG/JPG), and  
2) brief **application context** (form fields).

The service calls **Google Cloud Vertex AI (Gemini)** with **multimodal** input (text + image) and returns **JSON** containing threats and improvement suggestions.

---

## Features
- Accepts **image** + **context** and returns STRIDE analysis:
  - `Spoofing`, `Tampering`, `Repudiation`, `Information Disclosure`, `Denial of Service`, `Elevation of Privilege`.
- Output is **JSON-only** (the model is instructed to respond with valid JSON).
- Language-selectable **prompt** (`en` or `pt`) without changing the endpoint.
- CORS open by default for easy testing.
