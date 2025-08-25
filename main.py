import os
import json
from dotenv import load_dotenv
from fastapi import FastAPI, UploadFile, Form, File
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# Vertex AI (GCP)
import vertexai
from vertexai.generative_models import GenerativeModel, Part, GenerationConfig

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
env_path = os.path.join(BASE_DIR, ".env")
load_dotenv(dotenv_path=env_path)

GCP_PROJECT_ID = os.getenv("GCP_PROJECT_ID")
GCP_LOCATION = os.getenv("GCP_LOCATION", "us-central1")
GCP_MODEL_NAME = os.getenv("GCP_MODEL_NAME", "gemini-1.5-pro")

# Initialize Vertex AI
vertexai.init(project=GCP_PROJECT_ID, location=GCP_LOCATION)
model = GenerativeModel(GCP_MODEL_NAME)

# FastAPI + CORS
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- Prompt templates (PT and EN). Select via `prompt_language` = "pt" | "en" ----
PT_TEMPLATE = """Aja como um especialista em cibersegurança com mais de 20 anos de experiência,
usando a metodologia STRIDE para produzir um modelo de ameaças para a aplicação e para a ARQUITETURA NA IMAGEM ANEXA.

Regras de saída:
- Responda SOMENTE com JSON válido (sem markdown, sem texto extra).
- Use exatamente as chaves: "threat_model" (array de objetos) e "improvement_suggestions" (array de strings).
- Em "Threat Type", use exatamente: "Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege".
- Liste 3–4 ameaças por categoria STRIDE, se aplicável, com cenários plausíveis no contexto fornecido.

Contexto:
TIPO_DE_APLICACAO: {application_type}
METODOS_DE_AUTENTICACAO: {authentication_methods}
EXPOSTA_NA_INTERNET: {internet_exposed}
DADOS_SENSIVEIS: {sensitive_data}
RESUMO_DESCRICAO: {application_description}

Saída esperada (SOMENTE JSON):
{{
  "threat_model": [
    {{ "Threat Type": "Spoofing", "Scenario": "…", "Potential Impact": "…" }}
  ],
  "improvement_suggestions": [
    "…"
  ]
}}"""

EN_TEMPLATE = """Act as a cybersecurity expert with 20+ years of experience,
using the STRIDE methodology to produce a threat model for the application and for the ARCHITECTURE IN THE ATTACHED IMAGE.

Output rules:
- Reply ONLY with valid JSON (no markdown, no extra text).
- Use exactly the keys: "threat_model" (array of objects) and "improvement_suggestions" (array of strings).
- For "Threat Type", use exactly: "Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege".
- List 3–4 threats per STRIDE category, if applicable, with plausible scenarios in the provided context.

Context:
APPLICATION_TYPE: {application_type}
AUTHENTICATION_METHODS: {authentication_methods}
INTERNET_EXPOSED: {internet_exposed}
SENSITIVE_DATA: {sensitive_data}
SUMMARY_DESCRIPTION: {application_description}

Expected output (JSON ONLY):
{{
  "threat_model": [
    {{ "Threat Type": "Spoofing", "Scenario": "…", "Potential Impact": "…" }}
  ],
  "improvement_suggestions": [
    "…"
  ]
}}"""

def create_threat_model_prompt(
    application_type: str,
    authentication_methods: str,
    internet_exposed: str,
    sensitive_data: str,
    application_description: str,
    prompt_language: str = "en",
) -> str:
    """
    Build the STRIDE prompt in the selected language ("pt" or "en").
    Choose language via form field `prompt_language`.
    """
    lang = (prompt_language or "en").strip().lower()
    template = EN_TEMPLATE if lang.startswith("en") else PT_TEMPLATE
    return template.format(
        application_type=application_type,
        authentication_methods=authentication_methods,
        internet_exposed=internet_exposed,
        sensitive_data=sensitive_data,
        application_description=application_description,
    )

@app.post("/analyze_threats")
async def analyze_threats(
    image: UploadFile = File(...),
    application_type: str = Form(...),
    authentication_methods: str = Form(...),
    internet_exposed: str = Form(...),
    sensitive_data: str = Form(...),
    application_description: str = Form(...),
    prompt_language: str = Form("en"),  # "en" or "pt"
):
    """
    FastAPI handler that:
    - Builds a PT/EN STRIDE prompt
    - Sends multimodal (text + image) to Vertex Gemini
    - Returns the model's JSON or raw text if parsing fails
    """
    try:
        # Build prompt
        prompt = create_threat_model_prompt(
            application_type=application_type,
            authentication_methods=authentication_methods,
            internet_exposed=internet_exposed,
            sensitive_data=sensitive_data,
            application_description=application_description,
            prompt_language=prompt_language,
        )

        # Read uploaded image
        image_bytes = await image.read()
        mime_type = image.content_type or "image/png"
        if isinstance(image_bytes, bytearray):
            image_bytes = bytes(image_bytes)
        image_part = Part.from_data(mime_type=mime_type, data=image_bytes)

        # Multimodal content
        contents = [
            prompt,
            image_part,
            "Analyze the image and the text above and return ONLY the JSON described in the instructions.",
        ]

        # Generation config
        cfg = GenerationConfig(
            temperature=0.7,
            top_p=0.95,
            max_output_tokens=1500,
        )
        response = model.generate_content(contents, generation_config=cfg)

        # Try to parse JSON strictly
        text = response.text or ""
        try:
            parsed = json.loads(text)
            return JSONResponse(content=parsed, status_code=200)
        except json.JSONDecodeError:
            return JSONResponse(content={"raw_text": text}, status_code=200)

    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)
