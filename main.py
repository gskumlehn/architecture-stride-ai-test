import os
import json
from dotenv import load_dotenv
from fastapi import FastAPI, UploadFile, Form, File
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

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

# ---- Prompt templates (PT and EN). Best way to select language: pass form field `prompt_language` with "pt" or "en". ----
PT_TEMPLATE = """Aja como um especialista em cibersegurança com mais de 20 anos de experiência,
usando a metodologia STRIDE para produzir um modelo de ameaças para a aplicação e a ARQUITETURA DA IMAGEM ANEXA.

Regras de saída:
- Responda SOMENTE com JSON válido (sem markdown, sem texto extra).
- Use exatamente as chaves: "threat_model" (array de objetos) e "improvement_suggestions" (array de strings).
- Em "Threat Type", use exatamente: "Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege".
- Liste 3–4 ameaças por categoria STRIDE, se aplicável, com cenários plausíveis no contexto fornecido.

Contexto:
TIPO_DE_APLICACAO: {tipo_aplicacao}
METODOS_DE_AUTENTICACAO: {autenticacao}
EXPOSTA_NA_INTERNET: {acesso_internet}
DADOS_SENSIVEIS: {dados_sensiveis}
RESUMO_DESCRICAO: {descricao_aplicacao}

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
APPLICATION_TYPE: {tipo_aplicacao}
AUTHENTICATION_METHODS: {autenticacao}
INTERNET_EXPOSED: {acesso_internet}
SENSITIVE_DATA: {dados_sensiveis}
SUMMARY_DESCRIPTION: {descricao_aplicacao}

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
    tipo_aplicacao: str,
    autenticacao: str,
    acesso_internet: str,
    dados_sensiveis: str,
    descricao_aplicacao: str,
    prompt_language: str = "pt",
) -> str:
    """
    Build the STRIDE prompt in the selected language ("pt" or "en").
    Best way to choose: pass form field `prompt_language` with value "pt" or "en".
    """
    lang = (prompt_language or "pt").strip().lower()
    template = EN_TEMPLATE if lang.startswith("en") else PT_TEMPLATE
    return template.format(
        tipo_aplicacao=tipo_aplicacao,
        autenticacao=autenticacao,
        acesso_internet=acesso_internet,
        dados_sensiveis=dados_sensiveis,
        descricao_aplicacao=descricao_aplicacao,
    )

@app.post("/analisar_ameacas")
async def analyze_threats(  # function name in English; route kept for compatibility
    imagem: UploadFile = File(...),
    tipo_aplicacao: str = Form(...),
    autenticacao: str = Form(...),
    acesso_internet: str = Form(...),
    dados_sensiveis: str = Form(...),
    descricao_aplicacao: str = Form(...),
    prompt_language: str = Form("pt"),  # "pt" or "en"
):
    """
    FastAPI handler that:
    - Builds a PT/EN prompt for STRIDE threat modeling
    - Sends multimodal (text + image) content to Vertex Gemini
    - Returns the model's JSON or raw text if parsing fails
    """
    try:
        # Build prompt (PT or EN)
        prompt = create_threat_model_prompt(
            tipo_aplicacao=tipo_aplicacao,
            autenticacao=autenticacao,
            acesso_internet=acesso_internet,
            dados_sensiveis=dados_sensiveis,
            descricao_aplicacao=descricao_aplicacao,
            prompt_language=prompt_language,
        )

        # Read uploaded image
        image_bytes = await imagem.read()
        mime_type = imagem.content_type or "image/png"
        if isinstance(image_bytes, bytearray):
            image_bytes = bytes(image_bytes)
        image_part = Part.from_data(mime_type=mime_type, data=image_bytes)

        # Multimodal content for Gemini
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
