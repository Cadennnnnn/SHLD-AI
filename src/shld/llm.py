
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_groq import ChatGroq
from langchain_openai import ChatOpenAI

from shld.config import (
    LLM_PROVIDER,
    GOOGLE_API_KEY,
    GOOGLE_MODEL,
    GROQ_API_KEY,
    GROQ_MODEL,
    OPENROUTER_API_KEY,
    OPENROUTER_MODEL,
)


def create_llm():
    if LLM_PROVIDER == "google":
        if not GOOGLE_API_KEY:
            raise RuntimeError("Falta GOOGLE_API_KEY en .env")
        return ChatGoogleGenerativeAI(
            model=GOOGLE_MODEL,
            google_api_key=GOOGLE_API_KEY,
            temperature=0,
        )

    if LLM_PROVIDER == "groq":
        if not GROQ_API_KEY:
            raise RuntimeError("Falta GROQ_API_KEY en .env")
        return ChatGroq(
            model=GROQ_MODEL,
            api_key=GROQ_API_KEY,
            temperature=0,
        )

    if LLM_PROVIDER == "openrouter":
        if not OPENROUTER_API_KEY:
            raise RuntimeError("Falta OPENROUTER_API_KEY en .env")
        return ChatOpenAI(
            model=OPENROUTER_MODEL,
            api_key=OPENROUTER_API_KEY,
            base_url="https://openrouter.ai/api/v1",
            temperature=0,
        )

    raise RuntimeError(f"Proveedor no compatible: {LLM_PROVIDER}")
