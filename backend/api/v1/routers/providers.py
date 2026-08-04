from fastapi import APIRouter, Query
from typing import List, Optional
from pydantic import BaseModel
import time

router = APIRouter(prefix="/providers", tags=["Providers"])

class OpenRouterModelResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    context_length: Optional[int] = None
    max_completion_tokens: Optional[int] = None
    modality: Optional[str] = None
    prompt_price: Optional[str] = None
    completion_price: Optional[str] = None
    supported_parameters: List[str] = []

class OpenRouterModelsResponse(BaseModel):
    source: str
    fetched_at: int
    total_count: int
    items: List[OpenRouterModelResponse]

FALLBACK_MODELS = [
    OpenRouterModelResponse(
        id="anthropic/claude-3.5-sonnet",
        name="Claude 3.5 Sonnet",
        description="Most capable Anthropic model for code and complex reasoning",
        context_length=200000,
        max_completion_tokens=8192,
        modality="text->text",
        prompt_price="$3/M",
        completion_price="$15/M",
        supported_parameters=["temperature", "max_tokens"],
    ),
    OpenRouterModelResponse(
        id="openai/gpt-4o",
        name="GPT-4o",
        description="High-intelligence flagship model for multimodal and text tasks",
        context_length=128000,
        max_completion_tokens=4096,
        modality="text->text",
        prompt_price="$2.5/M",
        completion_price="$10/M",
        supported_parameters=["temperature", "max_tokens"],
    ),
    OpenRouterModelResponse(
        id="meta-llama/llama-3.3-70b-instruct",
        name="Llama 3.3 70B Instruct",
        description="Open-weights high performance instruction-tuned model",
        context_length=131072,
        max_completion_tokens=4096,
        modality="text->text",
        prompt_price="$0.4/M",
        completion_price="$0.4/M",
        supported_parameters=["temperature", "max_tokens"],
    ),
]

@router.get("/openrouter/models", response_model=OpenRouterModelsResponse)
async def list_openrouter_models(refresh: bool = Query(default=False)):
    """List available LLM review models from OpenRouter."""
    return OpenRouterModelsResponse(
        source="catalog",
        fetched_at=int(time.time()),
        total_count=len(FALLBACK_MODELS),
        items=FALLBACK_MODELS,
    )
