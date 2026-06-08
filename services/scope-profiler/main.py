from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional

app = FastAPI(title="EASM Scope Profiler Service")

class Seed(BaseModel):
    domains: List[str] = Field(default_factory=list)
    ips: List[str] = Field(default_factory=list)

class ClassifyRequest(BaseModel):
    customer_id: str
    seed: Seed

class ClassifyResponse(BaseModel):
    customer_id: str
    tier: str

@app.post("/classify", response_model=ClassifyResponse)
async def classify_seed(request: ClassifyRequest):
    # Rule-based tier classification:
    # Tier A: Has domains (high priority targets for subfinder/dns resolution)
    # Tier B: Has IPs but no domains
    # Tier C: Empty seed or other small/inactive targets
    
    domains_count = len(request.seed.domains)
    ips_count = len(request.seed.ips)
    
    if domains_count > 0:
        tier = "A"
    elif ips_count > 0:
        tier = "B"
    else:
        tier = "C"
        
    return ClassifyResponse(
        customer_id=request.customer_id,
        tier=tier
    )

@app.get("/health")
async def health_check():
    return {"status": "healthy"}
