from fastapi import FastAPI
from pydantic import BaseModel
from scorer import score_code

app = FastAPI(
    title="PCI DSS Requirement 6 Scoring API",
    description="Paste code → get PCI DSS compliance score (1–5)",
    version="1.0"
)

class CodeInput(BaseModel):
    code: str

@app.post("/score")
def score_pci(code_input: CodeInput):
    result = score_code(code_input.code)
    return result
