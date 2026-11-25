
from pathlib import Path
import pandas as pd
import joblib
import io

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "random_forest_model.joblib"

app = FastAPI(
    title="NEXUS Network Security API",
    description="Backend API for network intrusion detection.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

model = None

@app.on_event("startup")
def load_model():
    global model
    if MODEL_PATH.exists():
        model = joblib.load(MODEL_PATH)
        print("NEXUS ML model loaded successfully.")
    else:
        print("Warning: ML model file not found.")

@app.get("/")
def root():
    return {"message": "NEXUS API is running"}

@app.get("/api/health")
def health():
    return {
        "status": "online",
        "service": "NEXUS Network Security API",
        "model_loaded": model is not None
    }

@app.post("/api/datasets/preview")
async def preview_dataset(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=400,
            detail="Please upload a CSV file."
        )

    content = await file.read()

    if len(content) > 25 * 1024 * 1024:
        raise HTTPException(
            status_code=413,
            detail="File must be smaller than 25 MB."
        )

    try:
        df = pd.read_csv(io.BytesIO(content), nrows=10)
        return {
            "filename": file.filename,
            "preview_rows": df.fillna("").to_dict(orient="records"),
            "columns": list(df.columns),
            "message": "CSV preview loaded successfully."
        }
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Could not read CSV: {exc}"
        )

@app.post("/api/predict")
async def predict(file: UploadFile = File(...)):
    if model is None:
        raise HTTPException(
            status_code=503,
            detail="ML model is not loaded."
        )

    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=400,
            detail="Please upload a CSV file."
        )

    content = await file.read()

    if len(content) > 25 * 1024 * 1024:
        raise HTTPException(
            status_code=413,
            detail="File must be smaller than 25 MB."
        )

    try:
        df = pd.read_csv(io.BytesIO(content))

        # Remove target and identifier columns if present
        df = df.drop(
            columns=["attack_cat", "label", "id"],
            errors="ignore"
        )

        predictions = model.predict(df)

        results = pd.Series(predictions).value_counts().to_dict()

        return {
            "filename": file.filename,
            "total_records": len(df),
            "predicted_categories": results,
            "predictions": predictions.tolist(),
            "message": "Network traffic classification completed."
        }

    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Prediction failed: {str(exc)}"
        )
    
@app.post("/api/firewall/simulate")
async def firewall_simulate(file: UploadFile = File(...)):
    if model is None:
        raise HTTPException(status_code=503, detail="ML model is not loaded.")

    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Please upload a CSV file.")

    content = await file.read()

    if len(content) > 25 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File must be smaller than 25 MB.")

    try:
        df = pd.read_csv(io.BytesIO(content))

        features = df.drop(
            columns=["attack_cat", "label", "id"],
            errors="ignore"
        )

        predictions = model.predict(features)

        results = []

        for category in predictions:
            category = str(category)

            if category == "Normal":
                action = "Allow"
            elif category in ["Analysis", "Reconnaissance", "Fuzzers"]:
                action = "Review"
            else:
                action = "Block"

            results.append({
                "attack_category": category,
                "firewall_action": action
            })

        summary = pd.Series(
            [item["firewall_action"] for item in results]
        ).value_counts().to_dict()

        return {
            "filename": file.filename,
            "total_records": len(results),
            "decision_summary": summary,
            "results": results[:100],
            "message": "Firewall simulation completed. No real firewall rules were changed."
        }

    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Firewall simulation failed: {str(exc)}")

