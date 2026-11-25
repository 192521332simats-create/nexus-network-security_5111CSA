# NEXUS Network Security

A React + Vite frontend and Python FastAPI backend scaffold for an academic
Intelligent Machine Learning-Based Network Intrusion Detection System.

## Requirements
- Node.js 18 or newer
- Python 3.10 or newer

## Frontend
Open a terminal in this project folder:

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173

## Backend
Open a second terminal in the project folder:

```bash
cd backend
python -m venv venv
```

Windows PowerShell:
```powershell
.\venv\Scripts\Activate.ps1
```

Windows Command Prompt:
```bat
venv\Scripts\activate.bat
```

Install and run:
```bash
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Backend health check: http://localhost:8000/api/health
Interactive API docs: http://localhost:8000/docs

## Project modules
1. Network Traffic Dataset Processing
2. Machine Learning-Based Attack Classification
3. Firewall Rule Simulation (simulation only)
4. Intrusion Monitoring and Analytics Dashboard
5. Unified Reporting
6. Network Reconnaissance results
7. Web Assessment results

Dashboard values and charts currently use illustrative sample data. The CSV
preview endpoint is a starter integration; the trained ML model and real report
generation are to be added in later development steps.
