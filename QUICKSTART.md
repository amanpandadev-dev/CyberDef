# AegisNet - Quick Start Guide

## Prerequisites Check

Before starting, ensure you have:
- ✅ Python 3.11 or higher
- ✅ Node.js 18 or higher
- ✅ Ollama installed and running

## Step-by-Step Setup

### 1. Install Ollama Models

```bash
# Start Ollama service (in a separate terminal)
ollama serve

# Pull required models
ollama pull llama3.1:latest
ollama pull nomic-embed-text:latest
```

### 2. Install Backend Dependencies

Choose one of these methods:

**Option A: Using requirements.txt**
```bash
pip install -r requirements.txt
```

**Option B: Using pyproject.toml**
```bash
pip install -e .
```

### 3. Configure Environment

```bash
# Copy the example environment file
cp .env.example .env

# Edit .env if needed (defaults should work)
```

### 4. Install Frontend Dependencies

```bash
cd ui
npm install
cd ..
```

### 5. Start the Backend

```bash
# From the project root
python main.py
```

The backend will start on `http://localhost:8000`
- API Documentation: `http://localhost:8000/docs`
- Health Check: `http://localhost:8000/health`

### 6. Start the Frontend

In a **new terminal**:

```bash
cd ui
npm run dev
```

The frontend will start on `http://localhost:5173`

## First Analysis

1. Open `http://localhost:5173` in your browser
2. Navigate to **File Upload**
3. Upload a CSV file (or use samples from `tests/fixtures/`)
4. Go to **Analysis** page
5. Click **Run Analysis** on your uploaded file
6. View results in **Incidents** page

## Sample Data

Test with provided samples:
```bash
# Brute force attack scenario
tests/fixtures/sample_brute_force.csv

# Firewall traffic with threats
tests/fixtures/sample_firewall.csv
```

## Troubleshooting

### Ollama Not Running
```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# If not, start it
ollama serve
```

### Backend Port Already in Use
Edit `.env` and change:
```
API_PORT=8001  # or any available port
```

### Frontend Build Errors
```bash
cd ui
rm -rf node_modules package-lock.json
npm install
```

### Missing Python Dependencies
```bash
pip install -r requirements.txt --upgrade
```

## Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific test suite
pytest tests/test_parser.py -v
pytest tests/test_chunking.py -v
pytest tests/test_agents.py -v
```

## Project Structure

```
CybeshieldPoC_PredictiveAI/
├── main.py              # FastAPI application entry point
├── requirements.txt     # Python dependencies
├── .env.example         # Environment configuration template
├── setup.sh            # Automated setup script
│
├── core/               # Core utilities
├── shared_models/      # Pydantic data models
├── file_intake/        # CSV upload and validation
├── parser/             # CSV parsers
├── normalization/      # Event normalization
├── chunking/           # Behavioral chunking
├── agents/             # AI agent ensemble
├── incidents/          # Incident management
├── case_api/           # REST API routes
│
├── ui/                 # React frontend
│   ├── src/
│   │   ├── pages/      # Dashboard, Upload, Incidents, etc.
│   │   ├── components/ # Layout and shared components
│   │   └── api/        # Backend API client
│   └── package.json
│
└── tests/              # Test suite
    └── fixtures/       # Sample CSV files
```

## Next Steps

- Review the [README.md](README.md) for detailed documentation
- Check the [walkthrough.md](.gemini/antigravity/brain/.../walkthrough.md) for architecture details
- Explore the API at `http://localhost:8000/docs`
- Upload your own security logs for analysis

## Support

For issues or questions:
1. Check the API health: `http://localhost:8000/health`
2. Review backend logs in the terminal
3. Check browser console for frontend errors
4. Verify Ollama is running: `ollama list`
