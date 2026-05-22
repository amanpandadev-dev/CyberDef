#!/bin/bash

# AegisNet Setup Script
# This script sets up the AegisNet development environment

set -e

echo "🛡️  AegisNet Setup Script"
echo "========================="
echo ""

# Check Python version
echo "📋 Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "   Found Python $python_version"

# Check Node version
echo "📋 Checking Node.js version..."
node_version=$(node --version 2>&1)
echo "   Found Node $node_version"

# Check if Ollama is installed
echo "📋 Checking Ollama..."
if command -v ollama &> /dev/null; then
    echo "   ✅ Ollama is installed"
else
    echo "   ❌ Ollama not found. Please install from https://ollama.ai"
    exit 1
fi

# Backend setup
echo ""
echo "🐍 Setting up Python backend..."
echo "   Installing dependencies..."
pip install -e . --quiet

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "   Creating .env file..."
    cp .env.example .env
    echo "   ✅ Created .env file"
else
    echo "   ✅ .env file already exists"
fi

# Create data directories
echo "   Creating data directories..."
mkdir -p data/raw_files
mkdir -p data/processed
echo "   ✅ Data directories created"

# Frontend setup
echo ""
echo "⚛️  Setting up React frontend..."
cd ui
echo "   Installing dependencies..."
npm install --silent
cd ..

# Pull Ollama models
echo ""
echo "🤖 Setting up Ollama models..."
echo "   This may take a few minutes..."

if ollama list | grep -q "llama3.1:latest"; then
    echo "   ✅ llama3.1:latest already installed"
else
    echo "   Pulling llama3.1:latest..."
    ollama pull llama3.1:latest
fi

if ollama list | grep -q "nomic-embed-text:latest"; then
    echo "   ✅ nomic-embed-text:latest already installed"
else
    echo "   Pulling nomic-embed-text:latest..."
    ollama pull nomic-embed-text:latest
fi

echo ""
echo "✅ Setup complete!"
echo ""
echo "🚀 To start AegisNet:"
echo ""
echo "   1. Start Ollama (if not running):"
echo "      $ ollama serve"
echo ""
echo "   2. Start the backend:"
echo "      $ python main.py"
echo ""
echo "   3. Start the frontend (in a new terminal):"
echo "      $ cd ui && npm run dev"
echo ""
echo "   4. Open http://localhost:5173 in your browser"
echo ""
echo "📚 Documentation:"
echo "   - README: ./README.md"
echo "   - API Docs: http://localhost:8000/docs (after starting backend)"
echo "   - Walkthrough: .gemini/antigravity/brain/.../walkthrough.md"
echo ""
