#!/bin/bash
# HIP-3 OI Cap Manager Deployment Script
# Run this on your target machine to set up the tool

set -e

echo "🚀 Deploying HIP-3 OI Cap Manager..."

# Create deployment directory
DEPLOY_DIR="$HOME/oi-caps-tool"
echo "📁 Creating deployment directory: $DEPLOY_DIR"
mkdir -p "$DEPLOY_DIR"

# Copy essential files
echo "📋 Copying files..."
cp -r . "$DEPLOY_DIR/"
cd "$DEPLOY_DIR"

# Clean up any local artifacts
rm -rf .venv __pycache__ *.egg-info

# Install dependencies
if command -v uv &> /dev/null; then
    echo "📦 Installing with uv..."
    uv sync
elif command -v pip &> /dev/null; then
    echo "📦 Installing with pip..."
    pip install -e .
else
    echo "❌ Neither uv nor pip found. Please install Python package manager first."
    exit 1
fi

# Create .env if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env from template..."
    cp .env.example .env
    echo ""
    echo "🔧 IMPORTANT: Edit .env with your configuration:"
    echo "   nano $DEPLOY_DIR/.env"
fi

echo ""
echo "✅ Deployment complete!"
echo ""
echo "📍 Tool installed at: $DEPLOY_DIR"
echo ""
echo "🚀 Quick start:"
echo "1. Edit configuration: cd $DEPLOY_DIR && nano .env"
echo "2. Test with dry run: uv run python main.py"
echo "3. Execute for real: HIP3_DRY_RUN=false uv run python main.py"
