#!/bin/bash
# HIP-3 OI Cap Manager Setup Script

set -e  # Exit on error

echo "🚀 Setting up HIP-3 OI Cap Manager..."

# Install dependencies
if command -v uv &> /dev/null; then
    echo "📦 Installing with uv..."
    uv sync
    echo "✅ Dependencies installed with uv"
elif command -v pip &> /dev/null; then
    echo "📦 Installing with pip..."
    pip install -e .
    echo "✅ Dependencies installed with pip"
else
    echo "❌ Neither uv nor pip found. Please install one of them first."
    echo "💡 Install uv: curl -LsSf https://astral.sh/uv/install.sh | sh"
    exit 1
fi

# Create .env from template if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env file from template..."
    cp .env.example .env
    echo "✅ Created .env file"
    echo ""
    echo "🔧 Please edit .env with your configuration:"
    echo "   - HIP3_DEPLOYER_PRIVATE_KEY: Your deployer EOA private key"
    echo "   - HIP3_DEX_NAME: Your HIP-3 DEX identifier" 
    echo "   - HIP3_MARKET_NAME: Asset to update"
    echo "   - HIP3_NEW_CAP: New cap value"
    echo "   - HIP3_IS_MAINNET: false for testnet, true for mainnet"
else
    echo "✅ .env file already exists"
fi

# Verify installation
echo ""
echo "🧪 Testing installation..."
if python -c "import hyperliquid; print('✅ Hyperliquid SDK imported successfully')" 2>/dev/null; then
    echo "✅ Installation verified"
else
    echo "❌ Installation verification failed"
    exit 1
fi

echo ""
echo "🎉 Setup complete!"
echo ""
echo "Next steps:"
echo "1. Edit .env with your configuration: nano .env"
echo "2. Test with dry run: HIP3_DRY_RUN=true uv run python main.py"
echo "3. Execute for real: HIP3_DRY_RUN=false uv run python main.py"
echo ""
echo "📚 Read README.md for detailed usage instructions"
