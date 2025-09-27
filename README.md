# HIP-3 OpenInterest Cap Manager

Production-ready tool for managing OpenInterest caps on Hyperliquid HIP-3 (builder-deployed) perpetual markets. Uses EOA L1 signing with proper constraint validation according to official Hyperliquid specifications.

## 🔥 Key Features

- **⚡ Native SDK Integration**: Uses hyperliquid-python-sdk's native L1 signing
- **🛡️ EOA Signing**: Proper L1 action signing with EIP-712 domain verification  
- **🎯 HIP-3 Specific**: Handles `perpDeploy` actions with `setOpenInterestCaps`
- **📊 Smart Validation**: Enforces HIP-3 constraints (`max($1M, 0.5 × current OI)`)
- **🛡️ Safety First**: Comprehensive dry-run mode and error handling
- **🔒 Critical Safety Checks**: 
  - New cap can never be less than current OpenInterest
  - Configurable maximum cap change percentage (default: 200%)
  - First-time cap setting support for new assets
- **📈 Precision Math**: Decimal arithmetic throughout, no float precision loss
- **🔍 Full Verification**: Reads back changed caps to confirm updates
- **📝 Detailed Logging**: Clear progress tracking and helpful error hints
- **🚫 Null Field Protection**: Omits null vaultAddress/expiresAfter from payload

## 🚀 Quick Start

### 1. Installation

{{ ... }}
#### Option A: Standalone Installation (Recommended for Production)
```bash
# Download just the oi_caps directory
# Or clone and copy oi_caps to your target machine

cd oi_caps

# Install dependencies with uv (recommended)
uv sync

# Or with pip
pip install -e .
```

#### Option B: From Source Repository
```bash
# Clone the full repository 
git clone https://github.com/hyperliquid-dex/hyperliquid-python-sdk.git
cd hyperliquid-python-sdk/oi_caps

# Install dependencies
uv sync
```

### 2. Configuration

```bash
# Copy the example environment file
cp .env.example .env

# Edit .env with your configuration
nano .env
```

Required environment variables:
```bash
HIP3_DEPLOYER_PRIVATE_KEY=0x...    # Your deployer EOA private key
HIP3_DEX_NAME=MYDEX               # Your HIP-3 DEX name  
HIP3_MARKET_NAME=BTC              # Asset to update
HIP3_NEW_CAP=5000000              # New cap (USD notional)
HIP3_IS_MAINNET=false             # false=testnet, true=mainnet
```

### 3. Usage

```bash
# Dry run first (recommended)
HIP3_DRY_RUN=true python main.py

# Execute for real
HIP3_DRY_RUN=false python main.py

# Or using the installed script
oi-caps
```

## 📋 Requirements

- **Deployer Permissions**: Your EOA must have deployer permissions for the target DEX
- **Sufficient Cap**: New cap must be ≥ `max($1,000,000, 50% × current_open_interest)`
- **Whole Dollars**: Caps must be integers (no fractional cents)
- **Valid Asset**: Asset must exist in the specified DEX

## 🔧 Advanced Usage

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `HIP3_DEPLOYER_PRIVATE_KEY` | ✅ | - | Deployer EOA private key (0x prefix) |
| `HIP3_DEX_NAME` | ✅ | `MYDEX` | HIP-3 DEX identifier |
| `HIP3_MARKET_NAME` | ✅ | - | Asset name to update |
| `HIP3_NEW_CAP` | ✅ | - | New cap in USD (supports 1_000_000, 1e6) |
| `HIP3_IS_MAINNET` | ❌ | `false` | Network selection |
| `HIP3_DRY_RUN` | ❌ | `false` | Validation-only mode |

### Cap Value Formats

All formats are supported for `HIP3_NEW_CAP`:
```bash
HIP3_NEW_CAP=1000000      # Standard notation
HIP3_NEW_CAP=1_000_000    # Underscores for readability  
HIP3_NEW_CAP=1e6          # Scientific notation
HIP3_NEW_CAP=5.5e6        # 5,500,000
```

### Batch Operations

For multiple assets, create a simple wrapper:
```bash
#!/bin/bash
declare -A CAPS=(
    ["BTC"]="10000000"
    ["ETH"]="5000000"
    ["SOL"]="2000000"
)

for asset in "${!CAPS[@]}"; do
    echo "Updating $asset to ${CAPS[$asset]}"
    HIP3_MARKET_NAME="$asset" HIP3_NEW_CAP="${CAPS[$asset]}" python main.py
done
```

## 🛡️ Security Best Practices

### 🔐 Private Key Management
- Use hardware wallets or secure key management systems
- Never commit `.env` files with real keys
- Use testnet for development and testing
- Rotate keys periodically

### 🧪 Testing Workflow
1. **Always dry run first**: `HIP3_DRY_RUN=true`
2. **Test on testnet**: `HIP3_IS_MAINNET=false`
3. **Verify DEX and asset names** carefully
4. **Check current caps** with small test changes
5. **Monitor logs** for any warnings

### 📊 Monitoring
```bash
# Check current caps
curl -X POST https://api.hyperliquid.xyz/info \
  -H "Content-Type: application/json" \
  -d '{"type":"perpDexLimits","dex":"MYDEX"}'

# Monitor your transactions
tail -f /var/log/oi_caps.log
```

## 🔍 Troubleshooting

### Common Issues

**❌ "Asset not found in DEX"**
- Verify `HIP3_DEX_NAME` matches your deployed DEX exactly
- Check asset exists: call `meta` endpoint with your DEX name
- Ensure proper case sensitivity

**❌ "Signature mismatch"**  
- Check private key format (must have `0x` prefix)
- Verify deployer permissions on the target DEX
- Try on testnet first to validate signing

**❌ "Cap constraint violation"**
- Current cap is too low: must be ≥ `max($1M, 50% × current_OI)`
- Check current open interest is not too high
- Server enforces this even if client validation passes

**❌ "DEX not found"**
- List available DEXs: `{"type":"perpDexs"}`
- Empty string `""` is the default DEX
- HIP-3 DEX names are case-sensitive

### Debug Mode

Enable detailed logging:
```python
import logging
logging.getLogger().setLevel(logging.DEBUG)
```

## 📚 Technical Details

### L1 Signing Process
1. Build `perpDeploy` action with `setOpenInterestCaps`
2. Create action hash: `keccak(msgpack(action) + nonce + vault + expires)`
3. Construct phantom Agent: `{source: "a"/"b", connectionId: "0x" + hash.hex()}`
4. Sign EIP-712 typed data with domain `{name: "Exchange", chainId: 1337}`
5. Submit to `/exchange` endpoint

### API Endpoints Used
- `perpDexLimits`: Read current OI caps
- `meta`: Get DEX universe and margin tables  
- `metaAndAssetCtxs`: Get current OI (default DEX only)
- `perpDexs`: List available DEXs
- `/exchange`: Submit signed actions

### Constraint Validation
```
min_cap = max($1,000,000, 0.5 × current_open_interest)
new_cap >= min_cap
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-improvement`
3. Test thoroughly on testnet
4. Submit a pull request with detailed description

## 📄 License

MIT License - see LICENSE file for details.

## 🔗 Links

- [Hyperliquid Documentation](https://hyperliquid.gitbook.io/hyperliquid-docs/)
- [HIP-3 Specification](https://hyperliquid.gitbook.io/hyperliquid-docs/hyperliquid-improvement-proposals-hips/hip-3-builder-deployed-perpetuals)  
- [API Reference](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api)
- [Python SDK](https://github.com/hyperliquid-dex/hyperliquid-python-sdk)

---

⚠️ **Disclaimer**: This tool manages real money on live markets. Always test thoroughly on testnet first. Use at your own risk.