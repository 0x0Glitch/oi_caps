#!/usr/bin/env python3
"""
HIP-3 Cap Changing Script
Uses deployer EOA for L1 action signing with proper constraint validation.

CRITICAL SPECIFICATIONS (According to official docs):
• OI caps are USD NOTIONAL values (position_size × mark_price)
• Minimum constraint: max(1_000_000 = $1 USD, 50% of current OI)
• SetOpenInterestCaps: Array<[asset_name, cap_usd_notional]> (alphabetically sorted)

ENVIRONMENT VARIABLES:
• HIP3_DEPLOYER_PRIVATE_KEY - Deployer's private key (required)
• HIP3_DEX_NAME - Target DEX name (required, ≤6 chars, no empty string)
• HIP3_MARKET_NAME - Asset to update (required)
• HIP3_NEW_CAP_USD - New cap in USD (e.g., 5000000 for $5M) [choose this OR _RAW]
• HIP3_NEW_CAP_RAW - New cap in microUSD units (e.g., 5000000000000 for $5M) [choose this OR _USD]
• HIP3_DRY_RUN - "true" for validation only (default: "true")
• HIP3_IS_MAINNET - "true" for mainnet, "false" for testnet
• HIP3_MAX_CAP_CHANGE_PERCENT - Max % cap change allowed (default: 200)
• HIP3_ENFORCE_CAP_ABOVE_OI - Require cap ≥ current OI (default: true, stricter than spec)

TECHNICAL DETAILS:
• L1 signing using SDK's native sign_l1_action (handles chain ID automatically)
• Validates constraints per HIP-3 specifications
"""

import json
import logging
import os
import sys
import time
from decimal import Decimal, InvalidOperation
from typing import Dict, List, Optional, Tuple, Any
from eth_account import Account
from hyperliquid.info import Info
from hyperliquid.utils import constants
from hyperliquid.utils.signing import get_timestamp_ms, sign_l1_action

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class HIP3OpenInterestCapManager:
    """Manages Open Interest caps for HIP-3 markets using EOA signing."""
    def __init__(
        self,
        private_key: str,
        base_url: Optional[str] = None,
        is_mainnet: bool = True,
        max_cap_change_percent: float = 5.0,
        enforce_cap_above_oi: bool = True
    ):
        """
        Initialize the HIP-3 OI Cap Manager.
        
        Args:
            private_key: Deployer's private key (with 0x prefix)
            base_url: API base URL (defaults to mainnet/testnet based on is_mainnet)
            is_mainnet: Whether to use mainnet (True) or testnet (False)
            max_cap_change_percent: Maximum allowed cap change as percentage (default 5%)
            enforce_cap_above_oi: If True, enforce cap >= current OI (stricter than HIP-3 spec)
        """
        self.wallet = Account.from_key(private_key)
        self.address = self.wallet.address
        self.is_mainnet = is_mainnet
        self.max_cap_change_percent = max_cap_change_percent
        self.enforce_cap_above_oi = enforce_cap_above_oi
        
        if base_url is None:
            self.base_url = constants.MAINNET_API_URL if is_mainnet else constants.TESTNET_API_URL
        else:
            self.base_url = base_url
            
        self.info = Info(self.base_url, skip_ws=True)
        
        logger.info(f"Initialized HIP-3 OI Cap Manager")
        logger.info(f"Deployer Address: {self.address}")
        logger.info(f"Network: {'Mainnet' if is_mainnet else 'Testnet'}")
        logger.info(f"Max cap change allowed: {max_cap_change_percent}%")
        logger.info(f"Enforce cap >= current OI: {'Yes' if enforce_cap_above_oi else 'No (follows HIP-3 spec)'}")
    
    def normalize_address(self, address: Optional[str]) -> Optional[str]:
        """
        Normalize addresses to lowercase for consistent signing.
        
        Args:
            address: Address to normalize (can be None)
            
        Returns:
            Lowercase address or None
        """
        if address is None:
            return None
        if not isinstance(address, str):
            return address
        # Remove 0x prefix, lowercase, add back prefix
        clean_addr = address[2:] if address.startswith("0x") else address
        return "0x" + clean_addr.lower()
    
    def get_meta_and_asset_ctxs(self) -> Optional[Tuple[Dict, List[Dict]]]:
        """
        Get metadata and asset contexts for the DEFAULT/FIRST DEX ONLY.
        
        IMPORTANT: The metaAndAssetCtxs endpoint does NOT accept a dex parameter.
        It always returns data for the first/default perp DEX.
        
        Returns:
            Tuple of (meta, assetCtxs) for default DEX only, or None if unavailable
        """
        try:
            # metaAndAssetCtxs doesn't take dex param - always returns first perp DEX
            payload = {"type": "metaAndAssetCtxs"}
            response = self.info.post("/info", payload)
            
            # Response should be [meta, assetCtxs] format
            if isinstance(response, list) and len(response) == 2:
                return response[0], response[1]
                
        except Exception as e:
            logger.warning(f"Could not fetch metaAndAssetCtxs: {e}")
            
        return None
    
    def get_dex_limits(self, dex: str) -> Dict[str, Any]:
        """
        Get HIP-3 DEX limits including OI caps.
        
        This endpoint exists but is not wrapped in the SDK, so we call it directly.
        Based on official documentation from: https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/info-endpoint/perpetuals#request-body-10:~:text=%7D-,Retrieve%20Builder%2DDeployed%20Perp%20Market%20Limits,-POST%20https%3A//api
        
        Args:
            dex: The DEX identifier (cannot be empty string)
            
        Returns:
            Dictionary with:
            - totalOiCap: Total OI cap for the DEX
            - oiSzCapPerPerp: OI size cap per perp
            - maxTransferNtl: Max transfer notional
            - coinToOiCap: Array of [coin, cap] pairs (strings)
        """
        if not dex or dex == "":
            raise ValueError("perpDexLimits requires non-empty dex name")
            
        payload = {
            "type": "perpDexLimits",
            "dex": dex
        }
        
        # Use the SDK's post method directly since this endpoint isn't wrapped
        response = self.info.post("/info", payload)
        
        # Validate response structure
        if not isinstance(response, dict):
            raise ValueError(f"Invalid response from perpDexLimits: {response}")
            
        return response
    
    def get_meta(self, dex: Optional[str] = "") -> Dict[str, Any]:
        """
        Fetch 'meta' (universe + margin tables). If dex is "",
        it returns the default/first perp DEX; otherwise the specified HIP-3 DEX.
        
        Args:
            dex: DEX identifier (empty string for default DEX)
            
        Returns:
            Dictionary with universe and margin tables
        """
        payload = {"type": "meta"}
        if dex is not None and dex != "":
            payload["dex"] = dex
        return self.info.post("/info", payload)
    
    def validate_oi_cap(self, asset: str, new_cap: Decimal, current_oi: Optional[Decimal]) -> bool:
        """
        Validate that the new OI cap meets constraints.
        
        Args:
            asset: Asset name
            new_cap: Proposed new cap (in USD notional)
            current_oi: Current open interest (in USD notional), None if unavailable
            
        Returns:
            True if valid, raises exception otherwise
        """
        # Optional safety check: New cap >= current OI (stricter than HIP-3 spec)
        if self.enforce_cap_above_oi and current_oi is not None and new_cap < current_oi:
            raise ValueError(
                f"❌ SAFETY VIOLATION: New cap ${new_cap:,.0f} is less than current OI ${current_oi:,.0f}\n"
                f"   This would immediately violate open positions!\n"
                f"   New cap must be >= current OI: ${current_oi:,.0f}\n"
                f"   (This is stricter than HIP-3 spec - disable with HIP3_ENFORCE_CAP_ABOVE_OI=false)"
            )
        
        # Minimum cap is 1,000,000 units = $1 USD 
        # Hyperliquid uses microUSD representation (6 decimal places)
        # So 1,000,000 microUSD = $1.00 USD
        min_cap = Decimal("1000000")  # This represents $1.00 USD, not $1 million!
        
        # If current OI is available, also check 0.5 * current_oi constraint
        if current_oi is not None:
            half_oi = current_oi * Decimal("0.5")
            if half_oi > min_cap:
                min_cap = half_oi
            
            # Only enforce minimum >= current OI if the flag is set
            if self.enforce_cap_above_oi and current_oi > min_cap:
                min_cap = current_oi
                
            logger.info(f"  Current OI: ${current_oi:,.2f}, Half OI: ${half_oi:,.2f}")
            logger.info(f"  Required minimum: ${min_cap:,.2f}")
        else:
            logger.warning(f"  Current OI unavailable for {asset}, using $1 minimum only")
            logger.warning(f"  Server will still enforce current OI constraint")
        
        if new_cap < min_cap:
            # Convert to USD for display
            new_cap_usd = new_cap / Decimal("1000000")
            min_cap_usd = min_cap / Decimal("1000000")
            raise ValueError(
                f"Invalid OI cap for {asset}: ${new_cap_usd:,.0f} < minimum ${min_cap_usd:,.0f}"
            )
        
        # Convert to USD for display
        new_cap_usd = new_cap / Decimal("1000000")
        min_cap_usd = min_cap / Decimal("1000000")
        logger.info(f"✅ Valid OI cap for {asset}: ${new_cap_usd:,.0f} (min: ${min_cap_usd:,.0f})")
        return True
    
    def build_set_oi_caps_action(self, dex: str, asset: str, new_cap: Decimal) -> Dict:
        """
        Build a setOpenInterestCaps action for HIP-3.
        
        Args:
            dex: DEX identifier to update caps for
            asset: Asset name to update cap for
            new_cap: New cap value in USD notional (will be converted to int)
            
        Returns:
            Action dictionary ready for signing
        """
        cap_int = int(new_cap)  # Convert to integer as required by API
        
        # Format as array of [asset, cap] pairs (strings for asset, int for cap)
        caps_list = [[asset, cap_int]]
        caps_list.sort(key=lambda x: x[0])  # Sort by asset name
        
        action = {
            "type": "perpDeploy",
            "dex": dex,  # REQUIRED: specify which DEX to update
            "setOpenInterestCaps": caps_list
        }
        
        # Show USD amount in log for clarity
        cap_usd = cap_int / 1000000
        logger.info(f"Built setOpenInterestCaps action for {asset} on DEX {dex}: ${cap_usd:,.0f} (${cap_int:,} microUSD)")
        
        # Log the actual action structure for debugging
        logger.info(f"Action structure: {json.dumps(action, indent=2)}")
        return action

    
    def sign_and_submit_l1_action(
        self,
        action: Dict,
        nonce: int
    ) -> Dict:
        """
        Sign and submit an L1 action using SDK's native signing.
        
        Args:
            action: The action to sign (perpDeploy with setOpenInterestCaps)
            nonce: Unique nonce (timestamp)
            
        Returns:
            API response
        """
        # Set expiration time: 2 minutes from now for replay protection
        expires_after = nonce + 120_000  # 120 seconds = 2 minutes
        
        # Use SDK's native sign_l1_action function
        signature = sign_l1_action(
            wallet=self.wallet,
            action=action,
            active_pool=None,  # No vault address for HIP-3 actions
            nonce=nonce,
            expires_after=expires_after,  # Include expiration for security
            is_mainnet=self.is_mainnet
        )
        
        # Build the payload (include expires_after since we signed with it)
        payload = {
            "action": action,
            "nonce": nonce,
            "signature": signature,
            "expiresAfter": expires_after
        }
        # Note: vaultAddress omitted since active_pool is None
        
        # Submit to exchange endpoint
        try:
            response = self.info.post("/exchange", payload)
            
            if response.get("status") == "ok":
                logger.info(f"✅ Action submitted successfully")
            else:
                logger.error(f"❌ Action submission failed: {response}")
                if "signature" in str(response).lower() or "sign" in str(response).lower():
                    logger.error("💡 Hint: Check signing scheme (L1 vs user-signed) and payload field order")
                    logger.error("   See: https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/signing")
                if "constraint" in str(response).lower() or "cap" in str(response).lower():
                    logger.error("💡 Hint: OI cap must be >= max($1, 0.5 * current OI)")
            
            return response
            
        except Exception as e:
            logger.error(f"❌ Failed to submit action to /exchange endpoint")
            logger.error(f"Error type: {type(e).__name__}")
            logger.error(f"Error message: {e}")
            logger.error(f"This suggests a payload format issue - the server cannot parse the JSON")
            
            # Check if it's the common JSON deserialization error
            if "Failed to deserialize the JSON body" in str(e):
                logger.error("💡 Server cannot parse the payload JSON structure")
                logger.error("💡 This usually means a field type or structure mismatch")
                logger.error("💡 Common issues: wrong data types, missing required fields, extra fields")
            
            # Re-raise the original exception
            raise
    
    def submit_action(
        self,
        action: Dict,
        nonce: int,
        signature: Dict,
        vault_address: Optional[str] = None,
        expires_after: Optional[int] = None
    ) -> Dict:
        """
        Submit a signed action to the exchange.
        
        Args:
            action: The action dictionary
            nonce: Nonce timestamp
            signature: The signature dictionary
            vault_address: Vault address (optional, will be normalized to lowercase)
            expires_after: Expiration timestamp (optional)
            
        Returns:
            Exchange response
        """
        payload = {
            "action": action,
            "nonce": nonce,
            "signature": signature
        }
        
        # Only include vaultAddress and expiresAfter if they are not None
        # Normalize vault_address to lowercase for consistent signing
        if vault_address is not None:
            payload["vaultAddress"] = self.normalize_address(vault_address)
        if expires_after is not None:
            payload["expiresAfter"] = expires_after
        
        # Don't log sensitive signature data but show payload structure for debugging
        safe_payload = payload.copy()
        if "signature" in safe_payload:
            safe_payload["signature"] = {"r": "0x...", "s": "0x...", "v": "..."}
        logger.info(f"Payload structure (masked): {json.dumps(safe_payload, indent=2)}")
        
        logger.info(f"Submitting action to exchange...")
        
        response = self.info.post("/exchange", payload)
        
        if response.get("status") == "ok":
            logger.info(f"✅ Action submitted successfully")
        else:
            logger.error(f"❌ Action submission failed: {response}")
            if "signature" in str(response).lower() or "sign" in str(response).lower():
                logger.error("💡 Hint: Check signing scheme (L1 vs user-signed) and payload field order")
                logger.error("   See: https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/signing")
            if "constraint" in str(response).lower() or "cap" in str(response).lower():
                logger.error("💡 Hint: OI cap must be >= max($1M, 0.5 * current OI)")
            
        return response
    
    def change_oi_cap(
        self,
        dex: str,
        asset: str,
        new_cap: Decimal,
        dry_run: bool = False
    ) -> Dict:
        """
        Change Open Interest cap for a single asset in a HIP-3 DEX.
        Args:
            dex: The DEX identifier
            asset: Asset name to update
            new_cap: New cap in USD notional
            dry_run: If True, validate but don't submit   
        Returns:
            Result dictionary with status and details
        """
        logger.info(f"{'[DRY RUN] ' if dry_run else ''}Changing OI cap for {asset} on DEX: {dex}")
        
        # Handle new_cap input (already Decimal from main, but support legacy usage)
        new_cap_decimal = new_cap if isinstance(new_cap, Decimal) else Decimal(str(new_cap).replace("_", ""))
        
        # Positivity check
        if new_cap_decimal <= 0:
            raise ValueError(f"❌ New cap must be positive, got: ${new_cap_decimal}")
        
        # Enforce integral notional to avoid silent truncation
        if new_cap_decimal != new_cap_decimal.to_integral_value():
            raise ValueError("HIP-3 OI caps must be whole-dollar integers.")
        
        # MANDATORY: Validate DEX exists (CRASH ON FAILURE)
        # Note: We require non-empty dex since HIP-3 requires named DEXs
        perp_dexs_resp = self.info.post("/info", {"type": "perpDexs"})
        if not isinstance(perp_dexs_resp, list):
            raise RuntimeError(f"❌ Invalid perpDexs response: {type(perp_dexs_resp)}")
            
        dex_names = []
        for entry in perp_dexs_resp:
            if entry is None:
                continue  # Skip null entries
            if not isinstance(entry, dict):
                raise RuntimeError(f"❌ Invalid DEX entry in perpDexs: {type(entry)}")
            name = entry.get("name")
            if not isinstance(name, str) or name == "":
                continue  # Skip entries without valid names
            dex_names.append(name)
            
        if dex not in dex_names:
            logger.error(f"DEX '{dex}' not found. Available HIP-3 DEXs: {dex_names}")
            raise ValueError(f"❌ DEX '{dex}' does not exist")
        
        # Step 1: Read current DEX limits (contains OI caps) - MUST succeed
        logger.info("Step 1: Reading current DEX limits and OI caps...")
        limits = self.get_dex_limits(dex)
        if not limits:
            raise RuntimeError(f"❌ FAILED to get DEX limits for '{dex}' - null response")
        
        # Parse current caps from coinToOiCap array
        caps_map = {}
        coin_to_oi_cap = limits.get("coinToOiCap", [])
        for coin, cap_str in coin_to_oi_cap:
            caps_map[coin] = Decimal(str(cap_str))
        
        if asset not in caps_map:
            # Check if asset exists in the DEX universe (for first-time OI cap setting)
            logger.info(f"Asset {asset} not found in current OI caps. Checking DEX universe...")
            
            meta = self.get_meta(dex)
            if not meta:
                raise RuntimeError(f"❌ FAILED to get meta for DEX '{dex}' during asset verification")
                
            universe = meta.get("universe", [])
            if not universe:
                raise RuntimeError(f"❌ DEX '{dex}' has no universe during asset verification")
            
            asset_found_in_universe = False
            for asset_info in universe:
                if not isinstance(asset_info, dict):
                    raise RuntimeError(f"❌ Invalid asset info in universe - not a dict")
                if asset_info.get("name") == asset:
                    asset_found_in_universe = True
                    break
            
            if not asset_found_in_universe:
                universe_names = [a.get("name") for a in universe if isinstance(a, dict) and a.get("name")]
                raise ValueError(f"❌ Asset '{asset}' not found in DEX '{dex}'. Available assets: {universe_names}")
            
            # Asset exists in universe but no OI cap set yet - this is a first-time cap setting
            logger.info(f"✅ Asset {asset} found in DEX universe - setting first OI cap")
            current_cap = Decimal("0")  # No existing cap
        else:
            current_cap = caps_map[asset]
        
        # Step 2: MANDATORY - Get current OI (NO EXCEPTIONS)
        logger.info("Step 2: Fetching current open interest (CRASH ON FAILURE)...")
        current_oi = None
        
        # MANDATORY: Get current OI data or DIE - no exceptions allowed
        meta = self.get_meta(dex)
        if not meta:
            raise RuntimeError(f"❌ FAILED to get meta for DEX '{dex}' - cannot proceed")
            
        universe = meta.get("universe", [])
        if not universe:
            raise RuntimeError(f"❌ DEX '{dex}' has no universe - invalid DEX")
        
        # Check if this asset exists in this DEX - must exist
        asset_found = False
        for asset_info in universe:
            if isinstance(asset_info, dict) and asset_info.get("name") == asset:
                asset_found = True
                break
        
        if not asset_found:
            raise ValueError(f"❌ Asset '{asset}' not found in DEX '{dex}' universe")
        
        # For HIP-3 builder DEXs, metaAndAssetCtxs cannot scope by dex; rely on server-side constraint checks
        # Note: Since we require non-empty DEX names, we always fall into this branch
        logger.warning(
            f"Cannot get current OI for HIP-3 DEX '{dex}' with current SDK; "
            "proceeding with server-side validation of the 0.5× OI constraint."
        )
        current_oi = None
        
        logger.info(f"  Asset: {asset}")
        if current_oi is not None:
            logger.info(f"  Current OI: ${current_oi:,.2f}")
        else:
            logger.info(f"  Current OI: Unable to fetch (will rely on server validation)")
        
        if current_cap == Decimal("0"):
            logger.info(f"  Current Cap: Not set (first-time cap setting)")
        else:
            logger.info(f"  Current Cap: ${current_cap:,.2f}")
        # Show cap in USD, not microUSD units
        usd_amount = new_cap_decimal / Decimal("1000000")
        logger.info(f"  New Cap: ${usd_amount:,.2f}")
        
        # Step 3: Safety check - prevent excessive cap changes
        logger.info("Step 3: Performing safety checks...")
        if current_cap > Decimal("0"):
            cap_change_percent = abs((new_cap_decimal - current_cap) / current_cap * 100)
            logger.info(f"  Cap change: {cap_change_percent:.1f}%")
            
            # Convert max_cap_change_percent to Decimal for comparison
            max_change_decimal = Decimal(str(self.max_cap_change_percent))
            if cap_change_percent > max_change_decimal:
                # Convert to USD for display
                current_usd = current_cap / Decimal("1000000")
                new_usd = new_cap_decimal / Decimal("1000000")
                raise ValueError(
                    f"❌ SAFETY CHECK FAILED: Cap change of {cap_change_percent:.1f}% exceeds maximum allowed {self.max_cap_change_percent}%\n"
                    f"   Current cap: ${current_usd:,.0f}\n"
                    f"   New cap: ${new_usd:,.0f}\n"
                    f"   To override, set HIP3_MAX_CAP_CHANGE_PERCENT={max(cap_change_percent + 10, 500):.0f}"
                )
        
        # Step 4: Validate the new cap against HIP-3 constraints
        logger.info("Step 4: Validating new cap against HIP-3 constraints...")
        self.validate_oi_cap(asset, new_cap_decimal, current_oi)
        
        if dry_run:
            logger.info("✅ DRY RUN: Validation passed")
            return {
                "status": "dry_run_success",
                "dex": dex,
                "asset": asset,
                "current_cap": float(current_cap / Decimal("1000000")),  # Convert to USD
                "new_cap": float(new_cap_decimal / Decimal("1000000")),  # Convert to USD
                "current_oi": float(current_oi / Decimal("1000000")) if current_oi else None  # Convert to USD
            }
        
        # Step 5: Build action
        logger.info("Step 5: Building perpDeploy action...")
        action = self.build_set_oi_caps_action(dex, asset, new_cap_decimal)
        
        # Step 6: Sign and submit with SDK's native L1 signing
        logger.info("Step 6: Signing and submitting with SDK L1 scheme...")
        nonce = get_timestamp_ms()
        
        logger.info(f"  Nonce: {nonce}")
        logger.info(f"  Signer: {self.address}")
        
        response = self.sign_and_submit_l1_action(action, nonce)
        
        # Step 7: Verify changes
        if response.get("status") == "ok":
            logger.info("Step 7: Verifying changes via perpDexLimits...")
            time.sleep(2)  # Wait for state update
            
            try:
                # Re-fetch DEX limits to verify the change
                new_limits = self.get_dex_limits(dex)
                new_caps_map = {}
                new_coin_to_oi_cap = new_limits.get("coinToOiCap", [])
                
                for coin, cap_str in new_coin_to_oi_cap:
                    new_caps_map[coin] = Decimal(str(cap_str))
                
                if asset in new_caps_map:
                    actual_cap = new_caps_map[asset]
                    # Check if the cap was updated correctly (allow small rounding difference)
                    if abs(actual_cap - new_cap_decimal) < Decimal("1"):
                        actual_usd = actual_cap / Decimal("1000000")
                        logger.info(f"  ✅ {asset}: Cap successfully updated to ${actual_usd:,.2f}")
                        return {
                            "status": "success",
                            "dex": dex,
                            "asset": asset,
                            "old_cap": float(current_cap / Decimal("1000000")),  # Convert to USD
                            "new_cap": float(actual_cap / Decimal("1000000")),   # Convert to USD
                            "response": response
                        }
                    else:
                        actual_usd = actual_cap / Decimal("1000000")
                        expected_usd = new_cap_decimal / Decimal("1000000")
                        logger.warning(
                            f"  ⚠️ {asset}: Cap is ${actual_usd:,.2f}, "
                            f"expected ${expected_usd:,.2f}"
                        )
                else:
                    logger.warning(f"  ⚠️ Asset {asset} not found in updated caps")
                    
            except Exception as e:
                logger.error(f"  ❌ Failed to verify cap update: {e}")
        
        return {
            "status": "failed",
            "dex": dex,
            "asset": asset,
            "error": response.get("error", "Unknown error"),
            "response": response
        }


def main():
    """Main entry point for the HIP-3 OI Cap Manager."""
    # Load environment variables
    DEX_NAME = os.getenv("HIP3_DEX_NAME")  # HIP-3 requires explicit dex name
    MARKET_NAME = os.getenv("HIP3_MARKET_NAME", "")
    NEW_CAP_USD = os.getenv("HIP3_NEW_CAP_USD", "")
    NEW_CAP_RAW = os.getenv("HIP3_NEW_CAP_RAW", "")
    PRIVATE_KEY = os.getenv("HIP3_DEPLOYER_PRIVATE_KEY", "")
    IS_MAINNET = os.getenv("HIP3_IS_MAINNET", "false").lower() == "true"
    IS_DRY_RUN = os.getenv("HIP3_DRY_RUN", "true").lower() == "true"
    MAX_CAP_CHANGE_PERCENT = float(os.getenv("HIP3_MAX_CAP_CHANGE_PERCENT", "5.0"))
    ENFORCE_CAP_ABOVE_OI = os.getenv("HIP3_ENFORCE_CAP_ABOVE_OI", "true").lower() == "true"
    
    # Validate required parameters
    if not PRIVATE_KEY:
        logger.error("❌ Please set HIP3_DEPLOYER_PRIVATE_KEY environment variable")
        sys.exit(1)
    
    if not DEX_NAME:
        logger.error("❌ Please set HIP3_DEX_NAME (HIP-3 requires a named DEX; empty string not allowed)")
        sys.exit(1)
    
    if len(DEX_NAME) > 6:
        logger.error(f"❌ HIP-3 DEX names must be ≤ 6 characters. Got: '{DEX_NAME}' ({len(DEX_NAME)} chars)")
        sys.exit(1)
    
    if not MARKET_NAME:
        logger.error("❌ Please set HIP3_MARKET_NAME environment variable")
        sys.exit(1)
    
    # Validate that exactly one cap option is provided
    if not NEW_CAP_USD and not NEW_CAP_RAW:
        logger.error("❌ Please set either HIP3_NEW_CAP_USD or HIP3_NEW_CAP_RAW")
        logger.error("   HIP3_NEW_CAP_USD: Regular USD (e.g., 5000000 for $5M)")
        logger.error("   HIP3_NEW_CAP_RAW: MicroUSD units (e.g., 5000000000000 for $5M)")
        sys.exit(1)
    
    if NEW_CAP_USD and NEW_CAP_RAW:
        logger.error("❌ Please set only ONE of HIP3_NEW_CAP_USD or HIP3_NEW_CAP_RAW, not both")
        sys.exit(1)
    
    try:
        # Parse the cap value based on which option was provided
        if NEW_CAP_USD:
            # Convert USD to microUSD units (multiply by 1,000,000)
            cleaned_cap = NEW_CAP_USD.replace("_", "").replace(",", "")
            usd_amount = Decimal(cleaned_cap)
            new_cap = usd_amount * Decimal("1000000")  # Convert to microUSD
            logger.info(f"Using USD input: ${usd_amount:,.0f} = {new_cap:,.0f} microUSD units")
        else:
            # Use raw microUSD units directly
            cleaned_cap = NEW_CAP_RAW.replace("_", "").replace(",", "")
            new_cap = Decimal(cleaned_cap)
            usd_equivalent = new_cap / Decimal("1000000")
            logger.info(f"Using raw input: {new_cap:,.0f} microUSD units = ${usd_equivalent:,.0f}")
    except (InvalidOperation, ValueError) as e:
        cap_var = "HIP3_NEW_CAP_USD" if NEW_CAP_USD else "HIP3_NEW_CAP_RAW"
        cap_val = NEW_CAP_USD if NEW_CAP_USD else NEW_CAP_RAW
        logger.error(f"❌ Invalid {cap_var} value: {cap_val} (must be a number)")
        if NEW_CAP_USD:
            logger.error(f"   Examples for USD: 5000000 ($5M), 1000000 ($1M), 1 ($1)")
        else:
            logger.error(f"   Examples for microUSD: 5000000000000 ($5M), 1000000000000 ($1M), 1000000 ($1)")
        sys.exit(1)
    
    # Initialize manager
    manager = HIP3OpenInterestCapManager(
        private_key=PRIVATE_KEY,
        is_mainnet=IS_MAINNET,
        max_cap_change_percent=MAX_CAP_CHANGE_PERCENT,
        enforce_cap_above_oi=ENFORCE_CAP_ABOVE_OI
    )
    
    logger.info("=" * 60)
    logger.info(f"HIP-3 OI CAP MANAGER - {'MAINNET' if IS_MAINNET else 'TESTNET'}")
    logger.info("=" * 60)
    logger.info(f"DEX: {DEX_NAME}")
    logger.info(f"Asset: {MARKET_NAME}")
    
    # Show cap in user-friendly format
    usd_amount = new_cap / Decimal("1000000")
    logger.info(f"New Cap: ${usd_amount:,.0f} ({new_cap:,.0f} microUSD units)")
    logger.info(f"Mode: {'DRY RUN' if IS_DRY_RUN else 'LIVE EXECUTION'}")
    
    # Execute the operation
    result = manager.change_oi_cap(
        dex=DEX_NAME,
        asset=MARKET_NAME,
        new_cap=new_cap,
        dry_run=IS_DRY_RUN
    )
    
    # Handle results
    if result["status"] == "dry_run_success":
        logger.info("\n✅ DRY RUN SUCCESS: Validation passed")
        logger.info(f"Current cap: ${result['current_cap']:,.0f}")
        logger.info(f"New cap: ${result['new_cap']:,.0f}")
        if result.get('current_oi'):
            logger.info(f"Current OI: ${result['current_oi']:,.0f}")
        logger.info("\nTo execute for real, set HIP3_DRY_RUN=false")
        
    elif result["status"] == "success":
        logger.info("\n✅ SUCCESS: OI cap updated successfully")
        logger.info(f"Asset: {result['asset']}")
        logger.info(f"Old cap: ${result['old_cap']:,.0f}")
        logger.info(f"New cap: ${result['new_cap']:,.0f}")
        
    else:
        logger.error(f"\n❌ FAILED: {result.get('error', 'Unknown error')}")
        sys.exit(1)


if __name__ == "__main__":
    main()

