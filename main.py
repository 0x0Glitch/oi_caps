#!/usr/bin/env python3
"""
HIP-3 Cap Changing Script
Uses deployer EOA for L1 action signing with proper constraint validation.

CRITICAL SPECIFICATIONS (Accoring to official docs):
• OI caps are USD NOTIONAL values (position_size × mark_price)
• Minimum constraint: max($1,000,000, 50% of current OI)
• SetOpenInterestCaps: Array<[asset_name, cap_usd_notional]> (alphabetically sorted)

ENVIRONMENT VARIABLES:
• HIP3_DEPLOYER_PRIVATE_KEY - Deployer's private key (required)
• HIP3_DEX_NAME - Target DEX name (default: "MYDEX")
• HIP3_MARKET_NAME - Asset to update (required)
• HIP3_NEW_CAP - New cap in USD notional (required)
• HIP3_DRY_RUN - "true" for validation only (default: "false")
• HIP3_IS_MAINNET - "true" for mainnet, "false" for testnet

TECHNICAL DETAILS:
• L1 signing with chain ID 1337 (EOA direct)
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
        enforce_cap_above_oi: bool = False
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
        
        # Minimum cap is $1,000,000
        min_cap = Decimal("1000000")
        
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
            logger.warning(f"  Current OI unavailable for {asset}, using $1M minimum only")
            logger.warning(f"  Server will still enforce current OI constraint")
        
        if new_cap < min_cap:
            raise ValueError(
                f"Invalid OI cap for {asset}: ${new_cap:,.0f} < minimum ${min_cap:,.0f}"
            )
        
        logger.info(f"✅ Valid OI cap for {asset}: ${new_cap:,.0f} (min: ${min_cap:,.0f})")
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
        
        logger.info(f"Built setOpenInterestCaps action for {asset} on DEX {dex}: ${cap_int:,}")
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
        # Use SDK's native sign_l1_action function
        signature = sign_l1_action(
            wallet=self.wallet,
            action=action,
            active_pool=None,  # No vault address for HIP-3 actions
            nonce=nonce,
            expires_after=None,  # No expiration for HIP-3 actions
            is_mainnet=self.is_mainnet
        )
        
        # Build the payload (omit null fields)
        payload = {
            "action": action,
            "nonce": nonce,
            "signature": signature
        }
        # Don't include vaultAddress or expiresAfter if they're None
        
        # Submit to exchange endpoint
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
            vault_address: Vault address (optional)
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
        if vault_address is not None:
            payload["vaultAddress"] = vault_address
        if expires_after is not None:
            payload["expiresAfter"] = expires_after
        
        # Don't log sensitive signature data
        safe_payload = payload.copy()
        if "signature" in safe_payload:
            safe_payload["signature"] = {"r": "0x...", "s": "0x...", "v": "..."}
        logger.debug(f"Payload (masked): {json.dumps(safe_payload, indent=2)}")
        
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
        
        # Enforce integral notional to avoid silent truncation
        if new_cap_decimal != new_cap_decimal.to_integral_value():
            raise ValueError("HIP-3 OI caps must be whole-dollar integers.")
        
        # MANDATORY: Validate DEX exists (CRASH ON FAILURE)
        if dex != "":  # Don't check for default DEX
            # Query perpDexs to validate DEX exists - MUST succeed
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
        
        # If this is the default DEX (empty string), we MUST get OI from metaAndAssetCtxs
        if dex == "":
            meta_and_ctxs = self.get_meta_and_asset_ctxs()
            if meta_and_ctxs is None:
                raise RuntimeError(f"❌ FAILED to get metaAndAssetCtxs for default DEX - cannot proceed")
                
            meta_default, contexts = meta_and_ctxs
            universe_default = meta_default.get("universe", [])
            
            if not universe_default:
                raise RuntimeError(f"❌ Default DEX has no universe - corrupt data")
            
            if not contexts:
                raise RuntimeError(f"❌ No asset contexts available - cannot get current OI")
            
            # Build name to index mapping
            name_to_idx = {}
            for i, asset_info in enumerate(universe_default):
                if not isinstance(asset_info, dict):
                    raise RuntimeError(f"❌ Invalid asset info at index {i} - not a dict")
                asset_name = asset_info.get("name")
                if not asset_name:
                    raise RuntimeError(f"❌ Invalid asset info at index {i} - no name")
                name_to_idx[asset_name] = i
                    
            # Find the asset's context - MUST exist
            if asset not in name_to_idx:
                raise RuntimeError(f"❌ Asset '{asset}' not found in default DEX context mapping")
                
            idx = name_to_idx[asset]
            if idx >= len(contexts):
                raise RuntimeError(f"❌ Asset index {idx} out of range (contexts length: {len(contexts)})")
                
            # Get OI data - MUST have valid data
            asset_context = contexts[idx]
            if not asset_context:
                raise RuntimeError(f"❌ Null context for asset '{asset}' at index {idx}")
                
            oi_size_str = asset_context.get("openInterest")
            mark_px_str = asset_context.get("markPx")
            
            if oi_size_str is None:
                raise RuntimeError(f"❌ No openInterest data for '{asset}' - cannot proceed")
            if mark_px_str is None:
                raise RuntimeError(f"❌ No markPx data for '{asset}' - cannot proceed")
            
            # Convert to USD notional - MUST be valid numbers
            try:
                oi_size = Decimal(str(oi_size_str))
                mark_px = Decimal(str(mark_px_str))
            except Exception as e:
                raise RuntimeError(f"❌ Invalid numeric data: OI='{oi_size_str}', markPx='{mark_px_str}' - {e}")
            
            if mark_px <= 0:
                raise RuntimeError(f"❌ Invalid mark price: ${mark_px} - must be > 0")
            
            # Convert position size to USD notional
            current_oi = oi_size * mark_px
            logger.info(f"  ✅ OI size: {oi_size}, Mark price: ${mark_px}, USD notional: ${current_oi:,.2f}")
        else:
            # For HIP-3 builder DEXs, metaAndAssetCtxs cannot scope by dex; rely on server-side constraint checks
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
        logger.info(f"  New Cap: ${new_cap_decimal:,.2f}")
        
        # Step 3: Safety check - prevent excessive cap changes
        logger.info("Step 3: Performing safety checks...")
        if current_cap > Decimal("0"):
            cap_change_percent = abs((new_cap_decimal - current_cap) / current_cap * 100)
            logger.info(f"  Cap change: {cap_change_percent:.1f}%")
            
            # Convert max_cap_change_percent to Decimal for comparison
            max_change_decimal = Decimal(str(self.max_cap_change_percent))
            if cap_change_percent > max_change_decimal:
                raise ValueError(
                    f"❌ SAFETY CHECK FAILED: Cap change of {cap_change_percent:.1f}% exceeds maximum allowed {self.max_cap_change_percent}%\n"
                    f"   Current cap: ${current_cap:,.0f}\n"
                    f"   New cap: ${new_cap_decimal:,.0f}\n"
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
                "current_cap": float(current_cap),
                "new_cap": float(new_cap_decimal),
                "current_oi": float(current_oi) if current_oi else None
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
                        logger.info(f"  ✅ {asset}: Cap successfully updated to ${actual_cap:,.2f}")
                        return {
                            "status": "success",
                            "dex": dex,
                            "asset": asset,
                            "old_cap": float(current_cap),
                            "new_cap": float(actual_cap),
                            "response": response
                        }
                    else:
                        logger.warning(
                            f"  ⚠️ {asset}: Cap is ${actual_cap:,.2f}, "
                            f"expected ${new_cap_decimal:,.2f}"
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
    NEW_CAP_FOR_MARKET = os.getenv("HIP3_NEW_CAP", "")
    PRIVATE_KEY = os.getenv("HIP3_DEPLOYER_PRIVATE_KEY", "")
    IS_MAINNET = os.getenv("HIP3_IS_MAINNET", "false").lower() == "true"
    IS_DRY_RUN = os.getenv("HIP3_DRY_RUN", "true").lower() == "true"
    MAX_CAP_CHANGE_PERCENT = float(os.getenv("HIP3_MAX_CAP_CHANGE_PERCENT", "200.0"))
    ENFORCE_CAP_ABOVE_OI = os.getenv("HIP3_ENFORCE_CAP_ABOVE_OI", "false").lower() == "true"
    
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
        
    if not NEW_CAP_FOR_MARKET:
        logger.error("❌ Please set HIP3_NEW_CAP environment variable")
        sys.exit(1)
    
    try:
        # Support underscores (1_000_000) and scientific notation (1e6) with exact Decimal parsing
        cleaned_cap = NEW_CAP_FOR_MARKET.replace("_", "").replace(",", "")
        new_cap = Decimal(cleaned_cap)
    except (InvalidOperation, ValueError):
        logger.error(f"❌ Invalid HIP3_NEW_CAP value: {NEW_CAP_FOR_MARKET} (must be a number)")
        logger.error(f"   Examples: 1000000, 1_000_000, 1e6")
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
    logger.info(f"New Cap: ${new_cap:,.0f}")
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

