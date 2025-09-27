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
import msgpack
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import keccak
from hyperliquid.info import Info
from hyperliquid.utils import constants
from hyperliquid.utils.signing import get_timestamp_ms

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
        is_mainnet: bool = True
    ):
        """
        Initialize the HIP-3 OI Cap Manager.
        
        Args:
            private_key: Deployer's private key (with 0x prefix)
            base_url: API base URL (defaults to mainnet/testnet based on is_mainnet)
            is_mainnet: Whether to use mainnet (True) or testnet (False)
        """
        self.wallet = Account.from_key(private_key)
        self.address = self.wallet.address
        self.is_mainnet = is_mainnet
        
        if base_url is None:
            self.base_url = constants.MAINNET_API_URL if is_mainnet else constants.TESTNET_API_URL
        else:
            self.base_url = base_url
            
        self.info = Info(self.base_url, skip_ws=True)
        
        logger.info(f"Initialized HIP-3 OI Cap Manager")
        logger.info(f"Deployer Address: {self.address}")
        logger.info(f"Network: {'Mainnet' if is_mainnet else 'Testnet'}")
    
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
        # Minimum cap is $1,000,000
        min_cap = Decimal("1000000")
        
        # If current OI is available, also check 0.5 * current_oi constraint
        if current_oi is not None:
            half_oi = current_oi * Decimal("0.5")
            if half_oi > min_cap:
                min_cap = half_oi
            logger.info(f"  Current OI: ${current_oi:,.2f}, Half OI: ${half_oi:,.2f}")
        else:
            logger.warning(f"  Current OI unavailable for {asset}, using $1M minimum only")
            logger.warning(f"  Server will still enforce 0.5 * current OI constraint")
        
        if new_cap < min_cap:
            raise ValueError(
                f"Invalid OI cap for {asset}: ${new_cap:,.0f} < minimum ${min_cap:,.0f} "
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

    def action_hash(self, action: Dict, vault_address: Optional[str], nonce: int, expires_after: Optional[int]) -> bytes:
        """
        Create hash of the action for L1 signing.
        
        Args:
            action: The action dictionary
            vault_address: Vault address (None for master EOA)
            nonce: Nonce timestamp
            expires_after: Expiration timestamp (optional)
            
        Returns:
            The action hash
        """
        data = msgpack.packb(action)
        data += nonce.to_bytes(8, "big")
        
        if vault_address is not None:
            data += bytes.fromhex(vault_address[2:] if vault_address.startswith("0x") else vault_address)
            
        if expires_after is not None:
            data += expires_after.to_bytes(8, "big")
            
        return keccak(data)
    
    def construct_phantom_agent(self, hash: bytes) -> Dict:
        """
        Construct phantom agent for L1 signing.
        Args:
            hash: The action hash   
        Returns:
            Phantom agent dictionary
        """
        return {
            "source": "a" if self.is_mainnet else "b",
            "connectionId": "0x" + hash.hex(),  # hex string for bytes32
        }
    
    def l1_payload(self, phantom_agent: Dict) -> Dict:
        """
        Create L1 payload for EIP-712 signing.
        Args:
            phantom_agent: The phantom agent dictionary    
        Returns:
            The L1 payload for signing
        """
        return {
            "domain": {
                "chainId": 1337,  # Critical: must be 1337 for L1 actions
                "name": "Exchange",  # CRITICAL: Must be "Exchange" not "HyperliquidL1"
                "version": "1",
                "verifyingContract": "0x0000000000000000000000000000000000000000",
            },
            "types": {
                "Agent": [
                    {"name": "source", "type": "string"},
                    {"name": "connectionId", "type": "bytes32"},
                ],
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                ],
            },
            "primaryType": "Agent",
            "message": phantom_agent,
        }
    
    def sign_l1_action(
        self,
        action: Dict,
        nonce: int,
        vault_address: Optional[str] = None,
        expires_after: Optional[int] = None
    ) -> Dict:
        """
        Sign an L1 action using EOA.
        Args:
            action: The action to sign
            nonce: Nonce timestamp
            vault_address: Vault address (None for master EOA)
            expires_after: Expiration timestamp (optional)
            
        Returns:
            Signature dictionary with r, s, v
        """
        # Create action hash
        hash = self.action_hash(action, vault_address, nonce, expires_after)
        
        # Construct phantom agent
        phantom_agent = self.construct_phantom_agent(hash)
        
        # Create L1 payload
        data = self.l1_payload(phantom_agent)
        
        # Sign using EIP-712
        structured_data = encode_typed_data(full_message=data)
        signed_message = self.wallet.sign_message(structured_data)
        
        return {
            "r": "0x" + signed_message.r.to_bytes(32, byteorder='big').hex(),
            "s": "0x" + signed_message.s.to_bytes(32, byteorder='big').hex(),
            "v": signed_message.v
        }
    
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
            "signature": signature,
            "vaultAddress": vault_address,
            "expiresAfter": expires_after
        }
        
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
        
        # Optional: Validate DEX exists first (recommended for better error messages)
        if dex != "":  # Don't check for default DEX
            try:
                perp_dexs_resp = self.info.post("/info", {"type": "perpDexs"})
                if isinstance(perp_dexs_resp, list):
                    dex_names = []
                    for entry in perp_dexs_resp:
                        if isinstance(entry, dict):
                            name = entry.get("name")
                            if isinstance(name, str) and name != "":
                                dex_names.append(name)
                    if dex not in dex_names:
                        logger.error(f"DEX '{dex}' not found. Available HIP-3 DEXs: {dex_names}")
                        raise ValueError(f"DEX '{dex}' does not exist")
            except Exception as e:
                logger.warning(f"Could not validate DEX existence: {e}")
                # Continue anyway as this is just a validation check
        
        # Step 1: Read current DEX limits (contains OI caps)
        logger.info("Step 1: Reading current DEX limits and OI caps...")
        try:
            limits = self.get_dex_limits(dex)
        except Exception as e:
            raise ValueError(f"Failed to get DEX limits for {dex}: {e}")
        
        # Parse current caps from coinToOiCap array
        caps_map = {}
        coin_to_oi_cap = limits.get("coinToOiCap", [])
        for coin, cap_str in coin_to_oi_cap:
            caps_map[coin] = Decimal(str(cap_str))
        
        if asset not in caps_map:
            raise ValueError(f"Asset {asset} not found in DEX {dex}. Available assets: {list(caps_map.keys())}")
        
        current_cap = caps_map[asset]
        
        # Step 2: Try to get current OI 
        logger.info("Step 2: Fetching current open interest...")
        current_oi = None
        
        # Since metaAndAssetCtxs doesn't support dex parameter in current SDK,
        # we'll get meta for this DEX and check if it's the default DEX
        try:
            meta = self.get_meta(dex)
            universe = meta.get("universe", [])
            
            # Check if this asset exists in this DEX
            asset_found = False
            for asset_info in universe:
                if isinstance(asset_info, dict) and asset_info.get("name") == asset:
                    asset_found = True
                    break
            
            if not asset_found:
                raise ValueError(f"Asset {asset} not found in DEX {dex}")
            
            # If this is the default DEX (empty string), we can get OI from metaAndAssetCtxs
            if dex == "":
                meta_and_ctxs = self.get_meta_and_asset_ctxs()
                if meta_and_ctxs is not None:
                    meta_default, contexts = meta_and_ctxs
                    universe_default = meta_default.get("universe", [])
                    
                    # Build name to index mapping
                    name_to_idx = {}
                    for i, asset_info in enumerate(universe_default):
                        if isinstance(asset_info, dict):
                            name_to_idx[asset_info.get("name")] = i
                            
                    # Find the asset's context
                    if asset in name_to_idx:
                        idx = name_to_idx[asset]
                        if idx < len(contexts):
                            oi_str = contexts[idx].get("openInterest", "0")
                            current_oi = Decimal(str(oi_str))
            else:
                # For HIP-3 DEXs, we can't get current OI from SDK
                # This is a limitation of the current SDK
                logger.warning(f"Cannot get current OI for HIP-3 DEX {dex} with current SDK")
                logger.warning(f"Will rely on server-side validation of 0.5 * current OI constraint")
        except Exception as e:
            logger.warning(f"Could not fetch current OI: {e}")
            logger.warning(f"Will rely on server-side validation")
        
        logger.info(f"  Asset: {asset}")
        if current_oi is not None:
            logger.info(f"  Current OI: ${current_oi:,.2f}")
        else:
            logger.info(f"  Current OI: Unable to fetch (will rely on server validation)")
        logger.info(f"  Current Cap: ${current_cap:,.2f}")
        logger.info(f"  New Cap: ${new_cap_decimal:,.2f}")
        
        # Step 3: Validate the new cap
        logger.info("Step 3: Validating new cap against constraints...")
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
        
        # Step 4: Build action
        logger.info("Step 4: Building perpDeploy action...")
        action = self.build_set_oi_caps_action(dex, asset, new_cap_decimal)
        
        # Step 5: Sign with EOA (L1 signing)
        logger.info("Step 5: Signing with EOA (L1 scheme)...")
        nonce = get_timestamp_ms()
        signature = self.sign_l1_action(action, nonce)
        
        logger.info(f"  Nonce: {nonce}")
        logger.info(f"  Signer: {self.address}")
        
        # Step 6: Submit to exchange
        logger.info("Step 6: Submitting to exchange...")
        response = self.submit_action(action, nonce, signature)
        
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
    """Main function to run the OI cap manager for a single market."""
    
    # Load configuration from environment variables
    MARKET_NAME = os.getenv("HIP3_MARKET_NAME")
    IS_DRY_RUN = os.getenv("HIP3_DRY_RUN", "false").lower() == "true"
    NEW_CAP_FOR_MARKET = os.getenv("HIP3_NEW_CAP")
    PRIVATE_KEY = os.getenv("HIP3_DEPLOYER_PRIVATE_KEY")
    DEX_NAME = os.getenv("HIP3_DEX_NAME", "MYDEX")
    IS_MAINNET = os.getenv("HIP3_IS_MAINNET", "false").lower() == "true"
    
    # Validate required parameters
    if not PRIVATE_KEY:
        logger.error("❌ Please set HIP3_DEPLOYER_PRIVATE_KEY environment variable")
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
        is_mainnet=IS_MAINNET
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

