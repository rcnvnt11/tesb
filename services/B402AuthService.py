"""Service class for handling B402.ai authentication workflow"""
import requests
import json
import time
import base64
from web3 import Web3
from eth_account import Account
from eth_account.messages import encode_defunct
from typing import Dict, List, Optional
import secrets


class B402AuthService:
    """Service class for B402.ai authentication with wallet and email verification"""

    def __init__(self, nocaptcha_token: str):
        """
        Initialize the B402 authentication service

        Args:
            nocaptcha_token (str): API token for nocaptcha.io service
        """
        self.base_url = "https://www.b402.ai/api/api/v1"
        self.nocaptcha_token = nocaptcha_token
        self.nocaptcha_url = "http://api.nocaptcha.io/api/wanda/cloudflare/universal"
        self.sitekey = "0x4AAAAAAB5QdBYvpAN8f8ZI"
        self.client_id = "b402-s7chg25x"
        self.w3 = Web3()
        

        # Enable unaudited HD wallet features
        Account.enable_unaudited_hdwallet_features()

    def generate_wallet(self) -> Dict[str, str]:
        """
        Generate a new Ethereum wallet

        Returns:
            dict: Dictionary containing address and privateKey
        """
        # Generate random private key
        private_key = "0x" + secrets.token_hex(32)
        account = Account.from_key(private_key)

        return {
            "address": account.address,
            "privateKey": private_key
        }

    def get_captcha_token(self, proxy: Optional[str] = None) -> str:
        """
        Get captcha token from nocaptcha.io service

        Args:
            proxy (str, optional): Proxy in format usr:pwd@ip:port

        Returns:
            str: Turnstile token for captcha bypass

        Raises:
            Exception: If captcha solving fails
        """
        headers = {
            "User-Token": self.nocaptcha_token,
            "Content-Type": "application/json"
        }

        payload = {
            "href": "https://www.b402.ai/experience-b402",
            "sitekey": self.sitekey
        }

        if proxy:
            payload["proxy"] = proxy

        print("🔄 Solving captcha...")
        response = requests.post(self.nocaptcha_url, headers=headers, json=payload)

        if response.status_code != 200:
            raise Exception(f"Captcha API request failed: {response.status_code}")

        result = response.json()

        if result.get("status") != 1:
            raise Exception(f"Captcha solving failed: {result.get('msg', 'Unknown error')}")

        token = result.get("data", {}).get("token")
        if not token:
            raise Exception("No token received from captcha service")

        print(f"✅ Captcha solved in {result.get('cost', 'N/A')}")
        return token

    def generate_lid(self) -> str:
        """
        Generate a session lid (similar to UUID v4)

        Returns:
            str: Generated lid string
        """
        import uuid
        return str(uuid.uuid4())

    def get_nonce(self, wallet_address: str, turnstile_token: str, lid: str) -> Dict[str, str]:
        """
        Get nonce for wallet signing

        Args:
            wallet_address (str): Ethereum wallet address
            turnstile_token (str): Cloudflare turnstile token
            lid (str): Session lid

        Returns:
            dict: Dictionary containing nonce and message

        Raises:
            Exception: If nonce request fails
        """
        url = f"{self.base_url}/auth/web3/challenge"

        headers = {
            "Content-Type": "application/json",
            "ngrok-skip-browser-warning": "true",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
        }

        payload = {
            "walletType": "evm",
            "walletAddress": wallet_address,
            "turnstileToken": turnstile_token,
            "lid": lid,
            "clientId": self.client_id
        }

        print(f"🔄 Getting nonce for wallet {wallet_address}...")
        response = requests.post(url, headers=headers, json=payload)

        if response.status_code != 200:
            raise Exception(f"Nonce request failed: {response.status_code} - {response.text}")

        result = response.json()
        print(f"✅ Nonce received: {result.get('nonce')}")
        return result

    def sign_message(self, message: str, private_key: str) -> str:
        """
        Sign a message with private key

        Args:
            message (str): Message to sign (nonce)
            private_key (str): Wallet private key

        Returns:
            str: Signed message signature
        """
        account = Account.from_key(private_key)

        # Create the message to sign
        signable_message = f"unique nonce {message}"

        # Encode the message for signing
        encoded_message = encode_defunct(text=signable_message)
        
        # Sign the message
        signed_message = account.sign_message(encoded_message)

        return signed_message.signature.hex()

    def extract_code_from_otp(self, otp_token: str) -> str:
        """
        Extract verification code from base64 encoded OTP token

        Args:
            otp_token (str): Base64 encoded OTP token

        Returns:
            str: 6-digit verification code

        Raises:
            Exception: If code extraction fails
        """
        try:
            # Decode base64
            decoded = base64.b64decode(otp_token).decode('utf-8')
            # Format: email:code:timestamp:hash1:hash2
            # Example: genia2d2adc@wn.chessgameland.com:642447:1762960096:33727f99bb22bfc09c720a42dc3f3030:da3a2e35418a2dcca441e8dd5b9ce3f99bbcafbb7e7131f333f33992f3b48c77
            parts = decoded.split(':')
            if len(parts) >= 2:
                code = parts[1]
                print(f"✅ Extracted verification code from OTP: {code}")
                return code
            else:
                raise Exception(f"Invalid OTP format: {decoded}")
        except Exception as e:
            raise Exception(f"Failed to extract code from OTP: {str(e)}")

    def verify_email(
        self,
        wallet_address: str,
        signature: str,
        email: str,
        lid: str
    ) -> Dict[str, str]:
        """
        Verify email and get OTP token

        Args:
            wallet_address (str): Ethereum wallet address
            signature (str): Signed nonce
            email (str): Email address
            lid (str): Session lid

        Returns:
            dict: Dictionary containing otp token

        Raises:
            Exception: If verification fails
        """
        url = f"{self.base_url}/auth/web3/verify"

        headers = {
            "Content-Type": "application/json",
            "ngrok-skip-browser-warning": "true",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
        }

        payload = {
            "walletType": "evm",
            "walletAddress": wallet_address,
            "signature": signature,
            "email": email,
            "lid": lid,
            "clientId": self.client_id
        }

        print(f"🔄 Verifying email {email}...")
        response = requests.post(url, headers=headers, json=payload)

        if response.status_code != 200:
            raise Exception(f"Email verification failed: {response.status_code} - {response.text}")

        result = response.json()
        print(f"✅ OTP token received")
        return result

    def callback_verification(
        self,
        email: str,
        verification_code: str,
        otp_token: str,
        wallet_address: str,
        lid: str
    ) -> Dict[str, str]:
        """
        Complete verification with email code

        Args:
            email (str): Email address
            verification_code (str): 6-digit code from email
            otp_token (str): OTP token from verify step
            wallet_address (str): Ethereum wallet address
            lid (str): Session lid

        Returns:
            dict: Dictionary containing jwt and refreshToken

        Raises:
            Exception: If callback verification fails
        """
        url = f"{self.base_url}/auth/web3/callback"

        headers = {
            "Content-Type": "application/json",
            "ngrok-skip-browser-warning": "true",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
        }

        payload = {
            "email": email,
            "verificationCode": verification_code,
            "token": otp_token,
            "walletType": "evm",
            "walletAddress": wallet_address,
            "lid": lid,
            "clientId": self.client_id
        }

        print(f"🔄 Completing verification with code {verification_code}...")
        response = requests.post(url, headers=headers, json=payload)

        if response.status_code != 200:
            raise Exception(f"Callback verification failed: {response.status_code} - {response.text}")

        result = response.json()
        print(f"✅ JWT token received!")
        return result

    def check_user_status(self, jwt_token: str) -> Dict[str, bool]:
        """
        Check user status with JWT token

        Args:
            jwt_token (str): JWT authentication token

        Returns:
            dict: Dictionary containing user status (x, discord, hasMinted)

        Raises:
            Exception: If status check fails
        """
        url = f"{self.base_url}/auth/user-status"

        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "ngrok-skip-browser-warning": "true",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
        }

        print("🔄 Checking user status...")
        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            raise Exception(f"Status check failed: {response.status_code} - {response.text}")

        result = response.json()
        print(f"✅ User status: {result}")
        return result

    def complete_auth_flow(
        self,
        email: str,
        verification_code: str,
        proxy: Optional[str] = None
    ) -> Dict[str, any]:
        """
        Complete full authentication flow

        Args:
            email (str): Email address to use
            verification_code (str): 6-digit verification code from email
            proxy (str, optional): Proxy for captcha solving

        Returns:
            dict: Complete result with wallet, jwt, and user info

        Raises:
            Exception: If any step fails
        """
        print("\n" + "="*60)
        print("🚀 Starting B402.ai Authentication Flow")
        print("="*60 + "\n")

        # Step 1: Generate wallet
        print("📝 Step 1: Generating wallet...")
        wallet = self.generate_wallet()
        print(f"✅ Wallet generated: {wallet['address']}\n")

        # Step 2: Generate lid
        lid = self.generate_lid()
        print(f"🔑 Session LID: {lid}\n")

        # Step 3: Get captcha token
        print("📝 Step 2: Getting captcha token...")
        turnstile_token = self.get_captcha_token(proxy)
        print()

        # Step 4: Get nonce
        print("📝 Step 3: Getting nonce...")
        nonce_result = self.get_nonce(wallet['address'], turnstile_token, lid)
        nonce = nonce_result['nonce']
        print()

        # Step 5: Sign nonce
        print("📝 Step 4: Signing nonce...")
        signature = self.sign_message(nonce, wallet['privateKey'])
        print(f"✅ Signature: {signature}\n")

        # Step 6: Verify email
        print("📝 Step 5: Verifying email...")
        verify_result = self.verify_email(
            wallet['address'],
            signature,
            email,
            lid
        )
        otp_token = verify_result['otp']
        print()

        # Step 7: Complete verification
        print("📝 Step 6: Completing verification...")
        auth_result = self.callback_verification(
            email,
            verification_code,
            otp_token,
            wallet['address'],
            lid
        )
        print()

        # Step 8: Check user status
        print("📝 Step 7: Checking user status...")
        user_status = self.check_user_status(auth_result['jwt'])
        print()

        print("="*60)
        print("✅ Authentication Flow Completed Successfully!")
        print("="*60 + "\n")

        return {
            "wallet": wallet,
            "lid": lid,
            "email": email,
            "jwt": auth_result['jwt'],
            "refreshToken": auth_result['refreshToken'],
            "userStatus": user_status
        }

    def complete_auth_flow_auto(
        self,
        email: str,
        proxy: Optional[str] = None
    ) -> Dict[str, any]:
        """
        Complete full authentication flow with automatic code extraction from OTP
        No need to wait for email - code is embedded in OTP response

        Args:
            email (str): Email address to use
            proxy (str, optional): Proxy for captcha solving

        Returns:
            dict: Complete result with wallet, jwt, and user info

        Raises:
            Exception: If any step fails
        """
        print("\n" + "="*60)
        print("🚀 Starting B402.ai Authentication Flow (Auto Mode)")
        print("="*60 + "\n")

        # Step 1: Generate wallet
        print("📝 Step 1: Generating wallet...")
        wallet = self.generate_wallet()
        print(f"✅ Wallet generated: {wallet['address']}\n")

        # Step 2: Generate lid
        lid = self.generate_lid()
        print(f"🔑 Session LID: {lid}\n")

        # Step 3: Get captcha token
        print("📝 Step 2: Getting captcha token...")
        turnstile_token = self.get_captcha_token(proxy)
        print()

        # Step 4: Get nonce
        print("📝 Step 3: Getting nonce...")
        nonce_result = self.get_nonce(wallet['address'], turnstile_token, lid)
        nonce = nonce_result['nonce']
        print()

        # Step 5: Sign nonce
        print("📝 Step 4: Signing nonce...")
        signature = self.sign_message(nonce, wallet['privateKey'])
        print(f"✅ Signature: {signature}\n")

        # Step 6: Verify email
        print("📝 Step 5: Verifying email...")
        verify_result = self.verify_email(
            wallet['address'],
            signature,
            email,
            lid
        )
        otp_token = verify_result['otp']
        print()

        # Step 7: Extract verification code from OTP (bypass email check!)
        print("📝 Step 6: Extracting verification code from OTP...")
        verification_code = self.extract_code_from_otp(otp_token)
        print()

        # Step 8: Complete verification
        print("📝 Step 7: Completing verification...")
        auth_result = self.callback_verification(
            email,
            verification_code,
            otp_token,
            wallet['address'],
            lid
        )
        print()

        # Step 9: Check user status
        print("📝 Step 8: Checking user status...")
        user_status = self.check_user_status(auth_result['jwt'])
        print()

        print("="*60)
        print("✅ Authentication Flow Completed Successfully!")
        print("="*60 + "\n")

        return {
            "wallet": wallet,
            "lid": lid,
            "email": email,
            "verificationCode": verification_code,
            "jwt": auth_result['jwt'],
            "refreshToken": auth_result['refreshToken'],
            "userStatus": user_status
        }
