"""Bulk account generator for B402.ai with wallet and email automation"""
import json
import time
from services.B402AuthService import B402AuthService
from services.EmailService import EmailService
from typing import List, Dict
import re


class B402BulkGenerator:
    """Handles bulk generation of B402.ai accounts"""

    def __init__(self, nocaptcha_token: str, tempmail_api_key: str = None):
        """
        Initialize the bulk generator

        Args:
            nocaptcha_token (str): API token for nocaptcha.io
            tempmail_api_key (str, optional): API key for tempmail.lol
        """
        self.auth_service = B402AuthService(nocaptcha_token)
        self.email_service = EmailService(tempmail_api_key)
        self.results = []

    def wait_for_verification_code(self, inbox_token: str, timeout: int = 300) -> str:
        """
        Wait for verification code email and extract the code

        Args:
            inbox_token (str): Token for the temporary inbox
            timeout (int): Maximum time to wait in seconds (default 5 minutes)

        Returns:
            str: 6-digit verification code

        Raises:
            Exception: If code not received within timeout
        """
        print("📧 Waiting for verification code email...")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                emails = self.email_service.check_inbox(inbox_token)
                
                if emails and len(emails) > 0:
                    # Look for verification code in the most recent email
                    for email in emails:
                        subject = email.get('subject', '')
                        body_text = email.get('body_text', '')
                        body_html = email.get('body_html', '')
                        
                        # Combine all text to search
                        full_text = f"{subject} {body_text} {body_html}"
                        
                        # Search for 6-digit code
                        code_match = re.search(r'\b(\d{6})\b', full_text)
                        if code_match:
                            code = code_match.group(1)
                            print(f"✅ Verification code found: {code}")
                            return code
                
                # Wait before checking again
                time.sleep(5)
                print("⏳ Still waiting for email...")
                
            except Exception as e:
                print(f"⚠️ Error checking inbox: {str(e)}")
                time.sleep(5)
        
        raise Exception(f"Verification code not received within {timeout} seconds")

    def generate_single_account(
        self, 
        account_number: int, 
        proxy: str = None
    ) -> Dict[str, any]:
        """
        Generate a single B402.ai account with automatic code extraction from OTP

        Args:
            account_number (int): Account number for logging
            proxy (str, optional): Proxy for captcha solving

        Returns:
            dict: Account details including wallet, email, and auth tokens

        Raises:
            Exception: If account generation fails
        """
        print("\n" + "="*70)
        print(f"🎯 Generating Account #{account_number}")
        print("="*70 + "\n")

        try:
            # Step 1: Create temporary email
            print("📧 Creating temporary email...")
            inbox = self.email_service.create_inbox()
            email = inbox.address
            inbox_token = inbox.token
            print(f"✅ Email created: {email}\n")

            # Step 2: Generate wallet
            print("💼 Generating wallet...")
            wallet = self.auth_service.generate_wallet()
            print(f"✅ Wallet: {wallet['address']}\n")

            # Step 3: Generate lid
            lid = self.auth_service.generate_lid()
            print(f"🔑 Session LID: {lid}\n")

            # Step 4: Get captcha token
            print("🤖 Solving captcha...")
            turnstile_token = self.auth_service.get_captcha_token(proxy)
            print()

            # Step 5: Get nonce
            print("🔐 Getting nonce...")
            nonce_result = self.auth_service.get_nonce(
                wallet['address'], 
                turnstile_token, 
                lid
            )
            nonce = nonce_result['nonce']
            print()

            # Step 6: Sign nonce
            print("✍️ Signing nonce...")
            signature = self.auth_service.sign_message(nonce, wallet['privateKey'])
            print(f"✅ Signature generated\n")

            # Step 7: Send verification email
            print("📤 Sending verification request...")
            verify_result = self.auth_service.verify_email(
                wallet['address'],
                signature,
                email,
                lid
            )
            otp_token = verify_result['otp']
            print()

            # Step 8: Extract verification code from OTP (no email wait needed!)
            print("🔓 Extracting verification code from OTP...")
            verification_code = self.auth_service.extract_code_from_otp(otp_token)
            print()

            # Step 9: Complete verification
            print("✅ Completing verification...")
            auth_result = self.auth_service.callback_verification(
                email,
                verification_code,
                otp_token,
                wallet['address'],
                lid
            )
            print()

            # Step 10: Check user status
            print("📊 Checking user status...")
            user_status = self.auth_service.check_user_status(auth_result['jwt'])
            print()

            result = {
                "accountNumber": account_number,
                "wallet": wallet,
                "email": email,
                "lid": lid,
                "verificationCode": verification_code,
                "jwt": auth_result['jwt'],
                "refreshToken": auth_result['refreshToken'],
                "userStatus": user_status,
                "status": "completed"
            }

            print("="*70)
            print(f"✅ Account #{account_number} Generated Successfully!")
            print("="*70 + "\n")

            return result

        except Exception as e:
            print(f"❌ Failed to generate account #{account_number}: {str(e)}\n")
            return {
                "accountNumber": account_number,
                "status": "failed",
                "error": str(e)
            }

    def generate_bulk_accounts(
        self,
        count: int,
        proxy: str = None,
        delay_between: int = 5,
        output_file: str = "b402_accounts.json"
    ) -> List[Dict[str, any]]:
        """
        Generate multiple B402.ai accounts with automatic verification

        Args:
            count (int): Number of accounts to generate
            proxy (str, optional): Proxy for captcha solving
            delay_between (int): Delay between accounts in seconds
            output_file (str): JSON file to save results

        Returns:
            list: List of generated account details
        """
        print("\n" + "🌟"*35)
        print(f"🚀 B402.ai Bulk Account Generator (Auto Mode)")
        print(f"📊 Target: {count} accounts")
        print(f"🔥 No email waiting required - instant verification!")
        print("🌟"*35 + "\n")

        results = []
        successful = 0
        failed = 0

        for i in range(1, count + 1):
            result = self.generate_single_account(i, proxy)
            results.append(result)

            if result['status'] == 'completed':
                successful += 1
            elif result['status'] == 'failed':
                failed += 1

            # Save progress after each account
            self.save_results(results, output_file)

            # Delay between accounts (except for last one)
            if i < count:
                print(f"⏳ Waiting {delay_between} seconds before next account...\n")
                time.sleep(delay_between)

        # Final summary
        print("\n" + "="*70)
        print("📊 GENERATION SUMMARY")
        print("="*70)
        print(f"✅ Successful: {successful}/{count}")
        print(f"❌ Failed: {failed}/{count}")
        print(f"💾 Results saved to: {output_file}")
        print("="*70 + "\n")

        return results

    def save_results(self, results: List[Dict], filename: str):
        """
        Save results to JSON file

        Args:
            results (list): List of account results
            filename (str): Output filename
        """
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

    def complete_manual_verification(
        self,
        email: str,
        verification_code: str,
        otp_token: str,
        wallet_address: str,
        lid: str
    ) -> Dict[str, any]:
        """
        Complete verification for accounts in manual mode

        Args:
            email (str): Email address
            verification_code (str): 6-digit code from email
            otp_token (str): OTP token from verify step
            wallet_address (str): Wallet address
            lid (str): Session lid

        Returns:
            dict: JWT token and user status
        """
        print(f"\n🔄 Completing manual verification for {email}...")
        
        # Complete verification
        auth_result = self.auth_service.callback_verification(
            email,
            verification_code,
            otp_token,
            wallet_address,
            lid
        )

        # Check user status
        user_status = self.auth_service.check_user_status(auth_result['jwt'])

        return {
            "jwt": auth_result['jwt'],
            "refreshToken": auth_result['refreshToken'],
            "userStatus": user_status
        }


def main():
    """Main function to run the bulk generator"""
    print("\n🎮 B402.ai Bulk Account Generator (Auto Mode)")
    print("="*50)
    print("🔥 Instant verification - no email waiting!")
    print("="*50 + "\n")
    
    # Configuration
    NOCAPTCHA_TOKEN = input("Enter your nocaptcha.io API token: ").strip()
    
    if not NOCAPTCHA_TOKEN:
        print("❌ Nocaptcha token is required!")
        return
    
    TEMPMAIL_API_KEY = input("Enter tempmail.lol API key (or press Enter to skip): ").strip() or None
    
    count = int(input("How many accounts to generate? "))
    proxy = input("Enter proxy (usr:pwd@ip:port) or press Enter to skip: ").strip() or None
    delay = int(input("Delay between accounts in seconds (default 5): ").strip() or "5")
    
    # Initialize generator
    generator = B402BulkGenerator(NOCAPTCHA_TOKEN, TEMPMAIL_API_KEY)
    
    # Generate accounts
    results = generator.generate_bulk_accounts(
        count=count,
        proxy=proxy,
        delay_between=delay,
        output_file="b402_accounts.json"
    )
    
    print("\n✨ Generation complete! Check b402_accounts.json for results.")


if __name__ == "__main__":
    main()
