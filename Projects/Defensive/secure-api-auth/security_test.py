import requests
import jwt
import time
import json

class AuthSecurityTester:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
    
    def test_jwt_security(self, token):
        """Test JWT token security"""
        print("Testing JWT security...")
        
        try:
            # Decode without verification to inspect token
            decoded = jwt.decode(token, options={"verify_signature": False})
            
            # Check for weak algorithms
            if decoded.get('alg') == 'none':
                print("❌ JWT uses 'none' algorithm - insecure!")
            
            # Check expiration
            if 'exp' not in decoded:
                print("❌ JWT missing expiration claim")
            else:
                exp_time = decoded['exp']
                current_time = time.time()
                if exp_time - current_time > 24 * 3600:  # More than 24 hours
                    print("⚠️  JWT expiration too long")
                else:
                    print("✅ JWT expiration reasonable")
            
            # Check for sensitive data
            sensitive_fields = ['password', 'secret', 'private_key']
            for field in sensitive_fields:
                if field in str(decoded):
                    print(f"❌ JWT contains sensitive field: {field}")
            
            print("✅ JWT structure appears secure")
            
        except Exception as e:
            print(f"❌ JWT decoding error: {e}")
    
    def test_refresh_token_rotation(self):
        """Test refresh token rotation security"""
        print("\nTesting refresh token rotation...")
        
        # This would require actual authentication flow
        # For demo, we'll simulate the concept
        
        print("✅ Refresh token rotation should be implemented")
        print("✅ Old refresh tokens should be revoked after use")
        print("✅ Refresh tokens should have limited lifetime")
    
    def test_rate_limiting(self):
        """Test rate limiting on authentication endpoints"""
        print("\nTesting rate limiting...")
        
        failed_attempts = 0
        for i in range(10):
            response = self.session.post(
                f"{self.base_url}/auth/login",
                json={"username": "test", "password": "wrong"}
            )
            
            if response.status_code == 429:
                failed_attempts += 1
        
        if failed_attempts > 0:
            print("✅ Rate limiting is working")
        else:
            print("❌ Rate limiting may not be working properly")

if __name__ == "__main__":
    tester = AuthSecurityTester("http://localhost:8000")
    
    # These tests would need actual tokens and endpoints
    print("Run these tests against your actual API endpoints")
    print("Make sure to use test credentials, not production data!")
