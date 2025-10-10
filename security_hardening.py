# security_hardening.py - Security features for the scanner itself
import hashlib
import secrets
import time
from functools import wraps


class SecurityHardening:
    """Security hardening features for the scanner"""

    def __init__(self):
        self.rate_limits = {}
        self.failed_attempts = {}
        self.blocked_ips = set()

    def validate_target_url(self, url):
        """Validate and sanitize target URL"""
        import re
        from urllib.parse import urlparse

        # Basic URL validation
        if not url or len(url) > 2048:
            raise ValueError("Invalid URL length")

        parsed = urlparse(url)

        # Check for valid scheme
        if parsed.scheme not in ['http', 'https']:
            raise ValueError("Only HTTP and HTTPS URLs are allowed")

        # Prevent scanning of local/private networks
        import ipaddress
        try:
            ip = ipaddress.ip_address(parsed.hostname)
            if ip.is_private or ip.is_loopback:
                raise ValueError("Cannot scan private or local IP addresses")
        except:
            # Not an IP address, continue with domain validation
            pass

        # Block dangerous domains/patterns
        dangerous_patterns = [
            r'localhost',
            r'127\.0\.0\.1',
            r'192\.168\.',
            r'10\.',
            r'172\.(1[6-9]|2[0-9]|3[0-1])\.',
            r'.*\.local
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, parsed.netloc, re.IGNORECASE):
                raise ValueError(f"Target URL not allowed: {url}")

        return url

    def rate_limit(self, identifier, max_requests=10, time_window=3600):
        """Rate limiting decorator"""

        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                current_time = time.time()

                # Clean old entries
                if identifier in self.rate_limits:
                    self.rate_limits[identifier] = [
                        req_time for req_time in self.rate_limits[identifier]
                        if current_time - req_time < time_window
                    ]
                else:
                    self.rate_limits[identifier] = []

                # Check rate limit
                if len(self.rate_limits[identifier]) >= max_requests:
                    raise Exception(f"Rate limit exceeded for {identifier}")

                # Record this request
                self.rate_limits[identifier].append(current_time)

                return func(*args, **kwargs)

            return wrapper

        return decorator

    def generate_scan_token(self):
        """Generate secure scan token"""
        return secrets.token_urlsafe(32)

    def hash_sensitive_data(self, data):
        """Hash sensitive data for logging"""
        return hashlib.sha256(data.encode()).hexdigest()[:16]
