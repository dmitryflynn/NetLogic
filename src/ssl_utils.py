"""
NetLogic - SSL/TLS Utilities
Proper SSL certificate validation and context management.
"""

import ssl
import socket
import logging
from typing import Optional, Tuple
from dataclasses import dataclass
from enum import Enum


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SSLValidationLevel(Enum):
    """SSL validation levels for different security requirements."""
    NONE = "none"           # No validation (for legacy systems only)
    BASIC = "basic"         # Basic certificate validation
    STRICT = "strict"       # Strict validation with hostname checking
    CUSTOM = "custom"       # Custom validation rules


@dataclass
class SSLConfig:
    """SSL configuration options."""
    validation_level: SSLValidationLevel = SSLValidationLevel.BASIC
    verify_hostname: bool = True
    check_revocation: bool = True
    min_tls_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2
    max_tls_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_3
    cipher_suites: Optional[str] = None
    ca_cert_path: Optional[str] = None
    cert_path: Optional[str] = None
    key_path: Optional[str] = None


class SSLValidationError(Exception):
    """Raised when SSL validation fails."""
    pass


class SSLContextManager:
    """Manages SSL contexts with configurable validation levels."""
    
    def __init__(self, config: Optional[SSLConfig] = None):
        self.config = config or SSLConfig()
        self._context_cache = {}  # Cache contexts by config
    
    def create_context(self, purpose: ssl.Purpose = ssl.Purpose.SERVER_AUTH) -> ssl.SSLContext:
        """Create SSL context with specified configuration."""
        cache_key = (purpose, self.config.validation_level.value)
        
        if cache_key in self._context_cache:
            return self._context_cache[cache_key]
        
        # Create context based on validation level
        if self.config.validation_level == SSLValidationLevel.NONE:
            ctx = ssl._create_unverified_context()
            logger.warning("Using SSL context without certificate validation - security risk!")
        else:
            ctx = ssl.create_default_context(purpose)
            
            # Configure verification settings
            if self.config.validation_level == SSLValidationLevel.STRICT:
                ctx.verify_mode = ssl.CERT_REQUIRED
                ctx.check_hostname = True
            elif self.config.validation_level == SSLValidationLevel.BASIC:
                ctx.verify_mode = ssl.CERT_REQUIRED
                ctx.check_hostname = self.config.verify_hostname
            
            # Configure revocation checking
            if self.config.check_revocation:
                try:
                    ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_CHAIN
                except AttributeError:
                    logger.warning("CRL checking not available on this platform")
            
            # Configure TLS version range
            ctx.minimum_version = self.config.min_tls_version
            ctx.maximum_version = self.config.max_tls_version
            
            # Configure custom CA certificate
            if self.config.ca_cert_path:
                ctx.load_verify_locations(cafile=self.config.ca_cert_path)
            
            # Configure client certificate
            if self.config.cert_path and self.config.key_path:
                ctx.load_cert_chain(certfile=self.config.cert_path, keyfile=self.config.key_path)
            
            # Configure custom cipher suites
            if self.config.cipher_suites:
                ctx.set_ciphers(self.config.cipher_suites)
        
        self._context_cache[cache_key] = ctx
        return ctx
    
    def validate_certificate(self, cert: dict, hostname: str) -> Tuple[bool, Optional[str]]:
        """
        Validate certificate against hostname and security requirements.
        Returns (is_valid, error_message)
        """
        if not cert:
            return False, "No certificate provided"
        
        # Check certificate expiry.
        # notAfter/notBefore are always in GMT/UTC; strptime drops the zone and
        # yields a naive datetime, so we attach UTC and compare against UTC now.
        # Comparing against the local-time datetime.now() would be wrong by the
        # host's UTC offset and could mis-flag a valid cert near the boundary.
        from datetime import datetime, timezone

        def _utc_now():
            return datetime.now(timezone.utc)

        def _parse_utc(value):
            return datetime.strptime(value, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)

        not_after = cert.get('notAfter')
        if not_after:
            try:
                expiry_date = _parse_utc(not_after)
                if expiry_date < _utc_now():
                    return False, f"Certificate expired on {not_after}"
            except ValueError:
                pass  # Invalid date format, continue

        # Check certificate validity period
        not_before = cert.get('notBefore')
        if not_before:
            try:
                valid_from = _parse_utc(not_before)
                if valid_from > _utc_now():
                    return False, f"Certificate not valid until {not_before}"
            except ValueError:
                pass
        
        # Check hostname match if strict validation
        if self.config.validation_level == SSLValidationLevel.STRICT:
            common_names = []
            alt_names = []
            
            # Extract common names
            for subject in cert.get('subject', []):
                for key, value in subject:
                    if key == 'commonName':
                        common_names.append(value)
            
            # Extract subject alternative names
            sans = cert.get('subjectAltName', ())
            for san_type, san_value in sans:
                if san_type == 'DNS':
                    alt_names.append(san_value)
            
            # Check if hostname matches any CN or SAN
            hostname_lower = hostname.lower()
            for cn in common_names:
                if self._hostname_matches(cn, hostname_lower):
                    break
            else:
                for san in alt_names:
                    if self._hostname_matches(san, hostname_lower):
                        break
                else:
                    return False, f"Hostname '{hostname}' does not match certificate CN/SAN"
        
        return True, None
    
    def _hostname_matches(self, cert_hostname: str, requested_hostname: str) -> bool:
        """Check if certificate hostname matches requested hostname."""
        cert_hostname = cert_hostname.lower()
        requested_hostname = requested_hostname.lower()
        
        # Exact match
        if cert_hostname == requested_hostname:
            return True
        
        # Wildcard match
        if cert_hostname.startswith('*.'):
            domain = cert_hostname[1:]  # include leading dot → ".example.com"
            if requested_hostname.endswith(domain):
                prefix = requested_hostname[:-len(domain)]
                if prefix and '.' not in prefix:
                    return True
        
        return False
    
    def create_secure_connection(self, host: str, port: int, timeout: float = 10.0) -> Tuple[Optional[ssl.SSLSocket], Optional[str]]:
        """
        Create a secure SSL connection with proper validation.
        Returns (socket, error_message)
        """
        ctx = self.create_context()
        raw_sock = None
        tls_sock = None
        
        try:
            raw_sock = socket.create_connection((host, port), timeout=timeout)
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname=host)
            raw_sock = None

            # Validate certificate
            cert = tls_sock.getpeercert()
            if self.config.validation_level != SSLValidationLevel.NONE:
                is_valid, error_msg = self.validate_certificate(cert, host)
                if not is_valid:
                    raise SSLValidationError(f"Certificate validation failed: {error_msg}")
            
            # Check TLS version
            tls_version = tls_sock.version()
            if tls_version:
                logger.info(f"Established secure connection using {tls_version}")
            
            return tls_sock, None
                     
        except ssl.SSLError as e:
            error_msg = f"SSL handshake failed: {e}"
            logger.error(error_msg)
            if tls_sock:
                tls_sock.close()
            elif raw_sock:
                raw_sock.close()
            return None, error_msg
        except socket.timeout:
            error_msg = f"Connection timeout to {host}:{port}"
            logger.error(error_msg)
            if tls_sock:
                tls_sock.close()
            elif raw_sock:
                raw_sock.close()
            return None, error_msg
        except Exception as e:
            error_msg = f"Connection failed: {e}"
            logger.error(error_msg)
            if tls_sock:
                tls_sock.close()
            elif raw_sock:
                raw_sock.close()
            return None, error_msg


# Global SSL configuration
_ssl_config = SSLConfig()
_ssl_manager = SSLContextManager(_ssl_config)


def configure_ssl(config: SSLConfig):
    """Configure global SSL settings."""
    global _ssl_config, _ssl_manager
    _ssl_config = config
    _ssl_manager = SSLContextManager(config)
    logger.info(f"SSL configuration updated: {config.validation_level.value} validation")


def get_ssl_context(purpose: ssl.Purpose = ssl.Purpose.SERVER_AUTH) -> ssl.SSLContext:
    """Get SSL context with current configuration."""
    return _ssl_manager.create_context(purpose)


def probe_with_tls_secure(host: str, port: int, probe_data: bytes, 
                         timeout: float = 5.0, validation_level: SSLValidationLevel = SSLValidationLevel.BASIC) -> Tuple[Optional[bytes], Optional[str]]:
    """
    Send probe over TLS with proper certificate validation.
    Returns (response_data, error_message)
    """
    # Create temporary config for this request
    temp_config = SSLConfig(validation_level=validation_level)
    temp_manager = SSLContextManager(temp_config)
    
    try:
        ctx = temp_manager.create_context()
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                tls_sock.sendall(probe_data)
                
                # Receive response
                response = b""
                tls_sock.settimeout(timeout)
                while len(response) < 16384:  # Max 16KB
                    try:
                        chunk = tls_sock.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                    except socket.timeout:
                        break
                
                return response, None
                
    except ssl.SSLError as e:
        error_msg = f"SSL/TLS error: {e}"
        return None, error_msg
    except Exception as e:
        error_msg = f"Connection error: {e}"
        return None, error_msg


def tls_probe_secure(host: str, port: int, timeout: float = 5.0, 
                    validation_level: SSLValidationLevel = SSLValidationLevel.BASIC) -> Tuple[bool, Optional[str], Optional[dict]]:
    """
    Attempt TLS handshake with proper certificate validation.
    Returns (success, error_message, certificate_info)
    """
    temp_config = SSLConfig(validation_level=validation_level)
    temp_manager = SSLContextManager(temp_config)
    
    try:
        ctx = temp_manager.create_context()
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
                
                # Extract certificate information
                cert_info = {}
                if cert:
                    cert_info['subject'] = cert.get('subject', [])
                    cert_info['issuer'] = cert.get('issuer', [])
                    cert_info['version'] = cert.get('version')
                    cert_info['serial_number'] = cert.get('serialNumber')
                    cert_info['not_before'] = cert.get('notBefore')
                    cert_info['not_after'] = cert.get('notAfter')
                    cert_info['alt_names'] = []
                    
                    # Extract subject alternative names
                    sans = cert.get('subjectAltName', ())
                    cert_info['alt_names'] = [v for t, v in sans if t == 'DNS']
                
                # Validate certificate
                if validation_level != SSLValidationLevel.NONE:
                    is_valid, error_msg = temp_manager.validate_certificate(cert, host)
                    if not is_valid:
                        return False, error_msg, cert_info
                
                return True, None, cert_info
                
    except ssl.SSLError as e:
        error_msg = f"SSL/TLS error: {e}"
        return False, error_msg, None
    except Exception as e:
        error_msg = f"Connection error: {e}"
        return False, error_msg, None
