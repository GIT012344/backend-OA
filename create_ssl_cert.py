#!/usr/bin/env python3
"""
SSL Certificate Generator for Backend HTTPS
Creates self-signed certificate for ticket-backoffice.git.or.th
"""

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import datetime
import ipaddress

def create_ssl_certificate():
    """Create self-signed SSL certificate for backend HTTPS"""
    
    print("Creating SSL certificate for backend HTTPS...")
    
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    
    # Certificate details
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "TH"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Bangkok"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Bangkok"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "GIT Organization"),
        x509.NameAttribute(NameOID.COMMON_NAME, "ticket-backoffice.git.or.th"),
    ])
    
    # Create certificate
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("ticket-backoffice.git.or.th"),
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("10.10.1.53")),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            x509.DNSName("localhost"),
            x509.DNSName("10.10.1.53"),
            x509.IPAddress(ipaddress.IPv4Address("10.10.1.53")),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            # Add more IP variations for better compatibility
            x509.DNSName("*.git.or.th"),
        ]),
        critical=False,
    ).sign(private_key, hashes.SHA256())
    
    # Write certificate to file
    with open("cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    # Write private key to file
    with open("key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    print("SSL Certificate created successfully!")
    print("Files created:")
    print("   - cert.pem (SSL Certificate)")
    print("   - key.pem (Private Key)")
    print("")
    print("Certificate valid for:")
    print("   - ticket-backoffice.git.or.th")
    print("   - localhost")
    print("   - 10.10.1.53")
    print("   - 127.0.0.1")
    print("")
    print("Backend will now run in HTTPS mode!")

if __name__ == "__main__":
    try:
        create_ssl_certificate()
    except ImportError:
        print("Error: cryptography library not installed")
        print("Install with: pip install cryptography")
    except Exception as e:
        print(f"Error creating SSL certificate: {str(e)}")
