#!/usr/bin/env python3
"""
Export IIS SSL Certificate for Backend Use
"""
import subprocess
import os
from datetime import datetime

def export_certificate_from_windows_store():
    """Export the trusted SSL certificate from Windows Certificate Store"""
    print("=== Exporting SSL Certificate from Windows Store ===")
    
    # Certificate thumbprint from IIS
    thumbprint = "768B4A767D53364B67D9C1678E77AE276556AF0E"
    
    try:
        # Export certificate (public key) to PEM format
        cert_export_cmd = [
            "powershell", "-Command",
            f'$cert = Get-ChildItem -Path "Cert:\\LocalMachine\\My\\{thumbprint}"; '
            f'$certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert); '
            f'$certPem = [System.Convert]::ToBase64String($certBytes); '
            f'$certPem = $certPem -replace "(.{{64}})", "$1`n"; '
            f'"-----BEGIN CERTIFICATE-----`n" + $certPem + "`n-----END CERTIFICATE-----" | Out-File -FilePath "cert_from_iis.pem" -Encoding ASCII'
        ]
        
        print("Exporting certificate...")
        result = subprocess.run(cert_export_cmd, capture_output=True, text=True, cwd=os.getcwd())
        
        if result.returncode == 0:
            print("✅ Certificate exported successfully to cert_from_iis.pem")
        else:
            print(f"❌ Certificate export failed: {result.stderr}")
            return False
        
        # Note: Private key export requires additional steps and permissions
        print("\n⚠️  Private Key Export:")
        print("Private key export requires special permissions and is complex.")
        print("We'll try to use the certificate store directly in Python instead.")
        
        return True
        
    except Exception as e:
        print(f"❌ Error exporting certificate: {str(e)}")
        return False

def create_certificate_usage_script():
    """Create a script to use Windows Certificate Store directly"""
    print("\n=== Creating Certificate Usage Script ===")
    
    script_content = '''
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import subprocess

def get_certificate_from_store():
    """Get certificate directly from Windows Certificate Store"""
    thumbprint = "768B4A767D53364B67D9C1678E77AE276556AF0E"
    
    # PowerShell command to get certificate details
    ps_cmd = f'''
    $cert = Get-ChildItem -Path "Cert:\\LocalMachine\\My\\{thumbprint}"
    Write-Output "Subject: $($cert.Subject)"
    Write-Output "Issuer: $($cert.Issuer)"
    Write-Output "NotAfter: $($cert.NotAfter)"
    Write-Output "HasPrivateKey: $($cert.HasPrivateKey)"
    '''
    
    try:
        result = subprocess.run(["powershell", "-Command", ps_cmd], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print("Certificate found in Windows Store:")
            print(result.stdout)
            return True
        else:
            print(f"Error accessing certificate: {result.stderr}")
            return False
    except Exception as e:
        print(f"Error: {str(e)}")
        return False

if __name__ == "__main__":
    get_certificate_from_store()
'''
    
    with open("test_windows_cert.py", "w", encoding="utf-8") as f:
        f.write(script_content)
    
    print("✅ Created test_windows_cert.py")

if __name__ == "__main__":
    print(f"Certificate Export Tool - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    success = export_certificate_from_windows_store()
    create_certificate_usage_script()
    
    print("\n" + "=" * 60)
    print("Next Steps:")
    print("1. Check if cert_from_iis.pem was created")
    print("2. We need to modify app.py to use the Windows Certificate Store")
    print("3. This will use the same trusted certificate as IIS")
