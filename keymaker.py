#!/usr/bin/env python3
import argparse
import datetime
import os
import sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import pkcs12, BestAvailableEncryption
from cryptography.x509.oid import NameOID

def main():
    parser = argparse.ArgumentParser(
        description="A robust, standalone CLI utility to generate PKCS#12 (.p12) keystores (Java keytool alternative)."
    )
    
    # Required/Core arguments
    parser.add_argument("-o", "--output", required=True, help="Output filename or path for the .p12 keystore")
    parser.add_argument("-p", "--password", required=True, help="Password to secure/encrypt the keystore")
    parser.add_argument("-a", "--alias", default="my_key_alias", help="Key alias name (default: my_key_alias)")
    
    # Algorithm & Key Size options
    parser.add_argument("-alg", "--keyalg", choices=["RSA", "EC"], default="RSA", help="Key algorithm: RSA or EC (default: RSA)")
    parser.add_argument("-size", "--keysize", type=int, default=2048, help="Key size in bits for RSA (e.g., 2048, 4096) or EC curve bits")
    
    # Validity options
    parser.add_argument("-days", "--validity-days", type=int, default=9125, help="Validity duration in days (default: 9125 days / ~25 years)")
    
    # Distinguished Name (DN) Fields
    parser.add_argument("-cn", "--common-name", default="Android Debug Key", help="Common Name (CN) field (default: Android Debug Key)")
    parser.add_argument("-org", "--organization", default="Development", help="Organization (O) field (default: Development)")
    parser.add_argument("-c", "--country", default="US", help="Country (C) field code (default: US)")

    args = parser.parse_args()

    # Pre-flight safety checks
    output_dir = os.path.dirname(os.path.abspath(args.output))
    if output_dir and not os.path.exists(output_dir):
        print(f"[-] Error: Target directory does not exist: {output_dir}", file=sys.stderr)
        sys.exit(1)

    if len(args.password) < 6:
        print("[-] Warning: Keystore passwords less than 6 characters are insecure.", file=sys.stderr)

    try:
        print(f"[*] Generating {args.keyalg} private key (Size: {args.keysize})...")
        
        # 1. Generate Private Key based on algorithm selection
        if args.keyalg == "RSA":
            if args.keysize < 1024:
                raise ValueError("RSA key size must be at least 1024 bits (2048+ recommended).")
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=args.keysize
            )
        elif args.keyalg == "EC":
            curve = ec.SECP256R1()
            if args.keysize >= 384:
                curve = ec.SECP384R1()
            private_key = ec.generate_private_key(curve)
        else:
            raise ValueError(f"Unsupported key algorithm: {args.keyalg}")

        print(f"[*] Building self-signed X.509 certificate...")
        print(f"    -> CN: {args.common_name}")
        print(f"    -> Org: {args.organization} ({args.country})")
        print(f"    -> Validity: {args.validity_days} days")

        # 2. Build X.509 Certificate Subject & Issuer
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, args.country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, args.organization),
            x509.NameAttribute(NameOID.COMMON_NAME, args.common_name),
        ])

        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)) # Backdate 1 day to prevent clock skew issues
            .not_valid_after(now + datetime.timedelta(days=args.validity_days))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .sign(private_key, hashes.SHA256())
        )

        print(f"[*] Encrypting and packing into PKCS#12 container...")
        p12_data = pkcs12.serialize_key_and_certificates(
            name=args.alias.encode('utf-8'),
            key=private_key,
            cert=cert,
            cas=None,
            encryption_algorithm=BestAvailableEncryption(args.password.encode('utf-8'))
        )

        # 3. Securely write output file
        with open(args.output, "wb") as f:
            f.write(p12_data)

        print(f"[+] Success! Keystore successfully written to: {os.path.abspath(args.output)}")

    except Exception as e:
        print(f"[-] Critical Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()