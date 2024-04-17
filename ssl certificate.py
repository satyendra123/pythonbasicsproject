from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta

def generate_certificate():
    # Generate a key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Create a certificate builder
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "CH"),
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "Amritsar"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "HSPL"),
        x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, "AP"),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, "Server"),
        x509.NameAttribute(x509.NameOID.EMAIL_ADDRESS, "a@a.com")
    ])

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
    )

    # Add X509v3 extensions
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        critical=False
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
        ),
        critical=False
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    )

    # Sign the certificate with the private key
    certificate = builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    # Write the private key to a .pem file
    with open("example_certificate.pem", "wb") as key_file:
        key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Write the certificate to a .crt file
    with open("example_certificate.crt", "wb") as cert_file:
        cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))

    # Print the textual representation of the certificate
    print(certificate.public_bytes(serialization.Encoding.PEM).decode())

if __name__ == "__main__":
    generate_certificate()
