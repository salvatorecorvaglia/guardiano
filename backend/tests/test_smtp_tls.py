"""Exercise real SMTP handshakes; certificate failures must precede message delivery."""

import socket
import ssl
import threading
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.core.config import settings
from app.services import email


@pytest.mark.parametrize("security", ["ssl", "starttls"])
@pytest.mark.parametrize("certificate", ["trusted", "untrusted", "wrong-host"])
def test_smtp_verifies_certificate_before_sending(tmp_path, monkeypatch, security, certificate):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = "elsewhere.test" if certificate == "wrong-host" else "localhost"
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert_path, key_path)
    original_context = ssl.create_default_context

    def client_context():
        context = original_context()
        if certificate != "untrusted":
            context.load_verify_locations(cafile=cert_path)
        return context

    monkeypatch.setattr(email.ssl, "create_default_context", client_context)
    commands, messages, errors = [], [], []
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(5)

    def serve():
        try:
            connection, _ = listener.accept()
            connection.settimeout(5)
            with connection:
                if security == "ssl":
                    connection = server_context.wrap_socket(connection, server_side=True)
                with connection:
                    stream = connection.makefile("rb")
                    connection.sendall(b"220 localhost test SMTP\r\n")
                    while line := stream.readline():
                        command = line.decode().strip()
                        commands.append(command)
                        if command.upper().startswith("EHLO"):
                            connection.sendall(b"250-localhost\r\n250 STARTTLS\r\n")
                        elif command.upper() == "STARTTLS":
                            connection.sendall(b"220 Ready for TLS\r\n")
                            stream.close()
                            connection = server_context.wrap_socket(connection, server_side=True)
                            stream = connection.makefile("rb")
                        elif command.upper() == "DATA":
                            connection.sendall(b"354 Send message\r\n")
                            while (part := stream.readline()) not in (b".\r\n", b""):
                                messages.append(part)
                            connection.sendall(b"250 Accepted\r\n")
                        elif command.upper() == "QUIT":
                            connection.sendall(b"221 Bye\r\n")
                            break
                        else:
                            connection.sendall(b"250 OK\r\n")
                    stream.close()
                    connection.close()
        except ssl.SSLError:
            pass  # the client correctly rejects the untrusted / wrong-host certificate
        except Exception as exc:
            errors.append(exc)
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    monkeypatch.setattr(settings, "smtp_host", "localhost")
    monkeypatch.setattr(settings, "smtp_port", listener.getsockname()[1])
    monkeypatch.setattr(settings, "smtp_user", "")
    monkeypatch.setattr(settings, "smtp_security", security)
    if certificate == "trusted":
        email.send("reader@example.test", "TLS test", "Private report content")
    else:
        with pytest.raises(ssl.SSLCertVerificationError):
            email.send("reader@example.test", "TLS test", "Private report content")
    thread.join(timeout=6)
    assert not thread.is_alive() and not errors
    if certificate == "trusted":
        assert b"Private report content" in b"".join(messages)
    else:
        assert not messages
        assert not any(command.upper().startswith(("MAIL", "AUTH")) for command in commands)
