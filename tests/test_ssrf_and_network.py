import pytest
from app.network.ssrf import validate_destination_safety, is_ip_forbidden, parse_and_validate_ip

ALLOWED_DOMAINS = ["api.weather.example", "api.github.com", "httpbin.org"]


def test_ssrf_blocks_loopback_ipv4():
    with pytest.raises(ValueError) as exc:
        validate_destination_safety("http://127.0.0.1:8080/admin", ALLOWED_DOMAINS)
    assert "ssrf" in str(exc.value)


def test_ssrf_blocks_loopback_hostname():
    with pytest.raises(ValueError) as exc:
        validate_destination_safety("http://localhost:8000/internal", ALLOWED_DOMAINS)
    assert "ssrf" in str(exc.value)


def test_ssrf_blocks_cloud_metadata():
    with pytest.raises(ValueError) as exc:
        validate_destination_safety("http://169.254.169.254/latest/meta-data/", ALLOWED_DOMAINS)
    assert "ssrf" in str(exc.value)


def test_ssrf_blocks_private_rfc1918():
    with pytest.raises(ValueError) as exc:
        validate_destination_safety("https://10.0.0.1/secrets", ALLOWED_DOMAINS)
    assert "ssrf" in str(exc.value)

    with pytest.raises(ValueError) as exc:
        validate_destination_safety("https://192.168.1.1/router", ALLOWED_DOMAINS)
    assert "ssrf" in str(exc.value)


def test_ssrf_blocks_disallowed_domain():
    with pytest.raises(ValueError) as exc:
        validate_destination_safety("https://evil-attacker.com/collect", ALLOWED_DOMAINS)
    assert "ssrf_domain_not_allowlisted" in str(exc.value)


def test_ssrf_blocks_dangerous_schemes():
    with pytest.raises(ValueError) as exc:
        validate_destination_safety("file:///etc/passwd", ALLOWED_DOMAINS)
    assert "ssrf_disallowed_scheme" in str(exc.value)

    with pytest.raises(ValueError) as exc:
        validate_destination_safety("gopher://127.0.0.1:6379/_flushall", ALLOWED_DOMAINS)
    assert "ssrf_disallowed_scheme" in str(exc.value)


def test_ssrf_blocks_credential_leakage_in_url():
    with pytest.raises(ValueError) as exc:
        validate_destination_safety("https://admin:supersecret@httpbin.org/get", ALLOWED_DOMAINS)
    assert "ssrf_credentials_in_url" in str(exc.value)


def test_ssrf_blocks_non_standard_ip_notation():
    with pytest.raises(ValueError):
        parse_and_validate_ip("0177.0.0.1")  # Octal notation

    with pytest.raises(ValueError):
        parse_and_validate_ip("0x7f.0.0.1")  # Hex notation
