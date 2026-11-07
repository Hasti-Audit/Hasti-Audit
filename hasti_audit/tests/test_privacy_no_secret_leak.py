import json
from hasti_audit import audit_source

def test_secret_value_never_in_report():
    code = 'STRIPE_API_KEY = "sk_live_ABCDEFGH1234567890"'
    findings = audit_source(code, "test.py")
    output = json.dumps(findings)
    assert "sk_live_ABCDEFGH1234567890" not in output
    assert "ABCDEFGH1234567890" not in output

def test_aws_key_never_in_report():
    code = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'
    findings = audit_source(code, "test.py")
    output = json.dumps(findings)
    assert "AKIAIOSFODNN7EXAMPLE" not in output

def test_password_never_in_report():
    code = 'password = "SuperSecretPassword123!"'
    findings = audit_source(code, "test.py")
    output = json.dumps(findings)
    assert "SuperSecretPassword123!" not in output
    assert "SecretPassword123" not in output
