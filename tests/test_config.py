from __future__ import annotations

from core.config import Settings


def test_ollama_host_protocol_validation():
    # Test host with protocol prefix remains unchanged
    settings_http = Settings(ollama_host="http://localhost:11434")
    assert settings_http.ollama_host == "http://localhost:11434"

    settings_https = Settings(ollama_host="https://localhost:11434")
    assert settings_https.ollama_host == "https://localhost:11434"

    # Test host without protocol prefix gets http:// prepended
    settings_no_protocol = Settings(ollama_host="127.0.0.1:11434")
    assert settings_no_protocol.ollama_host == "http://127.0.0.1:11434"

    # Test spaces/stripping is handled
    settings_spaces = Settings(ollama_host="   127.0.0.1:11434   ")
    assert settings_spaces.ollama_host == "http://127.0.0.1:11434"
