"""
Per-org AI/fusion key isolation (the multi-tenant credential boundary).

Invariants:
  • Two orgs store different keys; each org's scan resolves ITS OWN key — never
    the other org's, and never a process-global one.
  • Keys are sealed at rest (ciphertext != plaintext, and the plaintext never
    appears in the stored record).
  • 'fusion' inherits the org's 'ai' settings when it has none of its own.
  • Setting a key with api_key=None keeps the existing one; "" clears it.
"""
import importlib

import pytest

from api import crypto


@pytest.fixture
def store(monkeypatch):
    # Force the in-memory backend (no Postgres) and a deterministic ephemeral seal.
    monkeypatch.delenv("NETLOGIC_DATABASE_URL", raising=False)
    monkeypatch.delenv("NETLOGIC_SECRETS_KEY", raising=False)
    crypto.reset_for_tests()
    import api.settings_store as ss
    importlib.reload(ss)
    return ss.OrgSettingsStore()


def test_two_orgs_keys_do_not_leak(store):
    store.put("acme", "ai", provider="openrouter", model="m-a", api_key="sk-acme-AAAA1111")
    store.put("globex", "ai", provider="openai", model="m-g", api_key="sk-globex-BBBB2222")

    a = store.get("acme", "ai")
    g = store.get("globex", "ai")
    assert a["api_key"] == "sk-acme-AAAA1111"
    assert g["api_key"] == "sk-globex-BBBB2222"
    assert a["api_key"] != g["api_key"]
    # An org with nothing stored gets nothing — no borrow.
    assert store.get("thirdco", "ai") is None


def test_key_is_sealed_at_rest(store):
    store.put("acme", "ai", provider="openrouter", api_key="sk-secret-PLAINTEXT-9999")
    raw = store._store[("acme", "ai")]          # the persisted record
    ct = raw["key_ct"]
    assert isinstance(ct, (bytes, bytearray))
    assert b"PLAINTEXT" not in ct                # plaintext never sits at rest
    assert raw["key_hint"] == "sk-s…9999"        # only a masked hint is displayable
    assert store.get("acme", "ai")["api_key"] == "sk-secret-PLAINTEXT-9999"  # round-trips


def test_keep_vs_clear_key(store):
    store.put("acme", "ai", provider="openrouter", api_key="sk-keepme-1234")
    # Update model only (api_key=None) → key preserved.
    store.put("acme", "ai", provider="openrouter", model="new-model", api_key=None, keep_key=True)
    assert store.get("acme", "ai")["api_key"] == "sk-keepme-1234"
    assert store.get("acme", "ai")["model"] == "new-model"
    # Explicit clear.
    store.put("acme", "ai", provider="openrouter", api_key=None, keep_key=False)
    assert store.get("acme", "ai")["api_key"] is None


def test_config_for_org_resolves_per_tenant(store, monkeypatch):
    # Wire the resolver to our in-memory store and assert org A's scan config is A's.
    import api.settings_store as ss
    monkeypatch.setattr(ss, "org_settings_store", store)
    from src import ai_analyst

    store.put("acme", "ai", provider="openrouter", model="claude-x", api_key="sk-acme-AAAA1111")
    cfg = ai_analyst.config_for_org("acme", "ai")
    assert cfg.api_key == "sk-acme-AAAA1111"
    assert cfg.provider == "openrouter"

    # fusion inherits ai when it has no own row.
    fcfg = ai_analyst.config_for_org("acme", "fusion")
    assert fcfg.api_key == "sk-acme-AAAA1111"

    # A separate fusion key overrides the inheritance.
    store.put("acme", "fusion", provider="ollama", model="glm-cloud", api_key="sk-fusion-CCCC3333")
    fcfg2 = ai_analyst.config_for_org("acme", "fusion")
    assert fcfg2.api_key == "sk-fusion-CCCC3333"
    assert fcfg2.provider == "ollama"


def test_no_org_context_uses_env(monkeypatch):
    # CLI / desktop (org_id="") keeps reading env config — unchanged behavior.
    monkeypatch.setenv("NETLOGIC_AI_PROVIDER", "openrouter")
    monkeypatch.setenv("NETLOGIC_AI_API_KEY", "sk-env-DDDD4444")
    from src import ai_analyst
    cfg = ai_analyst.config_for_org("", "ai")
    assert cfg.api_key == "sk-env-DDDD4444"
