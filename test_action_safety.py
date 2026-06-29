"""Action gating (Phase 8b) — the safety core. Defense in depth, risk-keyed, default-OFF.

These are the most important tests in Phase 8: any one gate must block independently, the core must
never run above safe_active, authorization must be explicit/scoped/expiring, and AI must never be
able to authorize.
"""
import time

from src.reasoning.action_gate import (
    ActionGate,
    AuthorizationToken,
    CORE_MAX_TIER,
    GateContext,
)
from src.reasoning.actions import Action, ActionDescriptor, ActionSemantics, RiskTier


def _action(aid="a", risk=RiskTier.READ_ONLY, reversible=True):
    return Action(descriptor=ActionDescriptor(id=aid, risk_tier=risk, reversible=reversible),
                  semantics=ActionSemantics())


def _ctx(**kw):
    base = dict(scope=["ex.com"])
    base.update(kw)
    return GateContext(**base)


def _allow(action, ctx, target="web.ex.com", objective=""):
    return ActionGate().evaluate(action, target, ctx, objective=objective).allowed


# ── Default posture: read-only only ──

def test_read_only_allowed_in_scope():
    assert _allow(_action(risk=RiskTier.READ_ONLY), _ctx())


def test_safe_active_denied_without_flag():
    assert not _allow(_action(risk=RiskTier.SAFE_ACTIVE), _ctx())          # flag OFF
    assert _allow(_action(risk=RiskTier.SAFE_ACTIVE), _ctx(active_validation_enabled=True))


def test_intrusive_and_exploit_denied_by_default():
    assert not _allow(_action(risk=RiskTier.INTRUSIVE), _ctx())
    assert not _allow(_action(risk=RiskTier.EXPLOIT), _ctx())


# ── Gating keys on RISK, not goal name (both directions) ──

def test_exploit_denied_even_for_benign_objective():
    ctx = _ctx(active_validation_enabled=True)
    assert not _allow(_action(risk=RiskTier.EXPLOIT), ctx, objective="gather_evidence:framework")


def test_safe_active_allowed_even_for_scary_objective():
    ctx = _ctx(active_validation_enabled=True)
    assert _allow(_action(risk=RiskTier.SAFE_ACTIVE), ctx, objective="build_attack_chain:root")


# ── The core never executes above safe_active (no external executor) ──

def test_core_ceiling_blocks_intrusive_even_with_full_authorization():
    tok = AuthorizationToken(targets=("ex.com",), max_risk_tier=RiskTier.EXPLOIT,
                             expires_at=time.time() + 3600, issued_for="engagement-1")
    ctx = _ctx(active_validation_enabled=True, execution_authorized=True, authorization=tok)
    # Authorized in every other respect, but the CORE has no executor for intrusive/exploit → denied.
    d = ActionGate().evaluate(_action(risk=RiskTier.INTRUSIVE), "web.ex.com", ctx)
    assert not d.allowed
    assert any("external authorized executor" in r for r in d.denials)


def test_external_executor_required_for_intrusive():
    tok = AuthorizationToken(targets=("ex.com",), max_risk_tier=RiskTier.EXPLOIT,
                             expires_at=time.time() + 3600)
    # Full authorization is the conjunction of INDEPENDENT knobs: an explicitly-raised ceiling,
    # execution authorized, a valid token, AND an external executor (the core has none by default).
    ctx = _ctx(risk_ceiling=RiskTier.INTRUSIVE, active_validation_enabled=True,
               execution_authorized=True, authorization=tok, external_executor=object())
    assert CORE_MAX_TIER is RiskTier.SAFE_ACTIVE
    assert _allow(_action(risk=RiskTier.INTRUSIVE), ctx)   # now permitted (external, authorized)


# ── Defense in depth: each gate blocks independently ──

def test_scope_blocks_independently():
    # everything else authorized, but off-scope target → denied
    tok = AuthorizationToken(targets=("ex.com",), max_risk_tier=RiskTier.EXPLOIT, expires_at=time.time()+3600)
    ctx = _ctx(active_validation_enabled=True, execution_authorized=True, authorization=tok,
               external_executor=object())
    d = ActionGate().evaluate(_action(risk=RiskTier.INTRUSIVE), "evil.com", ctx)
    assert not d.allowed and any("not in scope" in r for r in d.denials)


def test_authorization_blocks_independently():
    ctx = _ctx(active_validation_enabled=True, execution_authorized=True, authorization=None,
               external_executor=object())     # executor present but NO token
    d = ActionGate().evaluate(_action(risk=RiskTier.INTRUSIVE), "web.ex.com", ctx)
    assert not d.allowed and any("authorization" in r for r in d.denials)


def test_risk_ceiling_blocks_independently():
    # execution_authorized but ceiling left at read_only and active validation off
    tok = AuthorizationToken(targets=("ex.com",), max_risk_tier=RiskTier.EXPLOIT, expires_at=time.time()+3600)
    ctx = _ctx(execution_authorized=True, authorization=tok, external_executor=object())
    d = ActionGate().evaluate(_action(risk=RiskTier.SAFE_ACTIVE), "web.ex.com", ctx)
    assert not d.allowed and any("exceeds ceiling" in r for r in d.denials)


def test_reversibility_blocks_independently():
    ctx = _ctx(active_validation_enabled=True)
    d = ActionGate().evaluate(_action(risk=RiskTier.SAFE_ACTIVE, reversible=False), "web.ex.com", ctx)
    assert not d.allowed and any("irreversible" in r for r in d.denials)
    ctx2 = _ctx(active_validation_enabled=True, allow_irreversible=True)
    assert _allow(_action(risk=RiskTier.SAFE_ACTIVE, reversible=False), ctx2)


def test_kill_switch_aborts():
    ctx = _ctx(active_validation_enabled=True, kill_switch=True)
    d = ActionGate().evaluate(_action(risk=RiskTier.SAFE_ACTIVE), "web.ex.com", ctx)
    assert not d.allowed and any("kill_switch" in r for r in d.denials)


# ── Authorization is explicit / scoped / expiring ──

def test_token_respects_scope():
    tok = AuthorizationToken(targets=("ex.com",), max_risk_tier=RiskTier.EXPLOIT, expires_at=time.time()+3600)
    assert tok.permits(_action(risk=RiskTier.INTRUSIVE), "web.ex.com")
    assert not tok.permits(_action(risk=RiskTier.INTRUSIVE), "other.com")


def test_token_respects_risk_cap():
    tok = AuthorizationToken(targets=("ex.com",), max_risk_tier=RiskTier.INTRUSIVE, expires_at=time.time()+3600)
    assert tok.permits(_action(risk=RiskTier.INTRUSIVE), "web.ex.com")
    assert not tok.permits(_action(risk=RiskTier.EXPLOIT), "web.ex.com")     # above cap


def test_token_expires():
    tok = AuthorizationToken(targets=("ex.com",), max_risk_tier=RiskTier.EXPLOIT, expires_at=time.time()-1)
    assert not tok.permits(_action(risk=RiskTier.INTRUSIVE), "web.ex.com")   # expired


# ── AI cannot authorize: no path from AI output / state to a token or enabling flags ──

def test_ai_proposal_data_cannot_authorize():
    """An attacker-controlled 'authorized: true' field in arbitrary proposal data must have no
    effect — the gate only consults the typed GateContext, never free-form dicts."""
    ai_blob = {"authorized": True, "execution_authorized": True, "risk_ceiling": "exploit"}
    # The gate takes a GateContext, not a dict; AI data simply isn't an input it reads.
    ctx = _ctx()                       # default-safe; AI blob ignored
    assert not _allow(_action(risk=RiskTier.EXPLOIT), ctx)
    # And there is no constructor that builds a token/context from such a blob.
    assert "authorized" not in GateContext.__dataclass_fields__ or \
        GateContext().execution_authorized is False


# ── Audit: every attempt recorded ──

def test_every_attempt_is_audited():
    gate = ActionGate()
    gate.evaluate(_action(risk=RiskTier.READ_ONLY), "web.ex.com", _ctx(), objective="o1")
    gate.evaluate(_action(risk=RiskTier.EXPLOIT), "web.ex.com", _ctx(), objective="o2")
    assert len(gate.audit) == 2
    recs = gate.audit.records()
    assert recs[0].allowed and not recs[1].allowed
    assert recs[1].objective == "o2" and recs[1].risk_tier == "exploit"
