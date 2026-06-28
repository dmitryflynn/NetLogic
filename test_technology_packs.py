"""Technology Pack knowledge system (Phase 6.5).

Covers the architecture the reviewer asked to design BEFORE mass-importing fingerprints:
compile-once, inheritance, aliases, composition, source provenance + calibration, adapters into the
existing engine, and a per-pack benchmark corpus so knowledge can't silently degrade as it grows.
"""
import dataclasses as dc

import pytest

from src.reasoning.inference import InferenceEngine, Rule
from src.reasoning.packs.benchmark import evaluate_pack, run_fixture
from src.reasoning.packs.compiler import PackCompiler
from src.reasoning.packs.schema import CompiledPack, Fingerprints, KnowledgeSource


@pytest.fixture(scope="module")
def lib():
    return PackCompiler().compile_dir()


# ── Compile-once + basic load ──

def test_packs_compile(lib):
    ids = {p.id for p in lib.all()}
    assert {"wordpress", "woocommerce", "nginx", "spring_boot"} <= ids


def test_compiled_pack_is_immutable():
    assert CompiledPack.__dataclass_params__.frozen
    assert Fingerprints.__dataclass_params__.frozen


# ── Aliases ──

def test_alias_resolution(lib):
    assert lib.get("wp").id == "wordpress"
    assert lib.get("wordpress6").id == "wordpress"
    assert lib.get("woo").id == "woocommerce"
    assert "wp" in lib


def test_unknown_alias_returns_none(lib):
    assert lib.get("does-not-exist") is None


# ── Inheritance: WooCommerce extends WordPress ──

def test_inheritance_merges_parent_fingerprints(lib):
    woo = lib.get("woocommerce")
    # inherits WordPress markers...
    assert "wp-content" in woo.fingerprints.body
    assert "wordpress_logged_in" in woo.fingerprints.cookies
    # ...and adds its own
    assert "woocommerce" in woo.fingerprints.body
    assert "woocommerce_items_in_cart" in woo.fingerprints.cookies


def test_inheritance_merges_rules(lib):
    woo = lib.get("woocommerce")
    assert "wp-content" in woo.rule.confirm        # parent
    assert "woocommerce" in woo.rule.confirm        # child


def test_lineage_recorded(lib):
    assert lib.get("woocommerce").lineage == ("wordpress",)
    assert lib.get("wordpress").lineage == ()


def test_inheritance_accumulates_capabilities(lib):
    woo = lib.get("woocommerce")
    cap_ids = {c.id for c in woo.capabilities}
    assert "wordpress_investigation" in cap_ids     # inherited
    assert "woocommerce_investigation" in cap_ids   # own


# ── Investigation sequences (the valuable part) ──

def test_capability_carries_investigation_order(lib):
    sb = lib.get("spring_boot")
    inv = next(c for c in sb.capabilities if c.id == "spring_boot_investigation")
    assert inv.preferred_order == ("headers", "cookies", "favicon", "body", "actuator", "swagger")
    assert inv.fallback == ("robots", "graphql")


# ── Source provenance + calibration ──

def test_source_calibration_differentiates_trust(lib):
    # manual (0.95) is trusted more than wappalyzer (0.85)
    wp = lib.get("wordpress")       # source: manual
    nginx = lib.get("nginx")        # source: wappalyzer
    assert lib.effective_confidence(wp, 1.0) == 0.95
    assert lib.effective_confidence(nginx, 1.0) == 0.85
    assert lib.effective_confidence(wp, 1.0) > lib.effective_confidence(nginx, 1.0)


def test_source_recorded_on_pack(lib):
    assert lib.get("nginx").source == "wappalyzer"
    assert lib.source_of(lib.get("nginx")).id == "wappalyzer"


def test_knowledge_source_from_dict():
    s = KnowledgeSource.from_dict("x", {"confidence": 0.5, "coverage": "low"})
    assert s.confidence == 0.5 and s.coverage == "low"


# ── Composition: avoid the stack explosion ──

def test_composition_merges_independent_packs(lib):
    stack = lib.compose(["nginx", "wordpress", "woocommerce"], "site_stack")
    # union of all markers, no inheritance semantics
    assert "server: nginx" in stack.fingerprints.headers
    assert "wp-content" in stack.fingerprints.body
    assert "woocommerce" in stack.fingerprints.body
    assert "/wp-json" in stack.endpoints


def test_composition_unknown_pack_raises(lib):
    with pytest.raises(KeyError):
        lib.compose(["nginx", "nonexistent"])


# ── Adapters into the existing engine ──

def test_to_inference_rules_are_usable(lib):
    rules = lib.to_inference_rules()
    assert "wordpress" in rules and isinstance(rules["wordpress"], Rule)
    # The InferenceEngine consumes them directly.
    eng = InferenceEngine(rules=rules)
    assert eng._rules["wordpress"].confirm


def test_to_capabilities_registers_pack_capabilities(lib):
    reg = lib.to_capabilities()
    cap_ids = {c.id for c in reg.capabilities.values()}
    assert "spring_boot_investigation" in cap_ids
    assert "wordpress_investigation" in cap_ids


def test_priority_hints_bootstrapped_from_packs(lib):
    hints = lib.priority_hints()
    assert hints
    # earlier markers in a pack's order get a larger boost
    nginx_hints = [h for h in hints if "nginx" in h.reason]
    assert nginx_hints[0].boost >= nginx_hints[-1].boost


# ── Benchmark corpus: every pack's fingerprints get a regression test ──

def test_evaluate_pack_matches_recorded_response(lib):
    from src.reasoning.packs.benchmark import load_fixture
    response, _ = load_fixture("wordpress/basic")
    res = evaluate_pack(lib.get("wordpress"), response)
    assert res.detected
    assert "wp-content" in res.matched_markers


@pytest.mark.parametrize("fixture", [
    "wordpress/basic", "woocommerce/basic", "nginx/basic", "spring_boot/basic",
])
def test_benchmark_fixtures_pass(lib, fixture):
    result = run_fixture(lib, fixture)
    assert result["passed"], f"{fixture} failed: {result['failures']} (detected {result['detected']})"


def test_benchmark_catches_false_positives(lib):
    # nginx fixture must NOT trip wordpress/spring_boot
    result = run_fixture(lib, "nginx/basic")
    assert "wordpress" not in result["detected"]
    assert "spring_boot" not in result["detected"]


def test_inheritance_shows_in_benchmark(lib):
    # the woocommerce fixture detects BOTH woocommerce and (inherited) wordpress
    result = run_fixture(lib, "woocommerce/basic")
    assert "woocommerce" in result["detected"]
    assert "wordpress" in result["detected"]


# ── Compile-once performance invariant ──

def test_runtime_use_does_not_reparse_yaml(monkeypatch, lib):
    """PackCompiler parses once at startup (mirror Phase 4 rule compiler). Runtime consumption of
    the compiled library must never re-parse YAML — keeps the runtime deterministic."""
    import src.reasoning.packs.compiler as pc_mod
    calls = {"n": 0}
    real = pc_mod.yaml.safe_load

    def counting(*a, **k):
        calls["n"] += 1
        return real(*a, **k)
    monkeypatch.setattr(pc_mod.yaml, "safe_load", counting)

    lib.get("wp")
    lib.to_inference_rules()
    lib.to_capabilities()
    lib.compose(["nginx", "wordpress"])
    run_fixture(lib, "wordpress/basic")
    assert calls["n"] == 0, "runtime pack use must not parse YAML — compiled once at startup"
