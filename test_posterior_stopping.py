"""Joint-posterior stopping rule over competing hypotheses (Phase 5 §5 — the `Question` gate).

DESIGN DECISION: a separate `Question` object was evaluated and COLLAPSED. The reviewer's test —
"if I delete it, what becomes impossible?" — yields *nothing*: the competing-candidate set already
lives inside a single Hypothesis's `likelihoods` dict, and the only capability a Question would add
(a joint-posterior stopping rule) is a pure function over those likelihoods. So it is implemented as
methods on Hypothesis, not a new layer. These tests pin the capability and document the decision.
"""
from src.reasoning.hypothesis import Hypothesis, HypothesisEngine
from src.reasoning.objective import Objective
from src.reasoning.state import ReasoningState


def _competing(likelihoods):
    return Hypothesis(id="h", label="cms", likelihoods=likelihoods)


def test_normalized_posterior_sums_to_one():
    h = _competing({"wordpress": 3.0, "drupal": 1.0})
    post = h.normalized_posterior()
    assert abs(sum(post.values()) - 1.0) < 1e-9
    assert abs(post["wordpress"] - 0.75) < 1e-9


def test_leading_posterior_is_max_mass():
    h = _competing({"wordpress": 0.9, "drupal": 0.1})
    assert abs(h.leading_posterior() - 0.9) < 1e-9


def test_posterior_resolved_above_threshold():
    h = _competing({"wordpress": 0.97, "drupal": 0.02, "joomla": 0.01})
    assert h.posterior_resolved(0.95) is True


def test_posterior_not_resolved_when_spread():
    h = _competing({"wordpress": 0.5, "drupal": 0.3, "joomla": 0.2})
    assert h.posterior_resolved(0.95) is False


def test_single_candidate_is_not_a_competing_question():
    # one candidate is not a competing set — the stopping rule does not apply
    h = _competing({"wordpress": 1.0})
    assert h.posterior_resolved(0.95) is False


def test_objective_alone_cannot_express_joint_posterior():
    """The capability the (collapsed) Question would have owned: an Objective's boolean
    `satisfied` cannot represent 'the competing CMS set concentrated past 0.95'. The Hypothesis
    can; the Objective cannot. This is why the grouping lives on Hypothesis."""
    obj = Objective(name="identify_framework:ex.com:80")
    # An objective exposes only a boolean — no notion of a competing distribution or its mass.
    assert hasattr(obj, "satisfied")
    assert not hasattr(obj, "leading_posterior")

    h = _competing({"wordpress": 0.96, "drupal": 0.04})
    # The same decision IS expressible on the hypothesis.
    assert h.posterior_resolved(0.95) is True


def test_engine_roundtrip_preserves_competing_set():
    eng = HypothesisEngine()
    hid = eng.add_hypothesis(label="cms", likelihoods={"wordpress": 0.6, "drupal": 0.4})
    restored = HypothesisEngine.from_dict(eng.to_dict())
    assert restored.get(hid).normalized_posterior().keys() == {"wordpress", "drupal"}
