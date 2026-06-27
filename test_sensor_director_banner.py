"""SensorDirector must not crash on a ServiceBanner object in open_ports.

Regression for `'ServiceBanner' object is not subscriptable`: the engine used to pass the
ServiceBanner dataclass through as "banner", and the director sliced it as a string.
"""
from src.directors.sensor_director import build_sensor_plan
from src.scanner import ServiceBanner


def test_build_sensor_plan_tolerates_servicebanner_object():
    banner = ServiceBanner(raw="Apache/2.4.7 (Ubuntu)", product="apache", version="2.4.7")
    ports = [{"port": 80, "service": "http", "banner": banner}]
    # complete=None → deterministic default plan; the crash happened before any AI call,
    # while summarizing ports, so this exercises the regression directly.
    plan = build_sensor_plan(open_ports=ports, complete=None)
    assert isinstance(plan, dict)
    assert "skip_reasons" in plan


def test_build_sensor_plan_tolerates_none_and_str_banner():
    ports = [
        {"port": 22, "service": "ssh", "banner": None},
        {"port": 443, "service": "https", "banner": "nginx/1.25.3"},
    ]
    plan = build_sensor_plan(open_ports=ports, complete=None)
    assert isinstance(plan, dict)
