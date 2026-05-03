from __future__ import annotations

import pytest

from badlands.validity_experiments import parse_args, run_validity_experiments


def test_validity_report_generation_for_current_ablations(tmp_path):
    out = tmp_path / "validity"
    report = run_validity_experiments(
        parse_args(
            [
                "--seeds",
                "7",
                "--until",
                "60",
                "--out",
                str(out),
                "--ablations",
                "no_benign_noise",
                "perfect_sensors",
            ]
        )
    )
    assert report["schema_version"] == "ds23.validity_report.v1"
    assert report["seed_count"] == 1
    assert (out / "validity-report.json").exists()
    assert (out / "validity-summary.md").exists()
    assert {item["name"] for item in report["ablations"]} == {"no_benign_noise", "perfect_sensors"}
    for item in report["ablations"]:
        assert item["status"] == "pass"
        assert item["runs"][0]["trace_path"]
        assert item["runs"][0]["baseline_trace_path"]
        assert item["runs"][0]["replay_ok"] is True
        assert item["runs"][0]["observation_leak_check"]["ok"] is True


def test_no_noise_directional_report_fields(tmp_path):
    report = run_validity_experiments(
        parse_args(["--seeds", "7", "--until", "60", "--out", str(tmp_path), "--ablations", "no_benign_noise"])
    )
    item = report["ablations"][0]
    assert item["status"] == "pass"
    checks = {check["metric"]: check for check in item["directional_checks"]}
    assert checks["false_positive_actions"]["status"] == "pass"
    assert checks["analyst_minutes"]["observed_aggregate_delta"] > 0
    assert checks["alert_count"]["observed_aggregate_delta"] > 0


def test_perfect_sensors_directional_report_fields(tmp_path):
    report = run_validity_experiments(
        parse_args(["--seeds", "7", "--until", "60", "--out", str(tmp_path), "--ablations", "perfect_sensors"])
    )
    item = report["ablations"][0]
    checks = {check["metric"]: check for check in item["directional_checks"]}
    assert item["status"] == "pass"
    assert checks["sensor_dropped_count"]["observed_aggregate_delta"] > 0
    assert checks["sensor_delayed_count"]["observed_aggregate_delta"] > 0
    assert checks["first_alert_timestamp"]["status"] == "pass"


def test_magic_observations_zero_baseline_is_directional_signal(tmp_path):
    report = run_validity_experiments(
        parse_args(["--seeds", "7", "--until", "60", "--out", str(tmp_path), "--ablations", "magic_observations"])
    )
    item = report["ablations"][0]
    checks = {check["metric"]: check for check in item["directional_checks"]}
    assert item["status"] == "pass"
    assert checks["true_positive_actions"]["observed_aggregate_delta"] < 0
    assert item["runs"][0]["observation_leak_check"]["ok"] is True
    assert "suspect_host" not in (tmp_path / "magic_observations" / "ablation" / "seed-7.jsonl").read_text()


def test_unsupported_ablation_fails_loudly(tmp_path):
    args = parse_args(["--out", str(tmp_path), "--ablations", "instant_actions"])
    with pytest.raises(SystemExit, match="unsupported ablations requested: instant_actions"):
        run_validity_experiments(args)


def test_allow_unimplemented_records_planned_ablation(tmp_path):
    report = run_validity_experiments(
        parse_args(["--out", str(tmp_path), "--ablations", "instant_actions", "--allow-unimplemented"])
    )
    item = report["ablations"][0]
    assert item["status"] == "unimplemented"
    assert item["supported"] is False
    assert "No instant-action scheduler" in item["blocker"]
