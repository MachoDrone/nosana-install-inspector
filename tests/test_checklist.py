"""Checklist presentation contracts from synthetic evidence, with no host access."""
import copy
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import types
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location(
    "checklist_inspector", Path(__file__).resolve().parents[1] / "nosana-inspect.py")
inspector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inspector)


def row(ident, status="PASS", detail="Observed successfully", evidence=None):
    result = {"id": ident, "status": status, "detail": detail}
    if evidence is not None:
        result["evidence"] = evidence
    return result


def healthy_report():
    checks = [row("os.baseline", "INFO", "Ubuntu 24.04 baseline")]
    for ident in ("gpu.host", "gpu.toolkit", "gpu.persistence", "gpu.outer", "gpu.cdi",
                  "docker.user_access", "docker.group", "runtime.node_state", "runtime.state_mount",
                  "runtime.mount", "runtime.privileged", "runtime.gpus", "runtime.fuse",
                  "runtime.node_socket", "runtime.socket_access", "runtime.gateway", "runtime.podman",
                  "runtime.network_backend", "storage.capacity", "storage.writable_mount", "network.clock",
                  "os.reboot", "network.dns_policy", "network.outer_dns_policy", "wallet.runtime_access",
                  "wallet.acl", "wallet.ancestors", "socket.acl", "directory.acl"):
        checks.append(row(ident))
    checks += [row("runtime.outer", "INFO", json.dumps({"image": "nosana/podman:fixture", "running": True})),
               row("runtime.node", "INFO", json.dumps({"image": "nosana/nosana-node:fixture", "running": True})),
               row("network.node_resolver", "INFO", "Container nameservers", "nameserver 192.168.101.1"),
               row("network.node_dns_policy", "UNKNOWN", "Proxy upstream is not determined by its address"),
               row("wallet.metadata", "INFO", "mode=0600 uid=0 gid=0 type=regular file", "/PRIVATE_EVIDENCE/nosana_key.json"),
               row("socket.metadata", "INFO", "mode=0660 uid=0 gid=999 type=socket", "/var/run/docker.sock"),
               row("directory.metadata", "INFO", "mode=0700 uid=0 gid=0 type=directory", "/PRIVATE_EVIDENCE/state")]
    for ident in ("network.dns", "network.outer_dns", "network.node_dns", "network.https"):
        for host in ("api.nosana.com", "registry-1.docker.io"):
            if ident == "network.https":
                code = "200" if host == "api.nosana.com" else "401"
                detail = host + " TLS/HTTP transport: HTTP " + code + ". HTTP errors (including registry 401) can still demonstrate transport; this is not successful onboarding."
            elif ident == "network.dns":
                detail = host + ": resolved"
            else:
                detail = host + ": resolved in existing container"
            checks.append(row(ident, detail=detail))
    return {"host": "fixture-host", "checks": checks}


def by_label(report, label):
    matches = [item for item in inspector.checklist(report) if item["label"] == label]
    if len(matches) != 1:
        raise AssertionError("Expected exactly one %r, got %r" % (label, matches))
    return matches[0]


class ChecklistTests(unittest.TestCase):
    def test_compact_nn02_like_checklist_explains_two_actionable_items(self):
        report = healthy_report()
        for entry in report["checks"]:
            if entry["id"] == "network.dns_policy":
                entry.update(status="UNKNOWN", detail="Live resolver query timed out")
            if entry["id"] == "wallet.metadata":
                entry["detail"] = "mode=0644 uid=0 gid=0 type=regular file"
        report["checks"] += [row("wallet.read_mode", "WARN", "Wallet mode has group and other reads"),
                             row("network.upstream_file_policy", "INFO", "Saved file matches suggested Google addresses")]
        items = inspector.checklist(report)
        self.assertGreaterEqual(len(items), 15)
        self.assertLessEqual(len(items), 20)
        failures = [item for item in items if not item["ok"]]
        self.assertEqual({item["label"] for item in failures},
                         {"Google/Cloudflare DNS settings", "Wallet file permissions"})
        self.assertIn("host's live DNS", by_label(report, "Google/Cloudflare DNS settings")["explanation"])
        self.assertIn("group/other reads", by_label(report, "Wallet file permissions")["explanation"])
        rendered = inspector.render_checklist(report)
        self.assertIn("✅", rendered)
        self.assertIn("❌", rendered)
        for technical in ("[PASS]", "[INFO]", "wallet.read_mode", "runtime.outer", "PRIVATE_EVIDENCE",
                          '"running": true', "mode=0644", "uid=0"):
            self.assertNotIn(technical, rendered)
        for item in items:
            if not item["ok"]:
                self.assertTrue(item["explanation"].strip())

    def test_missing_or_unknown_essential_evidence_cannot_be_green(self):
        cases = (("gpu.host", "NVIDIA GPU detected"),
                 ("wallet.runtime_access", "Nosana can access its wallet"),
                 ("socket.acl", "Folder and Docker socket permissions"),
                 ("network.clock", "System clock synchronized"),
                 ("runtime.node", "Nosana containers running"))
        for ident, label in cases:
            for action in ("missing", "unknown"):
                with self.subTest(ident=ident, action=action):
                    report = healthy_report()
                    if action == "missing":
                        report["checks"] = [entry for entry in report["checks"] if entry["id"] != ident]
                    else:
                        for entry in report["checks"]:
                            if entry["id"] == ident:
                                entry.update(status="UNKNOWN", detail="Query unavailable")
                                entry.pop("evidence", None)
                    item = by_label(report, label)
                    self.assertFalse(item["ok"])
                    self.assertTrue(item["explanation"])

    def test_expected_node_dns_proxy_requires_verified_gateway_and_address(self):
        report = healthy_report()
        self.assertTrue(by_label(report, "Google/Cloudflare DNS settings")["ok"])
        self.assertTrue(by_label(report, "DNS lookups")["ok"])
        for alteration in ("gateway_missing", "gateway_unknown", "foreign_proxy"):
            with self.subTest(alteration=alteration):
                changed = copy.deepcopy(report)
                if alteration == "gateway_missing":
                    changed["checks"] = [entry for entry in changed["checks"] if entry["id"] != "runtime.gateway"]
                else:
                    for entry in changed["checks"]:
                        if alteration == "gateway_unknown" and entry["id"] == "runtime.gateway":
                            entry.update(status="UNKNOWN", detail="Network query unavailable")
                        if alteration == "foreign_proxy" and entry["id"] == "network.node_resolver":
                            entry["evidence"] = "nameserver 192.168.99.1"
                self.assertFalse(by_label(changed, "Google/Cloudflare DNS settings")["ok"])

    def test_stopped_node_is_red_even_when_other_container_is_running(self):
        report = healthy_report()
        for entry in report["checks"]:
            if entry["id"] == "runtime.node":
                entry["detail"] = json.dumps({"image": "nosana/nosana-node:fixture", "running": False})
        report["checks"].append(row("runtime.node_stopped", "WARN", "Stopped"))
        item = by_label(report, "Nosana containers running")
        self.assertFalse(item["ok"])
        self.assertIn("stopped", item["explanation"])

    def test_one_bad_member_is_not_hidden_by_successful_group_members(self):
        fixtures = (("storage.capacity", "Free disk space and writable storage", "free"),
                    ("runtime.mount", "Nosana container setup", "mount"),
                    ("wallet.acl", "Wallet file permissions", "access rules"))
        for ident, label, explanation in fixtures:
            with self.subTest(ident=ident):
                report = healthy_report()
                report["checks"].append(row(ident, "WARN", "One member needs review"))
                item = by_label(report, label)
                self.assertFalse(item["ok"])
                self.assertIn(explanation, item["explanation"].lower())

    def test_not_found_native_service_is_not_a_green_service_health_claim(self):
        report = healthy_report()
        report["checks"].append(row("native.service", "PASS", "Query completed",
                                    "LoadState=not-found\nActiveState=inactive\nUser=\nGroup="))
        items = inspector.checklist(report)
        self.assertFalse(any(item["ok"] and "service" in item["label"].lower() for item in items))
        self.assertNotIn("not-found", inspector.render_checklist(report))

    def test_skipped_network_tests_produce_no_green_internet_checks(self):
        report = healthy_report()
        network_results = {"network.dns", "network.outer_dns", "network.node_dns", "network.https"}
        report["checks"] = [entry for entry in report["checks"] if entry["id"] not in network_results]
        report["checks"].append(row("network.external", "SKIP", "External probes not requested"))
        items = inspector.checklist(report)
        self.assertFalse(any(item["label"] in ("DNS lookups", "HTTPS connections to Nosana and Docker") for item in items))
        self.assertIn("Internet tests were not run", inspector.render_checklist(report))

    def test_one_endpoint_success_cannot_substitute_for_missing_peer_result(self):
        fixtures = (("network.dns", "DNS lookups"),
                    ("network.outer_dns", "DNS lookups"),
                    ("network.node_dns", "DNS lookups"),
                    ("network.https", "HTTPS connections to Nosana and Docker"))
        for ident, label in fixtures:
            with self.subTest(ident=ident):
                report = healthy_report()
                report["checks"] = [entry for entry in report["checks"]
                                    if not (entry["id"] == ident and entry["detail"].split()[0].rstrip(":") == "registry-1.docker.io")]
                item = by_label(report, label)
                self.assertFalse(item["ok"])
                self.assertTrue(item["explanation"])

    def test_main_keeps_default_details_and_json_output_modes_distinct(self):
        checks = healthy_report()["checks"]
        for args in ([], ["--details"], ["--json"]):
            with self.subTest(args=args):
                captured = io.StringIO()
                with mock.patch.object(inspector.sys, "argv", ["nosana-inspect.py"] + args), \
                     mock.patch.object(inspector.os, "geteuid", return_value=1000), \
                     mock.patch.object(inspector.os, "uname", return_value=types.SimpleNamespace(nodename="fixture-host")), \
                     mock.patch.object(inspector, "Inspector") as factory, contextlib.redirect_stdout(captured):
                    factory.return_value.collect.return_value = copy.deepcopy(checks)
                    self.assertEqual(inspector.main(), 0)
                output = captured.getvalue()
                if args == ["--json"]:
                    decoded = json.loads(output)
                    self.assertEqual(decoded["checks"], checks)
                    self.assertEqual(decoded["host"], "fixture-host")
                    self.assertNotIn("Checking installation", output)
                    self.assertNotIn("✅", output)
                elif args == ["--details"]:
                    self.assertIn("[PASS] gpu.host", output)
                    self.assertIn("[INFO] wallet.metadata", output)
                    self.assertNotIn("Checking installation", output)
                    self.assertNotIn("✅", output)
                else:
                    self.assertIn("✅ NVIDIA GPU detected", output)
                    self.assertIn("Checking installation", output)
                    self.assertNotIn("[PASS]", output)
                    self.assertNotIn("wallet.metadata", output)
                    self.assertNotIn("PRIVATE_EVIDENCE", output)


if __name__ == "__main__":
    unittest.main()
