"""Independent safety and diagnostic fixtures; no containers or hosts contacted."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


MODULE = Path(__file__).resolve().parents[1] / "nosana-inspect.py"
spec = importlib.util.spec_from_file_location("nosana_inspect", MODULE)
inspector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inspector)


def result(out="", rc=0, error=""):
    return {"out": out, "rc": rc, "error": error}


def make_inspector(**options):
    args = argparse.Namespace(sudo=False, network=False, log=None)
    for name, value in options.items():
        setattr(args, name, value)
    return inspector.Inspector(args)


def rows_named(subject, ident):
    return [row for row in subject.rows if row["id"] == ident]


class ModeTests(unittest.TestCase):
    def test_private_wallet_mode_has_no_permission_failure(self):
        rows = inspector.mode_findings(0o600, "wallet")
        self.assertFalse(any(row[0] in ("FAIL", "WARN") for row in rows))

    def test_readable_wallet_warns_without_claiming_effective_exposure(self):
        rows = inspector.mode_findings(0o644, "wallet")
        self.assertTrue(any(row[0] == "WARN" and row[1] == "wallet.read_mode" for row in rows))
        self.assertFalse(any(row[0] == "FAIL" for row in rows))
        self.assertIn("traversal", " ".join(row[2] for row in rows).lower())

    def test_writable_wallet_and_public_runtime_socket_fail(self):
        for mode, kind, ident in ((0o666, "wallet", "wallet.write_mode"),
                                  (0o666, "socket", "socket.other_mode")):
            with self.subTest(kind=kind):
                self.assertIn(("FAIL", ident), [(row[0], row[1]) for row in inspector.mode_findings(mode, kind)])

    def test_group_runtime_socket_is_not_public(self):
        self.assertEqual(inspector.mode_findings(0o660, "socket"), [])


class DNSPolicyTests(unittest.TestCase):
    def test_suggested_google_cloudflare_and_mixed_pairs_pass(self):
        fixtures = (("8.8.8.8", "8.8.4.4"), ("1.1.1.1", "1.0.0.1"),
                    ("2001:4860:4860::8888", "2001:4860:4860::8844"),
                    ("2606:4700:4700::1111", "2606:4700:4700::1001"),
                    ("8.8.8.8", "1.1.1.1"))
        for addresses in fixtures:
            with self.subTest(addresses=addresses):
                status, detail = inspector.dns_policy(list(addresses))
                self.assertEqual(status, "PASS")
                self.assertIn("separately", detail)

    def test_single_suggested_server_warns_about_missing_secondary(self):
        for address in ("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"):
            with self.subTest(address=address):
                status, detail = inspector.dns_policy([address])
                self.assertEqual(status, "WARN")
                self.assertIn("secondary", detail)

    def test_nonstandard_and_mixed_public_provider_is_settings_warning(self):
        for addresses in (["9.9.9.9", "149.112.112.112"], ["8.8.8.8", "9.9.9.9"]):
            with self.subTest(addresses=addresses):
                status, detail = inspector.dns_policy(addresses)
                self.assertEqual(status, "WARN")
                self.assertIn("not proof DNS is broken", detail)

    def test_local_proxy_upstream_remains_unknown_even_with_known_peer(self):
        for address in ("127.0.0.53", "127.0.0.11", "192.168.0.1", "10.88.0.1", "fe80::1", "fd00::1"):
            for known_peer in ([], ["1.1.1.1"]):
                with self.subTest(address=address, known_peer=known_peer):
                    status, detail = inspector.dns_policy([address] + known_peer)
                    self.assertEqual(status, "UNKNOWN")
                    self.assertIn("upstream provider cannot be inferred", detail)
        self.assertEqual(inspector.dns_policy([])[0], "UNKNOWN")

    def test_dns_parsing_normalizes_ipv6_names_and_interface_suffixes(self):
        text = ("Link 2 (enp4s0): 8.8.8.8#dns.google\n"
                "2001:4860:4860:0:0:0:0:8888#dns.google\n"
                "fe80::1%enp4s0 [2606:4700:4700::1111] 8.8.8.8 invalid.address\n")
        self.assertEqual(inspector.dns_addresses(text),
                         ["8.8.8.8", "2001:4860:4860::8888", "fe80::1", "2606:4700:4700::1111"])


class PrivacyTests(unittest.TestCase):
    def test_url_and_simple_secret_values_are_redacted(self):
        text = "https://username:SENTINELPASS@example.invalid/a?token=SENTINELQUERY password=SENTINELPASSWORD api_key=SENTINELKEY"
        cleaned = inspector.clean(text)
        for marker in ("SENTINELPASS", "SENTINELQUERY", "SENTINELPASSWORD", "SENTINELKEY"):
            self.assertNotIn(marker, cleaned)

    def test_authorization_scheme_does_not_leave_credential_behind(self):
        for scheme in ("Bearer", "Basic"):
            with self.subTest(scheme=scheme):
                self.assertNotIn("SENTINELAUTH", inspector.clean("Authorization: %s SENTINELAUTH" % scheme))

    def test_quoted_json_secret_values_are_redacted(self):
        fixtures = ('{"Authorization":"Bearer SENTINELAUTH"}',
                    '{"token":"SENTINELTOKEN"}',
                    '{"password": "SENTINELPASSWORD"}',
                    "{'api_key': 'SENTINELKEY'}")
        for value in fixtures:
            with self.subTest(value=value):
                self.assertNotIn("SENTINEL", inspector.clean(value))

    def test_terminal_sequences_and_long_output_are_bounded(self):
        clean = inspector.clean("\x1b[31mred\x1b[0m\x00\x07" + "x" * 5000)
        self.assertNotIn("\x1b", clean)
        self.assertNotIn("\x00", clean)
        self.assertLessEqual(len(clean), 4000)

    def test_failed_command_does_not_publish_stdout_or_stderr(self):
        subject = make_inspector()
        with mock.patch.object(inspector, "run", return_value=result("SENTINELSTDOUT", 1, "command failed (exit 1)")):
            subject.command("sample", ["sample"])
        self.assertNotIn("SENTINELSTDOUT", json.dumps(subject.rows))
        actual = inspector.run([sys.executable, "-c", "import sys;sys.stderr.write('Authorization: Bearer SENTINELSTDERR');sys.exit(1)"])
        self.assertEqual(actual["rc"], 1)
        self.assertNotIn("SENTINELSTDERR", json.dumps(actual))

    def test_opt_in_log_outputs_counts_never_raw_secret(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "installer.log"
            path.write_text("Authorization: Bearer SENTINELLOG\nError whilst submiting onboarding request\npermission denied\n")
            subject = make_inspector(log=str(path))
            subject.logs()
        serialized = json.dumps(subject.rows)
        self.assertNotIn("SENTINELLOG", serialized)
        counts = json.loads(rows_named(subject, "logs.signatures")[0]["evidence"])
        self.assertEqual(counts["legacy_onboarding_error"], 1)
        self.assertEqual(counts["permission_denied"], 1)

    def test_log_flag_refuses_wallet_even_through_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            secret = Path(temp) / "nosana_key.json"
            secret.write_text("SENTINELKEYDATA")
            link = Path(temp) / "innocent.log"
            link.symlink_to(secret)
            for path in (secret, link):
                with self.subTest(path=path):
                    subject = make_inspector(log=str(path))
                    with mock.patch.object(Path, "open", side_effect=AssertionError("Wallet was opened")):
                        subject.logs()
                    self.assertEqual(rows_named(subject, "logs.signatures")[0]["status"], "UNKNOWN")

    def test_log_counts_only_last_two_mebibytes(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "installer.log"
            path.write_bytes(b"permission denied\n" + b"x" * (2 * 1024 * 1024))
            subject = make_inspector(log=str(path))
            subject.logs()
        counts = json.loads(rows_named(subject, "logs.signatures")[0]["evidence"])
        self.assertEqual(counts["permission_denied"], 0)


class CommandTests(unittest.TestCase):
    def test_missing_timeout_and_execution_errors_remain_distinct(self):
        with tempfile.TemporaryDirectory() as temp:
            nonexec = Path(temp) / "not-executable"
            nonexec.write_text("plain text")
            fixtures = (([str(Path(temp) / "not-present")], 127, "unavailable"),
                        ([sys.executable, "-c", "import time;print('SENTINELPARTIAL',flush=True);time.sleep(5)"], 124, "incomplete"),
                        ([str(nonexec)], 126, "could not be executed"))
            for argv, rc, phrase in fixtures:
                with self.subTest(rc=rc):
                    actual = inspector.run(argv, timeout=0.1)
                    self.assertEqual(actual["rc"], rc)
                    self.assertIn(phrase, actual["error"])
                    self.assertEqual(actual["out"], "")

    def test_runner_has_timeout_no_shell_and_no_interactive_input(self):
        actual = inspector.run([sys.executable, "-c", "import json,sys;print(json.dumps([sys.argv[1],sys.stdin.read()]))", "literal;echo unsafe"], timeout=3)
        self.assertEqual(actual["rc"], 0)
        self.assertEqual(json.loads(actual["out"]), ["literal;echo unsafe", ""])

    def test_output_limit_discards_incomplete_data(self):
        actual = inspector.run([sys.executable, "-c", "import sys;sys.stdout.write('x'*200000)"], timeout=3)
        self.assertEqual(actual["rc"], 125)
        self.assertIn("output limit", actual["error"])
        self.assertEqual(actual["out"], "")


class WalletTests(unittest.TestCase):
    def wallet_with(self, runtime_result=0, operator_access=False):
        subject = make_inspector()
        context = ["docker", "exec", "podman", "podman", "exec", "nosana-node"]
        def fake_run(argv, timeout=12):
            if argv[:len(context)] == context:
                return result(rc=runtime_result, error="timed out; result incomplete" if runtime_result == 124 else "")
            return result()
        def metadata(path, kind):
            return {"mode": 0o700 if kind == "directory" else 0o600,
                    "uid": 0, "gid": 0, "kind": "directory" if kind == "directory" else "regular file"}
        with mock.patch.object(subject, "path_check", side_effect=metadata), \
             mock.patch.object(subject, "storage"), \
             mock.patch.object(inspector.os, "access", return_value=operator_access), \
             mock.patch.object(inspector, "run", side_effect=fake_run) as calls:
            subject.wallet("/home/operator/.nosana", context)
        return subject, [call.args[0] for call in calls.call_args_list]

    def test_rootful_node_can_use_root_owned_key_without_login_user_access(self):
        subject, commands = self.wallet_with(operator_access=False)
        self.assertEqual(rows_named(subject, "wallet.runtime_access")[0]["status"], "PASS")
        self.assertFalse(any(row["status"] == "FAIL" for row in subject.rows))
        self.assertTrue(any(command[-2:] == ["-r", "/root/.nosana/nosana_key.json"] for command in commands))
        self.assertFalse(any("cat" in command or "chmod" in command or "chown" in command for command in commands))

    def test_manual_cli_access_checks_parent_traversal_and_write(self):
        subject = make_inspector()
        with mock.patch.object(subject, "path_check", return_value={"uid": 1000, "mode": 0o600}), \
             mock.patch.object(subject, "storage"), \
             mock.patch.object(inspector, "run", return_value=result()), \
             mock.patch.object(inspector.os, "access", side_effect=[True, False]) as access:
            subject.wallet("/state")
        self.assertEqual(rows_named(subject, "wallet.operator_access")[0]["status"], "WARN")
        self.assertIn(mock.call("/state", os.W_OK | os.X_OK), access.call_args_list)
        self.assertEqual(rows_named(subject, "wallet.runtime_access")[0]["status"], "UNKNOWN")

    def test_runtime_timeout_is_unknown_not_a_proven_access_failure(self):
        subject, _ = self.wallet_with(runtime_result=124)
        row = rows_named(subject, "wallet.runtime_access")[0]
        self.assertEqual(row["status"], "UNKNOWN")
        self.assertTrue("incomplete" in row["detail"] or "timed out" in row["detail"])

    def test_uninspectable_wallet_does_not_receive_missing_or_secure_verdict(self):
        subject = make_inspector()
        with mock.patch.object(subject, "metadata", return_value=None), \
             mock.patch.object(inspector, "run", return_value=result(rc=1)):
            self.assertIsNone(subject.path_check("/denied/nosana_key.json", "wallet"))
        self.assertEqual(subject.rows[0]["status"], "UNKNOWN")
        self.assertIn("inaccessible", subject.rows[0]["detail"])
        self.assertFalse(any(row["status"] == "PASS" for row in subject.rows))

    def test_symlink_target_assessed_acl_absence_is_explicit(self):
        subject = make_inspector()
        metadata = {"mode": 0o600, "uid": 0, "gid": 0, "kind": "regular file"}
        def fake_run(argv, timeout=12):
            if argv[0].endswith("readlink"):
                return result("/secure/private/nosana_key.json\n")
            if argv[0].endswith("getfacl"):
                return result(rc=127, error="command unavailable")
            raise AssertionError("Unexpected command: %r" % argv)
        with mock.patch.object(subject, "metadata", return_value=metadata), \
             mock.patch.object(inspector, "run", side_effect=fake_run):
            subject.path_check("/home/operator/.nosana/nosana_key.json", "wallet")
        self.assertEqual(rows_named(subject, "wallet.acl")[0]["status"], "UNKNOWN")
        self.assertEqual(rows_named(subject, "wallet.symlink")[0]["evidence"], "/secure/private/nosana_key.json")

    def test_named_acl_cannot_be_claimed_owner_only(self):
        subject = make_inspector()
        metadata = {"mode": 0o640, "uid": 1000, "gid": 1000, "kind": "regular file"}
        def fake_run(argv, timeout=12):
            return result("user::rw-\nuser:1001:r--\ngroup::---\nmask::r--\nother::---\n") if argv[0].endswith("getfacl") else result(rc=1)
        with mock.patch.object(subject, "metadata", return_value=metadata), \
             mock.patch.object(inspector, "run", side_effect=fake_run):
            subject.path_check("/state/nosana_key.json", "wallet")
        self.assertEqual(rows_named(subject, "wallet.acl")[0]["status"], "WARN")


class RuntimeTests(unittest.TestCase):
    def test_container_nameservers_are_selected_without_unrequested_lookups(self):
        subject = make_inspector(network=False)
        context = ["docker", "exec", "podman"]
        config = "# local resolver\nsearch PRIVATESEARCH.internal\ndomain PRIVATEDOMAIN.internal\nnameserver 127.0.0.11\n  nameserver 1.1.1.1\noptions ndots:0\n"
        with mock.patch.object(inspector, "run", return_value=result(config)) as command:
            subject.container_dns(context, "outer")
        command.assert_called_once_with(context + ["cat", "/etc/resolv.conf"])
        row = rows_named(subject, "network.outer_resolver")[0]
        self.assertEqual(row["evidence"].splitlines(), ["nameserver 127.0.0.11", "  nameserver 1.1.1.1"])
        published = json.dumps(subject.rows)
        for omitted in ("PRIVATESEARCH", "PRIVATEDOMAIN", "ndots"):
            self.assertNotIn(omitted, published)
        self.assertFalse(rows_named(subject, "network.outer_dns"))

    def test_container_lookup_failures_distinguish_unavailable_evidence(self):
        fixtures = ((0, "", "PASS"), (1, "lookup failed", "WARN"),
                    (2, "name not found", "WARN"), (127, "command unavailable", "UNKNOWN"),
                    (124, "timed out; result incomplete", "UNKNOWN"))
        for nodejs in (False, True):
            for rc, error, expected in fixtures:
                with self.subTest(nodejs=nodejs, rc=rc):
                    subject = make_inspector(network=True)
                    context = ["docker", "exec", "fixture"]
                    calls = []
                    def fake_run(argv, timeout=12):
                        if argv[-2:] == ["cat", "/etc/resolv.conf"]:
                            return result("nameserver 127.0.0.11\n")
                        calls.append((argv, timeout))
                        return result("address-output-is-not-published", rc, error)
                    with mock.patch.object(inspector, "run", side_effect=fake_run):
                        subject.container_dns(context, "fixture", nodejs=nodejs)
                    rows = rows_named(subject, "network.fixture_dns")
                    self.assertEqual([row["status"] for row in rows], [expected, expected])
                    self.assertEqual([argv[-1] for argv, _ in calls], ["api.nosana.com", "registry-1.docker.io"])
                    self.assertTrue(all(timeout == 8 for _, timeout in calls))
                    self.assertTrue(all(argv[:len(context)] == context for argv, _ in calls))
                    self.assertTrue(all(argv[len(context)] == ("node" if nodejs else "getent") for argv, _ in calls))
                    self.assertNotIn("address-output-is-not-published", json.dumps(rows))
                    if rc:
                        self.assertTrue(all(error in row["detail"] for row in rows))

    def test_sudo_only_docker_is_not_reported_as_daemon_absent(self):
        subject = make_inspector(sudo=True)
        subject.sudo = True
        def fake_run(argv, timeout=12):
            if "version" in argv:
                return result("29.0 29.0") if argv[0] == "sudo" else result(rc=1, error="command failed (exit 1)")
            return result()
        with mock.patch.object(subject, "path_check"), mock.patch.object(subject, "wallet"), \
             mock.patch.object(subject, "json_command", return_value=None), \
             mock.patch.object(inspector, "run", side_effect=fake_run):
            subject.runtimes()
        self.assertEqual(rows_named(subject, "docker.user_access")[0]["status"], "WARN")
        self.assertTrue(rows_named(subject, "docker.versions"))
        self.assertFalse(rows_named(subject, "docker.daemon"))

    def test_remote_docker_override_is_not_used_or_disclosed(self):
        subject = make_inspector()
        commands = []
        def fake_run(argv, timeout=12):
            commands.append(argv)
            return result(rc=127, error="command unavailable")
        with mock.patch.dict(os.environ, {"DOCKER_HOST": "https://user:SENTINELENV@remote.invalid"}), \
             mock.patch.object(subject, "path_check"), mock.patch.object(subject, "wallet"), \
             mock.patch.object(inspector, "run", side_effect=fake_run):
            subject.runtimes()
        self.assertNotIn("SENTINELENV", json.dumps(subject.rows))
        self.assertTrue(all("unix:///var/run/docker.sock" in command for command in commands))

    def test_host_cli_warning_does_not_relabel_current_node(self):
        rows = inspector.legacy_cli_findings("1.0.133")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "WARN")
        self.assertIn("/nodes/join-test-grid", rows[0][2])
        self.assertIn("running node", rows[0][2])
        self.assertEqual(inspector.legacy_cli_findings("1.1.91"), [])

    def test_nested_inspection_commands_never_mutate_or_read_key(self):
        subject = make_inspector()
        commands = []
        outer = {"image": "nosana/podman:v1.1.2", "user": "root", "running": True, "userns": "",
                 "mounts": [{"Type": "bind", "Source": "/home/operator/.nosana", "Destination": "/root/.nosana", "RW": True},
                            {"Type": "volume", "Source": "/var/lib/docker/volumes/cache/_data", "Destination": "/var/lib/containers", "RW": True},
                            {"Type": "bind", "Source": "/run/nvidia-persistenced", "Destination": "/run/nvidia-persistenced", "RW": True, "Propagation": "rslave"}]}
        node = {"image": "nosana/nosana-node:latest", "user": "root", "running": True, "userns": "",
                "mounts": [{"Type": "bind", "Source": "/root/.nosana", "Destination": "/root/.nosana", "RW": True},
                           {"Type": "bind", "Source": "/podman.sock", "Destination": "/root/.nosana/podman/podman.sock", "RW": True}]}
        def fake_run(argv, timeout=12):
            commands.append(argv)
            if "inspect" in argv and "--format" in argv:
                fmt = argv[argv.index("--format") + 1]
                if '"privileged"' in fmt:
                    return result(json.dumps({"privileged": True, "gpus": [{}], "devices": [{"PathInContainer": "/dev/fuse"}]}))
                if '"image"' in fmt:
                    return result(json.dumps(node if argv[-1] == "nosana-node" else outer))
            if "-e" in argv:
                return result('{"name":"@nosana/node","version":"1.1.91","node":"v24.0.0"}')
            return result("ok")
        with mock.patch.object(subject, "path_check", return_value={"uid": 0, "mode": 0o600}), \
             mock.patch.object(subject, "storage"), mock.patch.object(inspector.os, "access", return_value=False), \
             mock.patch.object(inspector, "run", side_effect=fake_run):
            subject.runtimes()
        forbidden = {"chmod", "chown", "start", "stop", "restart", "run", "pull", "create", "rm", "register", "join-test-grid"}
        for command in commands:
            self.assertFalse(forbidden.intersection(command), command)
            if any("nosana_key.json" in arg for arg in command):
                self.assertTrue("namei" in " ".join(command) or "test" in command, command)
            if "-e" in command:
                self.assertIn('package.json', command[-1])
                self.assertIn('@nosana/node', command[-1])
                self.assertNotIn("nosana_key", command[-1])
        package = rows_named(subject, "runtime.node_package")[0]
        self.assertIn("1.1.91", package["evidence"])
        self.assertEqual(rows_named(subject, "wallet.runtime_access")[0]["status"], "PASS")


class LauncherTests(unittest.TestCase):
    def test_committed_launcher_matches_fresh_generated_source(self):
        root = MODULE.parent
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp)
            for name in ("build_launcher.py", "nosana-inspect.py"):
                shutil.copyfile(root / name, target / name)
            generated = subprocess.run([sys.executable, str(target / "build_launcher.py")],
                                       capture_output=True, timeout=5)
            self.assertEqual(generated.returncode, 0, generated.stderr.decode())
            self.assertEqual((root / "nosana-inspect.sh").read_bytes(),
                             (target / "nosana-inspect.sh").read_bytes())

    def test_bash_syntax_and_streamed_help(self):
        launcher = (MODULE.parent / "nosana-inspect.sh").read_bytes()
        syntax = subprocess.run(["bash", "-n"], input=launcher, capture_output=True, timeout=5)
        self.assertEqual(syntax.returncode, 0, syntax.stderr.decode())
        streamed = subprocess.run(["bash", "-s", "--", "--help"], input=launcher,
                                  capture_output=True, timeout=5)
        self.assertEqual(streamed.returncode, 0, streamed.stderr.decode())
        self.assertIn(b"--sudo", streamed.stdout)
        self.assertIn(b"--network", streamed.stdout)
        self.assertIn(b"--log", streamed.stdout)
        self.assertNotIn(b"[PASS]", streamed.stdout)


if __name__ == "__main__":
    unittest.main()
