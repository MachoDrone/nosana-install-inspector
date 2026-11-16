# Nosana installation inspector

A read-only checker for Ubuntu Nosana installations, including the standard
Podman-in-Docker launcher and legacy manual CLI attempts. Run it as your normal
host user. It inspects the existing installation without starting a host or job.

## Run directly from GitHub

No predownload, clone, chmod, temporary script, or dependency installation:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/MachoDrone/nosana-install-inspector/main/nosana-inspect.sh) --network
```

Or with wget:

```bash
bash <(wget -qO- https://raw.githubusercontent.com/MachoDrone/nosana-install-inspector/main/nosana-inspect.sh) --network
```

For optional privileged metadata, authenticate sudo first and keep the checker
itself running as your normal user:

```bash
sudo -v && bash <(curl -fsSL https://raw.githubusercontent.com/MachoDrone/nosana-install-inspector/main/nosana-inspect.sh) --sudo --network
```

Streaming into Bash also works. `pipefail` preserves download failures:

```bash
set -o pipefail
curl -fsSL https://raw.githubusercontent.com/MachoDrone/nosana-install-inspector/main/nosana-inspect.sh | bash -s -- --network
```

`main` supplies the latest checker. For a reproducible run, replace `main` in the
URL with a reviewed commit SHA. A failed process-substitution download may leave
Bash an empty script: always require the inspector header and summary before
treating a run as complete.

## What it checks

- Ubuntu release, kernel, virtualization, Secure Boot status, reboot marker,
  host GPU/driver queries, NVIDIA toolkit and persistence service.
- Normal-user Docker access, effective versus configured group membership,
  local daemon versions/runtimes, socket permissions, and optional sudo access.
- Existing outer Podman and inner Nosana containers: mounts, GPU request,
  `/dev/fuse`, gateway network, runtime identity, and installed node packages.
  The host CLI, updater wrapper, and installed node versions are kept separate.
- Wallet **metadata only**: numeric owner/group, mode, symlinks, ancestor
  traversal, ACLs when available, and access tests as the existing container's
  configured user. Root-owned state can be valid. Group/other read bits are a
  privacy warning; parent permissions can still restrict access.
- Available filesystem space/inodes and read-only filesystems. The 10 GiB / 5%
  thresholds are diagnostic heuristics, not Nosana qualification requirements.
- DNS settings, explicitly compared with the suggested **Google**
  `8.8.8.8` / `8.8.4.4` or **Cloudflare** `1.1.1.1` / `1.0.0.1` servers and their
  standard IPv6 equivalents. Mixed Google/Cloudflare is accepted. A single
  suggested server warns about missing redundancy. Other public DNS warns of a
  settings difference, not a proven network failure. A local stub/router/bridge
  address leaves its upstream provider unknown. If resolved's API is unavailable,
  its generated upstream file is labeled a possibly stale snapshot.
- DNS settings inside existing outer and node containers. With `--network`,
  DNS lookup is tested on host and in both containers; host HTTPS transport is
  tested against Nosana and Docker Registry. Registry HTTP 401 is normal for
  this unauthenticated transport probe and does not mean registry pulls work.
- Legacy host `@nosana/cli` **1.0.133**, whose onboarding uses the obsolete
  `/nodes/join-test-grid` route. Its bare error suppresses HTTP status/body;
  a final “Creating network” spinner does not prove where the failure occurred.

The checker never executes the launcher, installs packages, starts/stops/pulls
containers, creates a network, edits DNS/firewall rules, changes ownership or
modes, reads a wallet's contents, submits registration, signs, or spends funds.
It runs small metadata queries inside existing containers. Ordinary audit logs
and DNS caches may record those queries.

## Options and output

| Option | Effect |
| --- | --- |
| `--network` | Optional public DNS and HTTPS probes; no registration request |
| `--sudo` | Selected noninteractive privileged metadata queries; never prompts |
| `--json` | Structured output for comparing hosts |
| `--log /path/to/install.log` | Signature counts from the last 2 MiB; no raw log output |
| `--help` | Usage only |

Reports go to stdout; save one only if wanted:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/MachoDrone/nosana-install-inspector/main/nosana-inspect.sh) --sudo --network --json > nosana-inspection.json
```

Reports contain hostname, usernames, local paths, network settings, package
versions and container metadata. Review before sharing publicly. No environment
dump, raw installer/container logs, wallet address extraction, or key content is
included. Error stderr is deliberately omitted to avoid credential leakage;
timeouts and incomplete checks remain explicit. Log scanning is opt-in and
refuses conventional wallet/key paths, including symlinks to them.

`PASS` means the named check passed, **not** that the host qualified. `WARN`
requires context; `FAIL` identifies a specific unacceptable condition;
`UNKNOWN` means evidence is incomplete; `INFO` and `SKIP` describe scope.
Exit codes: `0` no warnings/failures (unknowns may remain), `1` warnings,
`2` failures or invalid invocation, `3` missing Python in the Bash launcher.

Python 3.8+ and Bash are required; standard Ubuntu includes Python 3. Other
missing tools produce incomplete checks and are never installed automatically.
Queries have time/output limits (normally 12 seconds and 128 KiB each), but a
host with many unavailable services can take several minutes overall.

Native `nosana-host`, rootless Docker, remote Docker endpoints, and custom state
layouts are not fully validated. Their metadata may appear but the inspector
does not infer correctness. The daemon inspected is always the local
`/var/run/docker.sock`; environment overrides are reported without their values.
Installed package versions can differ from already-loaded code during an update.
No CUDA compute test, new workload-network test, full firewall analysis, backend
ban lookup, or end-to-end onboarding is performed. Never use recursive chown,
chmod 777, or a world-writable Docker socket as a blanket repair.

## Development and evidence

Maintain `nosana-inspect.py`, then regenerate the distributable Bash file:

```bash
python3 build_launcher.py
python3 -m unittest discover -s tests -v
bash -n nosana-inspect.sh
```

Fixtures cover permissions, runtime identity distinctions, DNS policy, privacy,
missing tools/timeouts, output limits, and generated/streamed launcher behavior.
Live validation uses four Ubuntu 24.04.4 hosts with existing standard nested
containers. This does not establish support for every installation or Ubuntu
26.04. Lab reports are local and excluded from this repository.

Source contracts reviewed November 15, 2026:

- [Original installer](https://github.com/MachoDrone/MDbiginstaller/blob/cf19e865d3eaca435c4dce31be2ad98d3e5fe4ba/installer-beta.sh)
  and [DNS helper](https://github.com/MachoDrone/MDbiginstaller/blob/cf19e865d3eaca435c4dce31be2ad98d3e5fe4ba/dnsconfig.sh).
- [Official launcher](https://nosana.com/start.sh), script `1.1.2-3`, SHA-256
  `4e417c1f018cd71b74c151ec70d9bccccde67b59b9c69fc724444d632458f75b`.
- [Current host guidance](https://learn.nosana.com/hosts/grid-run.html).
- [Legacy 1.0.133 registration source](https://github.com/nosana-ci/nosana-cli/blob/a96dc07c814e4d5d875ded2589aa1dd8826bd935/src/services/NodeManager/node/register/index.ts)
  and [current registration client](https://github.com/nosana-ci/nosana-node/blob/3f07617a7c64820202cf55adbc69625bc4390d72/src/NodeManager/node/market/hostManager.ts).
- [Google DNS addresses](https://developers.google.com/speed/public-dns/docs/using)
  and [Cloudflare DNS addresses](https://developers.cloudflare.com/1.1.1.1/ip-addresses/).

The original Discord text names Ubuntu 24.04.2 “Trusty Tahr”; 24.04 is Noble
Numbat. The original installer's actual log filename is `install.log`, not
`installer.log`. Neither wording difference establishes a host fault.
