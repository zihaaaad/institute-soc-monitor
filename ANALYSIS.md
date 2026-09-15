# Performance, Scan Load and Failure Modes

## Scan load

Notation: `N` = configured addresses (31 x /24 = 7,874), `L` = live hosts, `D = N - L` dark addresses,
`t` = `probe_timeout_seconds` (0.25), `W` = `probe_workers` (256), `Pd` = discovery ports (9),
`Pf` = fingerprint ports (24).

| Phase | Connection attempts | Worst-case wall time |
| :--- | :--- | :--- |
| First 3 cycles (all dark IPs probed) | at most `N x Pd` ~ 71k | `D x Pd x t / W` ~ 69 s |
| Steady state | about `L + (D / 5) x Pd` | `(D / 5) x Pd x t / W` ~ 14 s |
| Fingerprinting (new hosts, then every 15 min) | `L x Pf` | `L x Pf x t / W` (500 hosts ~ 12 s) |

Live hosts usually answer on their first remembered port, so their per-cycle cost is a single
handshake. The default `scan_interval_seconds` is 120 for the 31-subnet configuration; cycles never
overlap, and a warning is logged when a sweep outlasts the interval.

Compared with the previous design (27 ports on every IP every 60 s, about 200k connection attempts per
minute), steady-state load drops by more than 90%.

**Memory:** O(N) for scheduling state (dark-streak counters), O(L) for host memory, detectors and
hostname cache. Hosts unseen for 24 hours are forgotten.

**Prometheus cardinality:** about `L x (5 + open services + findings)` series. Labels are bounded to
inventory attributes. Command lines and account names are never labels.

## Failure modes

| Scenario | Behaviour |
| :--- | :--- |
| Firewall drops probes (no RST) | Each port costs `t`; the host is only seen if some probed port answers or its MAC is visible |
| Host behind a router | MAC not visible, so the host is marked `unverified`, never `rogue`, and not WMI-audited by default |
| Randomised phone MAC | Vendor reads "Randomized / Locally Administered MAC"; `rogue` if not whitelisted |
| Reverse DNS / NetBIOS slow or hostile | NetBIOS 0.5 s timeout, results cached, names sanitised |
| SMB server rejects SMBv1 | Connection closed, reset, or error response, reported as not vulnerable |
| SMB check times out | Inconclusive; the previous result is kept |
| WMI host hangs | Connect capped at 2 min, bounded pool, host skipped while in flight |
| WMI access denied | `wmi_audit_success=0` and the error is logged; no detections are fabricated |
| Security log large | Only the lookback window is queried; `RecordNumber` de-duplication |
| Metrics port in use | Monitor exits with a clear error instead of silently moving to another port |
| Invalid config | Refuses to start (`ConfigError`) instead of scanning a guessed network |
| Prometheus down when reporting | Report status NO DATA, exit code 2 |
| Monitor stopped | Heartbeat panel turns red; report status STALE |
| Webhook slow or failing | One worker, bounded queue of 500, 10 s timeout; scanning is unaffected |

## Validation

`python -m unittest discover -s tests -t .` covers:

* SMBv1 request structure, and responses from live local socket servers (accept, error, close)
* ARP parsing, hostname sanitisation, real TCP probe against a local listener
* Failed-logon de-duplication, brute force and password spray thresholds, process and command-line rules
* Credential eligibility: never rogue, unverified or unmanaged hosts by default
* Scheduling back-off, stale series removal in the collector, no fake health value
* Report escaping of hostile hostnames, NO DATA and STALE handling
* Console auth, CSRF header requirement, CSP headers, disabled API docs
