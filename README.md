# cidr-check

A CI linter for firewall-style CIDR rule files. It catches the rules that
quietly hurt you: SSH or a database port open to the entire internet, a
`deny` that can never match because an earlier `allow` already covers it,
duplicate rules, and CIDRs written with host bits set.

Pure Python standard library (`ipaddress`). No cloud account, no API
keys - it lints a text file, so it works with whatever generates your
rules.

## The problem

Firewall rules accrete. Someone opens `0.0.0.0/0` to port 22 "temporarily",
someone else adds a `deny` below an `allow` that already swallows it, and
review diffing ten near-identical lines stops seeing them. The failure
modes are silent until they're expensive. cidr-check reads the same file
the human was supposed to review and says exactly which lines deserve a
look and why.

## Rule file format

One rule per line, `#` comments and blank lines allowed:

```
allow tcp 0.0.0.0/0 443        # action proto cidr ports
allow tcp 203.0.113.0/24 22    # office SSH only
deny tcp 0.0.0.0/0 22
allow udp 10.0.0.0/8 10000-20000
```

- action: `allow` or `deny`
- proto: `tcp`, `udp`, or `any`
- cidr: a CIDR (RFC 4632 prefix notation), or a bare address (read as a
  single host, /32 or /128)
- ports: a number (`443`), a range (`8000-8080`), or `any`

## Usage

```bash
python3 cidr_check.py firewall.txt
python3 cidr_check.py prod.txt staging.txt --fail-on-warning
python3 cidr_check.py fw.txt --sensitive-ports 22,2222,3306 --format json
```

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Clean (warnings only when `--fail-on-warning` is off) |
| 1 | Findings present (errors, or warnings with `--fail-on-warning`) |
| 2 | Input problem: unreadable or unparseable file |

Example output:

```
firewall.txt:4 [error] world-open-admin: allows the entire internet (0.0.0.0/0) to reach sensitive port(s) 22 tcp; remote-access and data services should not face the public internet (the port list is a heuristic - tune with --sensitive-ports).
firewall.txt:9 [error] shadowed-deny: deny rule can never match: earlier allow rule at line 6 already covers this whole space (assuming first-match-wins evaluation).
cidr-check: 2 error(s), 0 warning(s)
```

## Rules

| Rule | Severity | Trigger |
|---|---|---|
| `world-open-admin` | error | `allow` from `0.0.0.0/0` or `::/0` covering a sensitive port (built-in list: SSH, RDP, Telnet, FTP, SMB, VNC, MySQL, PostgreSQL, MSSQL, Redis, Elasticsearch, Memcached, MongoDB) |
| `world-open` | warning | `allow` from the world on any other port - sometimes intended (80/443), hence a warning |
| `shadowed-deny` | error | a `deny` fully covered by an earlier `allow` (the deny can never match) |
| `unreachable-rule` | warning | an `allow` fully covered by an earlier `deny` |
| `redundant-rule` | warning | a rule fully covered by an earlier rule with the same action |
| `host-bits-set` | warning | a CIDR with host bits set (`10.0.0.1/24`); interpreted as the masked network (`10.0.0.0/24`) |

Coverage means: same IP version, subnet containment, protocol match
(`any` covers `tcp`/`udp`), and port-range containment. So
`allow tcp 10.0.0.0/8 443` followed by `deny tcp 10.0.0.0/8 443-444` is
NOT shadowed (port 444 still denied), and the classic guard pattern
`allow tcp 10.1.0.0/16 443` before `deny tcp 10.0.0.0/8 443` is clean.

## Semantics assumption and caveats

- Rules are evaluated top to bottom, first match wins (iptables-style).
  Some systems don't work this way: AWS security groups, for example, are
  allow-only with union semantics, so `shadowed-deny` reasoning doesn't
  apply to them. Check your firewall's model before trusting the shadow
  rules.
- The sensitive-port list is a heuristic, labeled as such in the finding
  message; replace it with `--sensitive-ports`.
- This is a static lint of one file. It cannot see rules managed by other
  tools, security-group references, or NAT.

## Options

```
--sensitive-ports LIST   comma-separated ports replacing the built-in list
--ignore RULE            suppress a rule by name (repeatable)
--fail-on-warning        exit 1 when only warnings are present
--format text|json       output format (default: text)
```

## Sources

- RFC 4632, Classless Inter-domain Routing (CIDR): The Internet Address
  Assignment and Aggregation Plan (prefix notation):
  https://www.rfc-editor.org/rfc/rfc4632

## Development

53 tests, all fabricated rule files, no network:

```bash
python3 -m unittest -v
```

CI runs the suite on Ubuntu and Windows with Python 3.9 and 3.13.

## License

MIT - see LICENSE.
