#!/usr/bin/env python3
"""cidr-check - a CI linter for firewall-style CIDR rule files.

Reads simple rule files (one rule per line: action, protocol, CIDR, port
range) and flags rules that open sensitive ports to the world, rules that
can never match because an earlier rule already covers them, and CIDRs
with host bits set. Rule evaluation assumes first-match-wins semantics
(top to bottom), which is how iptables-style rule lists work.

Pure standard library (ipaddress).

Sources:
- RFC 4632, Classless Inter-domain Routing (CIDR):
  https://www.rfc-editor.org/rfc/rfc4632
"""

import argparse
import ipaddress
import json
import sys

# Ports where world-open is an error, not a warning: remote access and
# data services that should never face the public internet. A heuristic
# list - replace with --sensitive-ports.
DEFAULT_SENSITIVE_PORTS = frozenset([
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    445,   # SMB
    1433,  # MSSQL
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    5900,  # VNC
    6379,  # Redis
    9200,  # Elasticsearch
    11211, # Memcached
    27017, # MongoDB
])

WORLD_V4 = ipaddress.ip_network("0.0.0.0/0")
WORLD_V6 = ipaddress.ip_network("::/0")
ACTIONS = ("allow", "deny")
PROTOS = ("tcp", "udp", "any")


class RulesError(Exception):
    """Raised for unparseable input (exit 2)."""


class Rule:
    def __init__(self, lineno, action, proto, network, pstart, pend, raw):
        self.lineno = lineno
        self.action = action
        self.proto = proto
        self.network = network
        self.pstart = pstart
        self.pend = pend
        self.raw = raw


class Finding:
    def __init__(self, path, line, rule, severity, message):
        self.path = path
        self.line = line
        self.rule = rule
        self.severity = severity  # "error" or "warning"
        self.message = message

    def as_dict(self):
        return {
            "file": self.path,
            "line": self.line,
            "rule": self.rule,
            "severity": self.severity,
            "message": self.message,
        }


def parse_ports(text, lineno):
    if text.lower() == "any":
        return 0, 65535
    try:
        if "-" in text:
            start_s, end_s = text.split("-", 1)
            start, end = int(start_s), int(end_s)
        else:
            start = end = int(text)
    except ValueError:
        raise RulesError(
            "line %d: port %r is not a number or range like 8000-8080" % (
                lineno, text))
    if not (0 <= start <= end <= 65535):
        raise RulesError(
            "line %d: port range %r must satisfy 0 <= start <= end <= "
            "65535" % (lineno, text))
    return start, end


def parse_network(text, lineno):
    if "/" not in text:
        # a bare address is a single host
        try:
            addr = ipaddress.ip_address(text)
        except ValueError:
            raise RulesError("line %d: %r is not an IP address or CIDR" % (
                lineno, text))
        bits = 32 if addr.version == 4 else 128
        return ipaddress.ip_network("%s/%d" % (text, bits)), False
    try:
        return ipaddress.ip_network(text, strict=True), False
    except ValueError as strict_exc:
        try:
            return ipaddress.ip_network(text, strict=False), True
        except ValueError:
            raise RulesError("line %d: invalid CIDR %r (%s)" % (
                lineno, text, strict_exc))


def parse_rules(text, path):
    rules = []
    host_bits = []
    for lineno, raw in enumerate(text.split("\n"), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) != 4:
            raise RulesError(
                "%s:%d: expected 4 fields 'action proto cidr ports', got "
                "%d" % (path, lineno, len(parts)))
        action, proto, cidr, ports = parts
        if action not in ACTIONS:
            raise RulesError("%s:%d: action must be allow or deny, got "
                             "%r" % (path, lineno, action))
        if proto not in PROTOS:
            raise RulesError("%s:%d: protocol must be tcp, udp or any, got "
                             "%r" % (path, lineno, proto))
        network, masked = parse_network(cidr, lineno)
        if masked:
            host_bits.append((lineno, cidr, str(network)))
        pstart, pend = parse_ports(ports, lineno)
        rules.append(Rule(lineno, action, proto, network, pstart, pend,
                          line))
    return rules, host_bits


def _covers(a, b):
    """True when rule a's whole match space covers rule b's (same IP
    version, subnet containment, proto match, port containment)."""
    if a.network.version != b.network.version:
        return False
    if not b.network.subnet_of(a.network):
        return False
    if a.proto != "any" and a.proto != b.proto:
        return False
    return a.pstart <= b.pstart and b.pend <= a.pend


def check_rules(text, path, sensitive_ports=None):
    if sensitive_ports is None:
        sensitive_ports = DEFAULT_SENSITIVE_PORTS
    rules, host_bits = parse_rules(text, path)
    findings = []

    def emit(line, rule, severity, message):
        findings.append(Finding(path, line, rule, severity, message))

    for lineno, cidr, masked in host_bits:
        emit(lineno, "host-bits-set", "warning",
             "CIDR %s has host bits set; interpreted as the masked network "
             "%s (RFC 4632 prefix notation describes networks, so this was "
             "likely meant as the network address)." % (cidr, masked))

    for i, r in enumerate(rules):
        world = r.network == WORLD_V4 or r.network == WORLD_V6
        if r.action == "allow" and world:
            sensitive = sorted(p for p in sensitive_ports
                               if r.pstart <= p <= r.pend)
            if sensitive:
                emit(r.lineno, "world-open-admin", "error",
                     "allows the entire internet (%s) to reach sensitive "
                     "port(s) %s %s; remote-access and data services "
                     "should not face the public internet (the port list "
                     "is a heuristic - tune with --sensitive-ports)." % (
                         r.network, ",".join(str(p) for p in sensitive),
                         r.proto))
            else:
                emit(r.lineno, "world-open", "warning",
                     "allows the entire internet (%s) to reach port(s) "
                     "%s %s; sometimes intended (e.g. 80/443), worth a "
                     "review." % (r.network,
                                  "any" if (r.pstart, r.pend) == (0, 65535)
                                  else "%d-%d" % (r.pstart, r.pend),
                                  r.proto))

    for i, r in enumerate(rules):
        for earlier in rules[:i]:
            if not _covers(earlier, r):
                continue
            if earlier.action == "allow" and r.action == "deny":
                emit(r.lineno, "shadowed-deny", "error",
                     "deny rule can never match: earlier allow rule at "
                     "line %d already covers this whole space (assuming "
                     "first-match-wins evaluation)." % earlier.lineno)
                break
            elif earlier.action == r.action:
                emit(r.lineno, "redundant-rule", "warning",
                     "rule is fully covered by the earlier %s rule at "
                     "line %d." % (earlier.action, earlier.lineno))
                break
            else:
                emit(r.lineno, "unreachable-rule", "warning",
                     "allow rule can never match: earlier deny rule at "
                     "line %d already covers this whole space." %
                     earlier.lineno)
                break
    return findings


def format_text(results):
    lines = []
    errors = warnings = 0
    for path, findings in results:
        for f in findings:
            lines.append("%s:%d [%s] %s: %s" % (
                f.path, f.line, f.severity, f.rule, f.message))
            if f.severity == "error":
                errors += 1
            else:
                warnings += 1
    if errors or warnings:
        lines.append("cidr-check: %d error(s), %d warning(s)" % (
            errors, warnings))
    else:
        lines.append("cidr-check: clean")
    return "\n".join(lines), errors, warnings


def format_json(results, errors, warnings):
    return json.dumps({
        "findings": [f.as_dict() for _, fs in results for f in fs],
        "summary": {"files": len(results), "errors": errors,
                    "warnings": warnings},
    }, indent=2)


def build_parser():
    p = argparse.ArgumentParser(
        prog="cidr-check",
        description="Lint firewall-style CIDR rule files: world-open "
                    "sensitive ports, shadowed/unreachable rules, host "
                    "bits set. Assumes first-match-wins evaluation.")
    p.add_argument("rulefiles", nargs="+", help="rule file(s): one "
                   "'allow|deny tcp|udp|any CIDR port[-port]|any' per line")
    p.add_argument("--sensitive-ports",
                   help="comma-separated ports replacing the built-in "
                        "sensitive list, e.g. 22,3306")
    p.add_argument("--ignore", action="append", default=[], metavar="RULE",
                   help="suppress a rule by name (repeatable)")
    p.add_argument("--fail-on-warning", action="store_true",
                   help="exit 1 when only warnings are present")
    p.add_argument("--format", choices=["text", "json"], default="text",
                   help="output format (default: text)")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    ignore = set(args.ignore)
    sensitive = None
    if args.sensitive_ports:
        try:
            sensitive = frozenset(
                int(p) for p in args.sensitive_ports.split(","))
        except ValueError:
            print("cidr-check: --sensitive-ports must be comma-separated "
                  "numbers", file=sys.stderr)
            return 2
    results = []
    for path in args.rulefiles:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                text = fh.read()
        except OSError as exc:
            print("cidr-check: cannot read %s: %s" % (path, exc),
                  file=sys.stderr)
            return 2
        try:
            findings = check_rules(text, path, sensitive_ports=sensitive)
        except RulesError as exc:
            print("cidr-check: %s" % exc, file=sys.stderr)
            return 2
        results.append((path, [f for f in findings if f.rule not in ignore]))

    text_out, errors, warnings = format_text(results)
    if args.format == "json":
        print(format_json(results, errors, warnings))
    else:
        print(text_out)
    if errors:
        return 1
    if args.fail_on_warning and warnings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
