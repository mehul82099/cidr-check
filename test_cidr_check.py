import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cidr_check as cc


def lint(text, **kw):
    return cc.check_rules(text, "fw.txt", **kw)


def rules(findings):
    return [f.rule for f in findings]


class ParseTests(unittest.TestCase):
    def test_basic_rule(self):
        rules, hb = cc.parse_rules("allow tcp 10.0.0.0/8 443\n", "f")
        self.assertEqual(len(rules), 1)
        r = rules[0]
        self.assertEqual((r.action, r.proto), ("allow", "tcp"))
        self.assertEqual(str(r.network), "10.0.0.0/8")
        self.assertEqual((r.pstart, r.pend), (443, 443))
        self.assertEqual(hb, [])

    def test_comments_and_blanks(self):
        rules, _ = cc.parse_rules("# header\n\nallow udp 1.2.3.4 53 # tail\n", "f")
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].lineno, 3)

    def test_bare_address_is_host(self):
        rules, _ = cc.parse_rules("allow tcp 192.0.2.10 22\n", "f")
        self.assertEqual(str(rules[0].network), "192.0.2.10/32")

    def test_bare_ipv6_host(self):
        rules, _ = cc.parse_rules("allow tcp 2001:db8::1 22\n", "f")
        self.assertEqual(str(rules[0].network), "2001:db8::1/128")

    def test_port_range(self):
        rules, _ = cc.parse_rules("allow tcp 10.0.0.0/8 8000-8080\n", "f")
        self.assertEqual((rules[0].pstart, rules[0].pend), (8000, 8080))

    def test_port_any(self):
        rules, _ = cc.parse_rules("allow tcp 10.0.0.0/8 any\n", "f")
        self.assertEqual((rules[0].pstart, rules[0].pend), (0, 65535))

    def test_wrong_field_count(self):
        with self.assertRaises(cc.RulesError):
            cc.parse_rules("allow tcp 10.0.0.0/8\n", "f")

    def test_bad_action(self):
        with self.assertRaises(cc.RulesError) as ctx:
            cc.parse_rules("permit tcp 10.0.0.0/8 22\n", "f")
        self.assertIn("allow or deny", str(ctx.exception))

    def test_bad_proto(self):
        with self.assertRaises(cc.RulesError):
            cc.parse_rules("allow icmp 10.0.0.0/8 0\n", "f")

    def test_bad_port(self):
        with self.assertRaises(cc.RulesError):
            cc.parse_rules("allow tcp 10.0.0.0/8 http\n", "f")

    def test_inverted_port_range(self):
        with self.assertRaises(cc.RulesError):
            cc.parse_rules("allow tcp 10.0.0.0/8 90-80\n", "f")

    def test_port_out_of_range(self):
        with self.assertRaises(cc.RulesError):
            cc.parse_rules("allow tcp 10.0.0.0/8 70000\n", "f")

    def test_invalid_cidr(self):
        with self.assertRaises(cc.RulesError):
            cc.parse_rules("allow tcp 999.0.0.0/8 22\n", "f")

    def test_host_bits_masked(self):
        rules, hb = cc.parse_rules("allow tcp 10.0.0.1/24 22\n", "f")
        self.assertEqual(str(rules[0].network), "10.0.0.0/24")
        self.assertEqual(len(hb), 1)


class CoversTests(unittest.TestCase):
    def make(self, line):
        rules, _ = cc.parse_rules(line + "\n", "f")
        return rules[0]

    def test_subnet_containment(self):
        a = self.make("allow tcp 10.0.0.0/8 443")
        b = self.make("allow tcp 10.1.0.0/16 443")
        self.assertTrue(cc._covers(a, b))
        self.assertFalse(cc._covers(b, a))

    def test_port_containment(self):
        a = self.make("allow tcp 10.0.0.0/8 8000-9000")
        b = self.make("allow tcp 10.0.0.0/8 8080-8081")
        self.assertTrue(cc._covers(a, b))
        c = self.make("allow tcp 10.0.0.0/8 9001")
        self.assertFalse(cc._covers(a, c))

    def test_any_proto_covers_specific(self):
        a = self.make("allow any 10.0.0.0/8 443")
        b = self.make("allow tcp 10.0.0.0/8 443")
        self.assertTrue(cc._covers(a, b))
        self.assertFalse(cc._covers(b, a))

    def test_different_protos(self):
        a = self.make("allow udp 10.0.0.0/8 53")
        b = self.make("allow tcp 10.0.0.0/8 53")
        self.assertFalse(cc._covers(a, b))

    def test_ip_versions_never_cover(self):
        a = self.make("allow tcp 0.0.0.0/0 22")
        b = self.make("allow tcp ::/0 22")
        self.assertFalse(cc._covers(a, b))


class WorldOpenTests(unittest.TestCase):
    def test_ssh_world_error(self):
        f = lint("allow tcp 0.0.0.0/0 22\n")
        self.assertEqual(f[0].rule, "world-open-admin")
        self.assertEqual(f[0].severity, "error")

    def test_rdp_world_error(self):
        self.assertIn("world-open-admin",
                      rules(lint("allow tcp 0.0.0.0/0 3389\n")))

    def test_postgres_world_error(self):
        self.assertIn("world-open-admin",
                      rules(lint("allow tcp 0.0.0.0/0 5432\n")))

    def test_range_covering_sensitive(self):
        f = lint("allow tcp 0.0.0.0/0 20-25\n")
        self.assertEqual(f[0].rule, "world-open-admin")
        self.assertIn("21,22", f[0].message)

    def test_http_world_warning(self):
        f = lint("allow tcp 0.0.0.0/0 80\n")
        self.assertEqual(f[0].rule, "world-open")
        self.assertEqual(f[0].severity, "warning")

    def test_ipv6_world(self):
        self.assertIn("world-open-admin",
                      rules(lint("allow tcp ::/0 22\n")))

    def test_deny_world_not_flagged(self):
        self.assertEqual(lint("deny tcp 0.0.0.0/0 22\n"), [])

    def test_private_range_clean(self):
        self.assertEqual(lint("allow tcp 10.0.0.0/8 22\n"), [])

    def test_custom_sensitive_ports(self):
        f = lint("allow tcp 0.0.0.0/0 8080\n", sensitive_ports={8080})
        self.assertEqual(f[0].rule, "world-open-admin")

    def test_any_port_world_mentions_any(self):
        f = lint("allow tcp 0.0.0.0/0 any\n")
        self.assertEqual(f[0].rule, "world-open-admin")  # covers 22 etc.
        self.assertIn("22", f[0].message)


class ShadowTests(unittest.TestCase):
    def test_deny_shadowed_by_allow(self):
        f = lint("allow tcp 10.0.0.0/8 443\ndeny tcp 10.0.0.0/16 443\n")
        self.assertEqual(f[0].rule, "shadowed-deny")
        self.assertEqual(f[0].severity, "error")
        self.assertIn("line 1", f[0].message)

    def test_redundant_same_action(self):
        f = lint("allow tcp 10.0.0.0/8 443\nallow tcp 10.1.0.0/16 443\n")
        self.assertEqual(f[0].rule, "redundant-rule")
        self.assertEqual(f[0].severity, "warning")

    def test_allow_shadowed_by_deny(self):
        f = lint("deny tcp 10.0.0.0/8 443\nallow tcp 10.1.0.0/16 443\n")
        self.assertEqual(f[0].rule, "unreachable-rule")

    def test_partial_overlap_not_shadowed(self):
        f = lint("allow tcp 10.0.0.0/8 443\ndeny tcp 192.168.0.0/16 443\n")
        self.assertEqual(f, [])

    def test_partial_port_overlap_not_shadowed(self):
        f = lint("allow tcp 10.0.0.0/8 443\ndeny tcp 10.0.0.0/8 443-444\n")
        self.assertEqual(f, [])

    def test_different_proto_not_shadowed(self):
        f = lint("allow udp 10.0.0.0/8 53\ndeny tcp 10.0.0.0/8 53\n")
        self.assertEqual(f, [])

    def test_any_proto_shadows_specific(self):
        f = lint("allow any 10.0.0.0/8 443\ndeny tcp 10.0.0.0/8 443\n")
        self.assertEqual(f[0].rule, "shadowed-deny")

    def test_exact_duplicate_redundant(self):
        f = lint("allow tcp 10.0.0.0/8 443\nallow tcp 10.0.0.0/8 443\n")
        self.assertEqual(f[0].rule, "redundant-rule")

    def test_first_match_intentional_order(self):
        # classic pattern: allow narrow, deny broad after - legal, no findings
        f = lint("allow tcp 10.1.0.0/16 443\ndeny tcp 10.0.0.0/8 443\n")
        self.assertEqual(f, [])

    def test_ipv6_shadowing(self):
        f = lint("allow tcp ::/0 80\ndeny tcp 2001:db8::/32 80\n")
        self.assertIn("shadowed-deny", rules(f))

    def test_host_bits_warning(self):
        f = lint("allow tcp 10.0.0.1/24 22\n")
        self.assertEqual(f[0].rule, "host-bits-set")
        self.assertIn("10.0.0.0/24", f[0].message)

    def test_clean_realistic(self):
        text = (
            "# web tier\n"
            "allow tcp 0.0.0.0/0 80\n"
            "allow tcp 0.0.0.0/0 443\n"
            "# office ssh\n"
            "allow tcp 203.0.113.0/24 22\n"
            "deny tcp 0.0.0.0/0 22\n"
            "# internal only\n"
            "allow tcp 10.0.0.0/8 5432\n"
            "deny tcp 0.0.0.0/0 5432\n")
        found = rules(lint(text))
        self.assertNotIn("world-open-admin", found)
        self.assertNotIn("shadowed-deny", found)
        self.assertEqual(found.count("world-open"), 2)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, text):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cc.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_clean_exit_0(self):
        p = self.write("fw.txt", "allow tcp 10.0.0.0/8 443\n")
        code, out, _ = self.run_cli([p])
        self.assertEqual(code, 0)
        self.assertIn("clean", out)

    def test_error_exit_1(self):
        p = self.write("fw.txt", "allow tcp 0.0.0.0/0 22\n")
        code, out, _ = self.run_cli([p])
        self.assertEqual(code, 1)
        self.assertIn("1 error(s)", out)

    def test_warning_only_exit_0(self):
        p = self.write("fw.txt", "allow tcp 0.0.0.0/0 80\n")
        code, _, _ = self.run_cli([p])
        self.assertEqual(code, 0)

    def test_fail_on_warning_exit_1(self):
        p = self.write("fw.txt", "allow tcp 0.0.0.0/0 80\n")
        code, _, _ = self.run_cli([p, "--fail-on-warning"])
        self.assertEqual(code, 1)

    def test_missing_file_exit_2(self):
        code, _, err = self.run_cli([os.path.join(self.dir, "no.txt")])
        self.assertEqual(code, 2)
        self.assertIn("cannot read", err)

    def test_parse_error_exit_2(self):
        p = self.write("fw.txt", "allow tcp 10.0.0.0/33 22\n")
        code, _, err = self.run_cli([p])
        self.assertEqual(code, 2)
        self.assertIn("invalid CIDR", err)

    def test_bad_sensitive_ports_exit_2(self):
        p = self.write("fw.txt", "allow tcp 10.0.0.0/8 443\n")
        code, _, err = self.run_cli([p, "--sensitive-ports", "22,ssh"])
        self.assertEqual(code, 2)

    def test_sensitive_ports_flag(self):
        p = self.write("fw.txt", "allow tcp 0.0.0.0/0 8080\n")
        code, out, _ = self.run_cli([p, "--sensitive-ports", "8080"])
        self.assertEqual(code, 1)
        self.assertIn("world-open-admin", out)

    def test_ignore_flag(self):
        p = self.write("fw.txt", "allow tcp 0.0.0.0/0 22\n")
        code, out, _ = self.run_cli([p, "--ignore", "world-open-admin"])
        self.assertEqual(code, 0)
        self.assertNotIn("world-open-admin", out)

    def test_json_output(self):
        p = self.write("fw.txt", "allow tcp 0.0.0.0/0 22\n")
        code, out, _ = self.run_cli([p, "--format", "json"])
        parsed = json.loads(out)
        self.assertEqual(parsed["summary"]["errors"], 1)
        self.assertEqual(parsed["findings"][0]["rule"], "world-open-admin")
        self.assertEqual(parsed["findings"][0]["line"], 1)

    def test_multiple_files(self):
        a = self.write("a.txt", "allow tcp 0.0.0.0/0 22\n")
        b = self.write("b.txt", "allow tcp 10.0.0.0/8 443\n")
        code, out, _ = self.run_cli([a, b])
        self.assertEqual(code, 1)
        self.assertIn(a + ":1", out)

    def test_output_shape(self):
        p = self.write("fw.txt", "allow tcp 0.0.0.0/0 22\n")
        _, out, _ = self.run_cli([p])
        self.assertIn("%s:1 [error] world-open-admin" % p, out)


if __name__ == "__main__":
    unittest.main()
