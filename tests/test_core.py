import unittest

from netvuln.anomaly import latency_outliers
from netvuln.findings import Finding, sort_findings, summarize
from netvuln.scanner import PortResult, parse_ports


class ParsePortsTest(unittest.TestCase):
    def test_ranges_and_lists(self):
        self.assertEqual(parse_ports("22,80,100-102"), [22, 80, 100, 101, 102])

    def test_out_of_range(self):
        with self.assertRaises(ValueError):
            parse_ports("70000")


class FindingsTest(unittest.TestCase):
    def test_sorted_by_severity(self):
        items = [Finding("a", "low", "h"), Finding("b", "critical", "h")]
        self.assertEqual(sort_findings(items)[0].title, "b")

    def test_summary_counts(self):
        items = [Finding("a", "low", "h"), Finding("b", "low", "h")]
        self.assertEqual(summarize(items)["low"], 2)

    def test_bad_severity(self):
        with self.assertRaises(ValueError):
            Finding("a", "bogus", "h")


class AnomalyTest(unittest.TestCase):
    def test_flags_outlier(self):
        results = [PortResult(p, "x", 1.0) for p in range(1, 9)]
        results.append(PortResult(99, "x", 50.0))
        flagged = latency_outliers("h", results)
        self.assertEqual([f.port for f in flagged], [99])


if __name__ == "__main__":
    unittest.main()
