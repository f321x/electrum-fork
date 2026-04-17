from ipaddress import ip_address

from electrum.asmap import ASMap

from . import ElectrumTestCase


# encoded with contrib/asmap/asmap.py of Bitcoin Core, from the prefixes:
#   1.1.1.0/24 AS13335, 8.0.0.0/9 AS3356, 8.8.8.0/24 AS15169, 34.64.0.0/10 AS396982, 2001:4860::/32 AS15169
ASMAP = bytes.fromhex(
    "8bae733fc0fe00fb03ec0fb03fc0fe00fb03ec0fb03fc0fec0fbffefffd374a3d88dfb03ee0f88056d"
    "0787c5de0fb13f046e81fd90aeb8d63db03fe0fe12fb1be01600")


class TestASMap(ElectrumTestCase):

    def test_lookup_asn(self):
        asmap = ASMap(ASMAP)
        for ip, asn in [
            ("1.1.1.1", 13335),
            ("8.8.8.8", 15169),
            ("8.1.2.3", 3356),  # only covered by the /9
            ("8.128.0.1", None),
            ("34.64.1.1", 396982),
            ("2001:4860:4860::8888", 15169),
            ("2606:4700::1111", None),
        ]:
            self.assertEqual(asn, asmap.lookup_asn(ip_address(ip)), msg=ip)
