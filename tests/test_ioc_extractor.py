"""
tests/test_ioc_extractor.py — Tests unitaires pour analyzers/ioc_extractor.py

Couvre :
  - Filtrage RFC 1918 (IPs privées)
  - Contextualisation des hashes MD5/SHA
  - Validation CIDR
  - Extraction d'IPs publiques valides
  - Extraction de domaines
"""

import sys
from pathlib import Path

# Ajout du répertoire parent au path pour les imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from analyzers.ioc_extractor import (
    IOCExtractor,
    _is_private_ip,
    _is_valid_cidr,
    _extract_hashes_contextual,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def extractor():
    """Instance de l'extracteur IOC."""
    return IOCExtractor()


# ---------------------------------------------------------------------------
# Tests : filtrage IP privées RFC 1918
# ---------------------------------------------------------------------------

class TestRFC1918Filtering:
    def test_private_ip_10_range_filtered(self, extractor):
        """Les IPs 10.x.x.x doivent être exclues."""
        result = extractor.extract("Attaque depuis 10.0.0.1 vers 10.255.255.254")
        assert "ipv4" not in result or len(result.get("ipv4", [])) == 0

    def test_private_ip_172_range_filtered(self, extractor):
        """Les IPs 172.16-31.x.x doivent être exclues."""
        result = extractor.extract("Source: 172.16.0.1, 172.31.255.254")
        assert "ipv4" not in result or len(result.get("ipv4", [])) == 0

    def test_private_ip_192_168_filtered(self, extractor):
        """Les IPs 192.168.x.x doivent être exclues."""
        result = extractor.extract("Router: 192.168.1.1 — default gateway")
        assert "ipv4" not in result or len(result.get("ipv4", [])) == 0

    def test_loopback_filtered(self, extractor):
        """L'IP loopback 127.0.0.1 doit être exclue."""
        result = extractor.extract("Écoute sur 127.0.0.1:8080")
        assert "ipv4" not in result or len(result.get("ipv4", [])) == 0

    def test_public_ip_retained(self, extractor):
        """Les IPs publiques doivent être conservées."""
        result = extractor.extract("C2 server identified at 185.220.101.42")
        assert "ipv4" in result
        assert "185.220.101.42" in result["ipv4"]

    def test_multiple_ips_mixed(self, extractor):
        """Seules les IPs publiques doivent être retenues parmi un mélange."""
        text = "Actors at 185.220.101.42 lateral movement via 192.168.1.5 to 91.108.4.1"
        result = extractor.extract(text)
        ips = result.get("ipv4", [])
        assert "185.220.101.42" in ips
        assert "91.108.4.1" in ips
        assert "192.168.1.5" not in ips

    def test_is_private_ip_function(self):
        """Test direct de la fonction _is_private_ip."""
        assert _is_private_ip("10.0.0.1") is True
        assert _is_private_ip("172.16.5.10") is True
        assert _is_private_ip("192.168.100.200") is True
        assert _is_private_ip("127.0.0.1") is True
        assert _is_private_ip("8.8.8.8") is False
        assert _is_private_ip("185.220.101.42") is False


# ---------------------------------------------------------------------------
# Tests : contextualisation hashes
# ---------------------------------------------------------------------------

class TestHashContextualisation:
    def test_md5_without_context_excluded(self, extractor):
        """Un hash MD5 sans contexte ne doit pas être extrait."""
        # 32 hex chars sans préfixe contextuel et pas de bloc IOC
        text = "The value d41d8cd98f00b204e9800998ecf8427e appeared in the document."
        result = extractor.extract(text)
        # Sans contexte IOC, le hash ne devrait pas être extrait
        assert result.get("md5", []) == []

    def test_sha256_with_prefix_extracted(self, extractor):
        """Un hash SHA256 avec préfixe doit être extrait."""
        sha = "a" * 64
        text = f"sha256:{sha} found in malware sample"
        result = extractor.extract(text)
        assert "sha256" in result
        assert sha in result["sha256"]

    def test_md5_with_prefix_extracted(self, extractor):
        """Un hash MD5 avec préfixe doit être extrait."""
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        text = f"md5:{md5} — fichier malveillant détecté"
        result = extractor.extract(text)
        assert "md5" in result
        assert md5 in result["md5"]

    def test_hash_in_ioc_block_extracted(self, extractor):
        """Un hash dans une section 'Indicators of Compromise' doit être extrait."""
        sha = "b" * 64
        text = f"Indicators of Compromise:\nFile hash: {sha}"
        result = extractor.extract(text)
        assert "sha256" in result
        assert sha in result["sha256"]

    def test_hash_prefix_case_insensitive(self, extractor):
        """Les préfixes de hash sont insensibles à la casse."""
        sha = "c" * 64
        text = f"SHA256:{sha}"
        result = extractor.extract(text)
        assert "sha256" in result


# ---------------------------------------------------------------------------
# Tests : validation CIDR
# ---------------------------------------------------------------------------

class TestCIDRValidation:
    def test_private_cidr_filtered(self, extractor):
        """Les CIDR privés ne doivent pas être retenus."""
        result = extractor.extract("Network 192.168.0.0/24 blocked")
        assert result.get("cidr", []) == []

    def test_public_cidr_retained(self, extractor):
        """Les CIDR publics doivent être retenus."""
        result = extractor.extract("Blocklist entry: 185.220.0.0/16")
        assert "cidr" in result
        assert "185.220.0.0/16" in result["cidr"]

    def test_is_valid_cidr_function(self):
        """Test direct de la fonction _is_valid_cidr."""
        assert _is_valid_cidr("192.168.0.0/24") is False
        assert _is_valid_cidr("10.0.0.0/8") is False
        assert _is_valid_cidr("185.0.0.0/16") is True
        assert _is_valid_cidr("invalid") is False


# ---------------------------------------------------------------------------
# Tests : extraction onion / BTC
# ---------------------------------------------------------------------------

class TestSpecialIOCs:
    def test_onion_address_extracted(self, extractor):
        """Les adresses .onion doivent être extraites."""
        result = extractor.extract("Darkweb market at abcdefghijklmnop.onion")
        assert "onion" in result

    def test_url_extracted(self, extractor):
        """Les URLs http/https doivent être extraites."""
        result = extractor.extract("C2 at http://185.220.101.42/beacon.php")
        assert "url" in result

    def test_cap_per_type(self, extractor):
        """Le nombre d'IOCs par type est limité à MAX_PER_TYPE."""
        ips = " ".join(f"1.2.3.{i}" for i in range(1, 20))
        result = extractor.extract(ips)
        assert len(result.get("ipv4", [])) <= extractor.MAX_PER_TYPE
