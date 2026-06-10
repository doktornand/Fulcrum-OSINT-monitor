"""
analyzers/ioc_extractor.py — Extracteur d'IOCs avec filtrage anti-faux-positifs

Améliorations vs fulcrum2e.py :
  - Filtrage des plages IP privées RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
  - Contextualisation MD5/SHA : exige préfixe ou bloc IOC explicite
  - Validation CIDR pour les sous-réseaux
  - Dédoublonnage et cap par type

Google-style docstrings.
"""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Patterns de base
# ---------------------------------------------------------------------------

_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b")
_CIDR = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/\d{1,2}\b"
)

# Hashes — raw patterns (contextualisation appliquée après)
_MD5_RAW = re.compile(r"\b([a-fA-F0-9]{32})\b")
_SHA1_RAW = re.compile(r"\b([a-fA-F0-9]{40})\b")
_SHA256_RAW = re.compile(r"\b([a-fA-F0-9]{64})\b")

# Préfixes de contextualisation pour les hashes
_HASH_CONTEXT_PREFIXES = re.compile(
    r"(?:hash|md5|sha1|sha256|sha-1|sha-256|ioc|indicator)[:\s]+([a-fA-F0-9]{32,64})\b",
    re.IGNORECASE,
)
# Blocs IOC explicites (ex: dans un tableau ou section labellisée)
_IOC_BLOCK_MARKERS = re.compile(
    r"(?:ioc|indicators? of compromise|hashes?|file hash|malware hash)",
    re.IGNORECASE,
)

_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)
_URL = re.compile(r"https?://[^\s<>\"\'{}|\\^`\[\]]+")
_EMAIL = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_BTC = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
_ONION = re.compile(r"[a-z2-7]{16,56}\.onion", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Plages IP privées RFC 1918 / réservées
# ---------------------------------------------------------------------------

_RFC1918_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),      # loopback
    ipaddress.ip_network("169.254.0.0/16"),   # link-local
    ipaddress.ip_network("100.64.0.0/10"),    # carrier-grade NAT
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
]


def _is_private_ip(ip_str: str) -> bool:
    """Vérifie si une IP appartient à une plage privée/réservée.

    Args:
        ip_str: Adresse IP en format string.

    Returns:
        True si l'IP est privée ou réservée.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _RFC1918_NETWORKS)
    except ValueError:
        return False


def _is_valid_cidr(cidr_str: str) -> bool:
    """Valide un bloc CIDR.

    Args:
        cidr_str: Notation CIDR à valider.

    Returns:
        True si le CIDR est valide et routable publiquement.
    """
    try:
        net = ipaddress.ip_network(cidr_str, strict=False)
        # Exclure les réseaux privés
        return not any(net.overlaps(priv) for priv in _RFC1918_NETWORKS)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Domaines à exclure (TLDs génériques non pertinents comme IOC)
# ---------------------------------------------------------------------------

_COMMON_BENIGN_DOMAINS = {
    "example.com", "example.org", "localhost",
    "github.com", "github.io", "microsoft.com",
    "google.com", "amazonaws.com", "cloudflare.com",
}

_SKIP_TLDS = {".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".pdf"}


def _is_interesting_domain(domain: str) -> bool:
    """Filtre les domaines peu pertinents comme IOC.

    Args:
        domain: Nom de domaine à évaluer.

    Returns:
        True si le domaine mérite d'être retenu.
    """
    if domain.lower() in _COMMON_BENIGN_DOMAINS:
        return False
    if any(domain.lower().endswith(ext) for ext in _SKIP_TLDS):
        return False
    # Exclure les domaines avec trop peu de labels (ex: "fr", "co.uk" seul)
    parts = domain.split(".")
    if len(parts) < 2:
        return False
    return True


# ---------------------------------------------------------------------------
# Extraction de hashes avec contextualisation
# ---------------------------------------------------------------------------

def _extract_hashes_contextual(text: str) -> Dict[str, List[str]]:
    """Extrait les hashes MD5/SHA1/SHA256 avec validation contextuelle.

    Un hash n'est retenu que si :
      - Il est précédé d'un préfixe de contextualisation (hash:, md5:, sha256:…)
      - OU il se trouve dans un bloc IOC explicite (section "IOC", "Indicators of Compromise"…)

    Args:
        text: Texte brut à analyser.

    Returns:
        Dict avec clés 'md5', 'sha1', 'sha256' et listes de hashes valides.
    """
    result: Dict[str, List[str]] = {"md5": [], "sha1": [], "sha256": []}

    # Hashes trouvés via préfixes de contextualisation
    for m in _HASH_CONTEXT_PREFIXES.finditer(text):
        h = m.group(1)
        _classify_hash(h, result)

    # Vérifier si le texte contient un bloc IOC — si oui, extraction plus large
    has_ioc_block = bool(_IOC_BLOCK_MARKERS.search(text))
    if has_ioc_block:
        for m in _SHA256_RAW.finditer(text):
            h = m.group(1)
            if h not in result["sha256"]:
                result["sha256"].append(h)
        for m in _SHA1_RAW.finditer(text):
            h = m.group(1)
            if len(h) == 40 and h not in result["sha1"]:
                result["sha1"].append(h)
        for m in _MD5_RAW.finditer(text):
            h = m.group(1)
            if len(h) == 32 and h not in result["md5"]:
                result["md5"].append(h)

    # Dédoublonnage + cap
    for k in result:
        result[k] = list(dict.fromkeys(result[k]))[:10]

    return result


def _classify_hash(h: str, result: Dict[str, List[str]]) -> None:
    """Classifie un hash dans md5/sha1/sha256 selon sa longueur.

    Args:
        h: Valeur hexadécimale du hash.
        result: Dictionnaire de résultats à mettre à jour.
    """
    if len(h) == 64 and h not in result["sha256"]:
        result["sha256"].append(h)
    elif len(h) == 40 and h not in result["sha1"]:
        result["sha1"].append(h)
    elif len(h) == 32 and h not in result["md5"]:
        result["md5"].append(h)


# ---------------------------------------------------------------------------
# Extracteur principal
# ---------------------------------------------------------------------------

class IOCExtractor:
    """Extracteur d'Indicateurs de Compromission (IOC) avec filtrage avancé.

    Améliorations vs version monolithe :
      - Filtrage RFC 1918 pour les IPs privées
      - Contextualisation des hashes (exige préfixe ou bloc IOC)
      - Validation CIDR
      - Dédoublonnage strict

    Example:
        >>> extractor = IOCExtractor()
        >>> iocs = extractor.extract("CVE-2024-1234 affecting 192.168.1.1")
        >>> iocs["ipv4"]  # vide — IP privée filtrée
        []
    """

    MAX_PER_TYPE = 10

    def extract(self, text: str) -> Dict[str, List[str]]:
        """Extrait tous les IOCs d'un texte avec filtrage anti-faux-positifs.

        Args:
            text: Texte brut (titre + résumé + contenu d'un article).

        Returns:
            Dict avec types d'IOC comme clés et listes de valeurs.
            Clés : ipv4, ipv6, cidr, md5, sha1, sha256, domain, url, email, btc, onion.
        """
        iocs: Dict[str, List[str]] = defaultdict(list)

        # IPs publiques uniquement (filtrage RFC 1918)
        for ip in _IPV4.findall(text):
            if not _is_private_ip(ip) and ip not in iocs["ipv4"]:
                iocs["ipv4"].append(ip)

        for ip in _IPV6.findall(text):
            try:
                addr = ipaddress.ip_address(ip)
                if not addr.is_private and not addr.is_loopback:
                    if ip not in iocs["ipv6"]:
                        iocs["ipv6"].append(ip)
            except ValueError:
                pass

        # CIDRs valides et publics
        for cidr in _CIDR.findall(text):
            if _is_valid_cidr(cidr) and cidr not in iocs["cidr"]:
                iocs["cidr"].append(cidr)

        # Hashes avec contextualisation
        hashes = _extract_hashes_contextual(text)
        iocs["md5"].extend(hashes["md5"])
        iocs["sha1"].extend(hashes["sha1"])
        iocs["sha256"].extend(hashes["sha256"])

        # Domaines
        for domain in _DOMAIN.findall(text):
            if _is_interesting_domain(domain) and domain not in iocs["domain"]:
                iocs["domain"].append(domain)

        # URLs
        for url in _URL.findall(text):
            if url not in iocs["url"]:
                iocs["url"].append(url)

        # Emails
        for email in _EMAIL.findall(text):
            if email not in iocs["email"]:
                iocs["email"].append(email)

        # Bitcoin
        for btc in _BTC.findall(text):
            if btc not in iocs["btc"]:
                iocs["btc"].append(btc)

        # Onion
        for onion in _ONION.findall(text):
            if onion not in iocs["onion"]:
                iocs["onion"].append(onion)

        # Cap par type
        return {k: v[: self.MAX_PER_TYPE] for k, v in iocs.items() if v}
