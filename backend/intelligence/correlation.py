"""
ExposureFence — Finding Correlation & Deduplication Engine
Identifies duplicate findings and correlates related findings across heterogeneous sources
(Native Connectors, AWS Security Hub, AWS Config, Prowler) under unified correlation IDs.
"""

from collections import defaultdict
import hashlib
from typing import Dict, List, Tuple

from backend.intelligence.models import CanonicalFinding


class CorrelationEngine:
    """
    Correlates findings across sources affecting the same resource or attack surface.
    """

    @staticmethod
    def generate_correlation_id(resource_arn: str, category: str = "EXPOSURE") -> str:
        """Computes deterministic correlation ID for resource and vulnerability category."""
        token = f"{resource_arn}|{category}"
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]
        return f"CORR-{digest}"

    @classmethod
    def correlate_findings(cls, findings: List[CanonicalFinding]) -> List[CanonicalFinding]:
        """
        Assigns correlation IDs and merges metadata across multi-source findings.
        """
        # Group by resource_arn
        by_resource: Dict[str, List[CanonicalFinding]] = defaultdict(list)
        for f in findings:
            by_resource[f.resource_arn].append(f)

        correlated_findings: List[CanonicalFinding] = []

        for resource_arn, group in by_resource.items():
            corr_id = cls.generate_correlation_id(resource_arn)

            # Collect union of compliance tags across sources
            combined_tags = set()
            for item in group:
                combined_tags.update(item.compliance_tags)

            for item in group:
                item.correlation_id = corr_id
                item.compliance_tags = sorted(list(combined_tags))
                correlated_findings.append(item)

        return correlated_findings

    @staticmethod
    def group_by_correlation(findings: List[CanonicalFinding]) -> Dict[str, List[CanonicalFinding]]:
        """
        Returns findings grouped by correlation_id.
        """
        grouped: Dict[str, List[CanonicalFinding]] = defaultdict(list)
        for f in findings:
            cid = f.correlation_id or f.finding_id
            grouped[cid].append(f)
        return dict(grouped)

    @staticmethod
    def deduplicate(findings: List[CanonicalFinding]) -> List[CanonicalFinding]:
        """
        Deduplicates identical findings based on source_type and source_id,
        updating last_seen timestamp if newer.
        """
        seen: Dict[Tuple[str, str], CanonicalFinding] = {}
        for f in findings:
            key = (f.source_type.value, f.source_id)
            if key in seen:
                # Keep most recent
                existing = seen[key]
                if f.last_seen > existing.last_seen:
                    existing.last_seen = f.last_seen
            else:
                seen[key] = f
        return list(seen.values())
