"""
CyberSage AI — Modular Threat Detectors Package

Provides an extensible, pluggable detection engine for enterprise SOC incident analysis.

Usage:
    from app.detectors.registry import DetectorRegistry
    from app.detectors.ioc_extractor import IOCExtractor
"""
from app.detectors.base import BaseDetector, DetectionResult
from app.detectors.ioc_extractor import IOCExtractor
from app.detectors.registry import DetectorRegistry

__all__ = ["BaseDetector", "DetectionResult", "IOCExtractor", "DetectorRegistry"]
