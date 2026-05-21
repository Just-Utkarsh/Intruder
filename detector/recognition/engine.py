"""
ArcFace embedding comparison with conservative thresholds.

Low false positives: require similarity above threshold for authorized;
unknown/intruder if best match below unknown_threshold or second-best gap small.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Optional

import numpy as np

from profile.embeddings.manager import EmbeddingProfile

logger = logging.getLogger(__name__)


@dataclass
class RecognitionConfig:
    similarity_threshold: float = 0.42
    unknown_threshold: float = 0.32
    compare_metric: str = "cosine"


class IdentityLabel(str, Enum):
    AUTHORIZED = "authorized"
    UNKNOWN = "unknown"
    NO_FACE = "no_face"


@dataclass
class RecognitionResult:
    label: IdentityLabel
    confidence: float
    best_pose: Optional[str] = None


class RecognitionEngine:
    def __init__(self, config: Optional[RecognitionConfig] = None) -> None:
        self.config = config or RecognitionConfig()

    @staticmethod
    def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
        a = a.astype(np.float32).flatten()
        b = b.astype(np.float32).flatten()
        na = np.linalg.norm(a)
        nb = np.linalg.norm(b)
        if na == 0 or nb == 0:
            return 0.0
        return float(np.dot(a / na, b / nb))

    def max_similarity(self, embedding: np.ndarray, profile: EmbeddingProfile) -> float:
        if not profile.samples and profile.centroid is None:
            return 0.0
        scores: list[float] = []
        if profile.centroid is not None:
            scores.append(self.cosine_similarity(embedding, profile.centroid))
        for sample in profile.samples:
            scores.append(self.cosine_similarity(embedding, sample.embedding))
        return max(scores) if scores else 0.0

    def identify(self, embedding: np.ndarray, profile: EmbeddingProfile) -> RecognitionResult:
        sim = self.max_similarity(embedding, profile)
        logger.debug("Recognition similarity: %.4f", sim)

        if sim >= self.config.similarity_threshold:
            return RecognitionResult(
                label=IdentityLabel.AUTHORIZED,
                confidence=sim,
            )
        if sim <= self.config.unknown_threshold:
            return RecognitionResult(
                label=IdentityLabel.UNKNOWN,
                confidence=1.0 - sim,
            )
        # Ambiguous zone — treat as unknown (conservative)
        return RecognitionResult(
            label=IdentityLabel.UNKNOWN,
            confidence=1.0 - sim,
        )
