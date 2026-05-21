"""
Encrypted face embedding profile storage.

Embeddings are ArcFace 512-d vectors from InsightFace; stored as encrypted
numpy-serialized bundles. Multiple samples per pose improve robustness.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import numpy as np

from security.encryption.crypto import CryptoManager
from security.secure_storage.storage import SecureStorage


@dataclass
class EmbeddingSample:
    pose: str
    embedding: np.ndarray
    quality_score: float
    captured_at: float = field(default_factory=time.time)


@dataclass
class EmbeddingProfile:
    version: int
    samples: list[EmbeddingSample]
    centroid: Optional[np.ndarray] = None
    updated_at: float = field(default_factory=time.time)

    def to_serializable(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "updated_at": self.updated_at,
            "centroid": self.centroid.tolist() if self.centroid is not None else None,
            "samples": [
                {
                    "pose": s.pose,
                    "embedding": s.embedding.tolist(),
                    "quality_score": s.quality_score,
                    "captured_at": s.captured_at,
                }
                for s in self.samples
            ],
        }

    @classmethod
    def from_serializable(cls, data: dict[str, Any]) -> "EmbeddingProfile":
        samples = [
            EmbeddingSample(
                pose=s["pose"],
                embedding=np.array(s["embedding"], dtype=np.float32),
                quality_score=float(s["quality_score"]),
                captured_at=float(s.get("captured_at", time.time())),
            )
            for s in data.get("samples", [])
        ]
        centroid = None
        if data.get("centroid"):
            centroid = np.array(data["centroid"], dtype=np.float32)
        return cls(
            version=int(data.get("version", 1)),
            samples=samples,
            centroid=centroid,
            updated_at=float(data.get("updated_at", time.time())),
        )

    def recompute_centroid(self) -> None:
        if not self.samples:
            self.centroid = None
            return
        stack = np.stack([s.embedding for s in self.samples], axis=0)
        self.centroid = np.mean(stack, axis=0).astype(np.float32)
        norm = np.linalg.norm(self.centroid)
        if norm > 0:
            self.centroid /= norm
        self.updated_at = time.time()


class ProfileManager:
    PROFILE_FILE = "profile.enc"
    META_FILE = "profile_meta.json"

    def __init__(self, storage: SecureStorage, crypto: CryptoManager) -> None:
        self._storage = storage
        self._crypto = crypto
        self._profile_dir = storage.data_dir / "profile"

    @property
    def profile_path(self) -> Path:
        return self._profile_dir / self.PROFILE_FILE

    @property
    def meta_path(self) -> Path:
        return self._profile_dir / self.META_FILE

    def exists(self) -> bool:
        return self.profile_path.exists()

    def save(self, profile: EmbeddingProfile, password: str) -> None:
        profile.recompute_centroid()
        payload = json.dumps(profile.to_serializable()).encode("utf-8")
        self._storage.write_encrypted(self.profile_path, payload, self._crypto, password)
        meta = {
            "sample_count": len(profile.samples),
            "poses": list({s.pose for s in profile.samples}),
            "updated_at": profile.updated_at,
            "version": profile.version,
        }
        self._storage.write_json(self.meta_path, meta)

    def load(self, password: str) -> EmbeddingProfile:
        raw = self._storage.read_encrypted(self.profile_path, self._crypto, password)
        data = json.loads(raw.decode("utf-8"))
        return EmbeddingProfile.from_serializable(data)

    def add_samples(
        self,
        new_samples: list[EmbeddingSample],
        password: str,
        *,
        replace: bool = False,
    ) -> EmbeddingProfile:
        if replace or not self.exists():
            profile = EmbeddingProfile(version=1, samples=list(new_samples))
        else:
            profile = self.load(password)
            profile.samples.extend(new_samples)
        profile.recompute_centroid()
        self.save(profile, password)
        return profile

    def reset(self) -> None:
        for p in (self.profile_path, self.meta_path):
            if p.exists():
                SecureStorage.secure_wipe(p)
