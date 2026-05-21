"""
Secure face profile updates with password authentication.

Identity validation before overwrite: user must provide password and
optionally match existing embeddings before destructive reset.
"""

from __future__ import annotations

from typing import Optional

import numpy as np

from detector.recognition.engine import RecognitionEngine
from profile.embeddings.manager import EmbeddingProfile, EmbeddingSample, ProfileManager
from security.password.manager import PasswordManager


class ProfileUpdater:
    def __init__(
        self,
        profile_manager: ProfileManager,
        password_manager: PasswordManager,
        recognition: RecognitionEngine,
    ) -> None:
        self._profiles = profile_manager
        self._passwords = password_manager
        self._recognition = recognition

    def add_samples(
        self,
        password: str,
        samples: list[EmbeddingSample],
        *,
        verify_identity: bool = True,
    ) -> EmbeddingProfile:
        self._passwords.require_verify(password)
        if verify_identity and self._profiles.exists():
            profile = self._profiles.load(password)
            for sample in samples[:1]:
                sim = self._recognition.max_similarity(sample.embedding, profile)
                if sim < self._recognition.config.similarity_threshold * 0.85:
                    raise PermissionError(
                        "New samples do not match enrolled identity. "
                        "Authenticate with matching face or use reset."
                    )
        return self._profiles.add_samples(samples, password)

    def retrain_centroid(self, password: str) -> EmbeddingProfile:
        self._passwords.require_verify(password)
        profile = self._profiles.load(password)
        profile.recompute_centroid()
        self._profiles.save(profile, password)
        return profile

    def reset_profile(self, password: str) -> None:
        self._passwords.require_verify(password)
        self._profiles.reset()

    def replace_profile(
        self,
        password: str,
        samples: list[EmbeddingSample],
    ) -> EmbeddingProfile:
        self._passwords.require_verify(password)
        return self._profiles.add_samples(samples, password, replace=True)
