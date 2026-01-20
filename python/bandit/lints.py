from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

import numpy as np


@dataclass
class LinTSConfig:
    # Prior / ridge
    lam: float = 1.0
    # Posterior sampling noise scale (reward assumed roughly in [-1, 1])
    sigma: float = 0.2
    # Exponential forgetting (rho close to 1 keeps long memory)
    rho: float = 0.99
    # Recompute A^{-1} every N updates (keeps compute bounded)
    recompute_inv_every: int = 20
    # Numerical jitter
    jitter: float = 1e-6
    # Random seed
    seed: int = 0


class LinTS:
    """Linear Thompson Sampling with exponential forgetting.

    Maintains A,b and periodically recomputes A^{-1}.
    Selection uses theta~N(theta_hat, sigma^2 A^{-1}).
    """

    def __init__(self, dim: int, cfg: LinTSConfig):
        self.dim = int(dim)
        self.cfg = cfg

        lam = float(cfg.lam)
        self.A = lam * np.eye(self.dim, dtype=np.float64)
        self.b = np.zeros((self.dim,), dtype=np.float64)
        self.A_inv = (1.0 / lam) * np.eye(self.dim, dtype=np.float64)
        self.theta_hat = np.zeros((self.dim,), dtype=np.float64)

        self.t = 0
        self.rng = np.random.RandomState(int(cfg.seed))

    def select(self, Phi: np.ndarray) -> Tuple[int, np.ndarray]:
        """Select action given stacked features.

        Phi: (n_actions, dim)
        Returns: (best_idx, sampled_theta)
        """

        Phi = np.asarray(Phi, dtype=np.float64)
        if Phi.ndim != 2 or Phi.shape[1] != self.dim:
            raise ValueError(f"Phi must be (n, {self.dim})")

        cov = (float(self.cfg.sigma) ** 2) * self.A_inv
        # Sample theta from multivariate normal.
        theta_tilde = self.rng.multivariate_normal(mean=self.theta_hat, cov=cov)
        scores = Phi @ theta_tilde
        best = int(np.argmax(scores))
        return best, theta_tilde.astype(np.float64)

    def update(self, *, phi: np.ndarray, reward: float) -> None:
        """Online update with exponential forgetting."""

        cfg = self.cfg
        rho = float(cfg.rho)
        lam = float(cfg.lam)
        phi = np.asarray(phi, dtype=np.float64).reshape(-1)
        if phi.size != self.dim:
            raise ValueError("phi dim mismatch")

        # Forgetting
        self.A *= rho
        self.b *= rho
        self.A += (1.0 - rho) * (lam * np.eye(self.dim, dtype=np.float64))

        # Rank-1 update
        self.A += np.outer(phi, phi)
        self.b += float(reward) * phi

        self.t += 1
        if self.t % max(1, int(cfg.recompute_inv_every)) == 0:
            self._recompute()

    def _recompute(self) -> None:
        # Add jitter for stability.
        jitter = float(self.cfg.jitter)
        A = self.A + jitter * np.eye(self.dim, dtype=np.float64)
        self.A_inv = np.linalg.inv(A)
        self.theta_hat = self.A_inv @ self.b
