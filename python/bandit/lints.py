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
    # Recompute A^{-1} exactly every N updates. Between exact recomputations,
    # LinTS uses a Sherman-Morrison rank-1 approximation.
    recompute_inv_every: int = 100
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
        if self.dim <= 0:
            raise ValueError("dim must be positive")
        if not np.isfinite(lam) or lam <= 0.0:
            raise ValueError("lam must be finite and > 0")
        if not np.isfinite(float(cfg.sigma)) or float(cfg.sigma) < 0.0:
            raise ValueError("sigma must be finite and >= 0")
        if not np.isfinite(float(cfg.rho)) or not (0.0 < float(cfg.rho) <= 1.0):
            raise ValueError("rho must be finite and in (0, 1]")
        if int(cfg.recompute_inv_every) <= 0:
            raise ValueError("recompute_inv_every must be positive")
        if not np.isfinite(float(cfg.jitter)) or float(cfg.jitter) < 0.0:
            raise ValueError("jitter must be finite and >= 0")
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

        theta_tilde = self._sample_theta()
        scores = Phi @ theta_tilde
        best = int(np.argmax(scores))
        return best, theta_tilde.astype(np.float64)

    def select_action_features(self, *, x: np.ndarray, action_features: np.ndarray) -> Tuple[int, np.ndarray]:
        """Select an action without materializing the full Phi matrix.

        For the feature map ``[1, x, a, x \u2297 a]``, with the cross block
        flattened in row-major order, the action-dependent score is:

            a @ (theta_a + Theta_xa.T @ x)

        The context-only terms are identical for every action and can be
        omitted from argmax. This is mathematically equivalent to calling
        ``select(Phi)`` with ``Phi[i] = phi(x, action_features[i])``.
        """

        x = np.asarray(x, dtype=np.float64).reshape(-1)
        action_features = np.asarray(action_features, dtype=np.float64)
        if x.ndim != 1:
            raise ValueError("x must be a vector")
        if action_features.ndim != 2:
            raise ValueError("action_features must be a 2D matrix")

        d = int(x.size)
        m = int(action_features.shape[1])
        expected_dim = 1 + d + m + d * m
        if int(self.dim) != expected_dim:
            raise ValueError(
                f"action feature shape implies dim={expected_dim}, but LinTS dim={self.dim}"
            )

        theta_tilde = self._sample_theta()
        off = 1 + d
        theta_a = theta_tilde[off : off + m]
        theta_xa = theta_tilde[off + m :].reshape(d, m)
        action_weights = theta_a + theta_xa.T @ x
        scores = action_features @ action_weights
        best = int(np.argmax(scores))
        return best, theta_tilde.astype(np.float64)

    def _sample_theta(self) -> np.ndarray:
        """Sample theta with a numerically robust covariance factorization.

        ``RandomState.multivariate_normal`` uses an SVD internally.  For this
        runner the covariance is 1925x1925 and is maintained by an approximate
        Sherman--Morrison update between exact inversions, so an otherwise
        finite matrix can occasionally make that SVD fail under heavy system
        load.  Cholesky is the natural factorization for the positive-definite
        LinTS covariance; retry with small diagonal jitter and refresh the
        inverse before falling back to an eigenvalue-clipped factorization.
        """

        sigma2 = float(self.cfg.sigma) ** 2
        if sigma2 == 0.0:
            return np.asarray(self.theta_hat, dtype=np.float64).copy()

        if not np.isfinite(self.theta_hat).all() or not np.isfinite(self.A_inv).all():
            self._recompute()

        eye = np.eye(self.dim, dtype=np.float64)
        cov = sigma2 * (0.5 * (self.A_inv + self.A_inv.T))
        scale = max(1.0, float(np.max(np.abs(np.diag(cov)))))
        jitters = (0.0, 1e-12 * scale, 1e-10 * scale, 1e-8 * scale, 1e-6 * scale)

        for jitter in jitters:
            try:
                factor = np.linalg.cholesky(cov + float(jitter) * eye)
                noise = self.rng.normal(size=self.dim)
                return np.asarray(self.theta_hat, dtype=np.float64) + factor @ noise
            except np.linalg.LinAlgError:
                continue

        # The approximate inverse may have drifted. Recompute from A and retry
        # before using the more expensive eigenvalue-clipped fallback.
        self._recompute()
        cov = sigma2 * (0.5 * (self.A_inv + self.A_inv.T))
        try:
            factor = np.linalg.cholesky(cov + 1e-8 * max(1.0, float(np.max(np.abs(np.diag(cov))))) * eye)
            noise = self.rng.normal(size=self.dim)
            return np.asarray(self.theta_hat, dtype=np.float64) + factor @ noise
        except np.linalg.LinAlgError:
            pass

        # Last-resort PSD projection. This keeps one numerical incident from
        # terminating a long experiment while preserving the LinTS sampling
        # distribution as closely as possible.
        try:
            eigvals, eigvecs = np.linalg.eigh(cov)
            eigvals = np.clip(eigvals, 0.0, None)
            noise = self.rng.normal(size=self.dim)
            return np.asarray(self.theta_hat, dtype=np.float64) + eigvecs @ (np.sqrt(eigvals) * noise)
        except np.linalg.LinAlgError as exc:
            raise np.linalg.LinAlgError(
                f"unable to factor LinTS covariance after refresh; dim={self.dim}"
            ) from exc

    def update(self, *, phi: np.ndarray, reward: float) -> None:
        """Online update with exponential forgetting."""

        cfg = self.cfg
        rho = float(cfg.rho)
        lam = float(cfg.lam)
        phi = np.asarray(phi, dtype=np.float64).reshape(-1)
        if phi.size != self.dim:
            raise ValueError("phi dim mismatch")

        # Forgetting. The ridge term is kept in A exactly. The inverse update
        # below treats this small diagonal shift approximately and is corrected
        # by the periodic exact recomputation.
        self.A *= rho
        self.b *= rho
        self.A += (1.0 - rho) * (lam * np.eye(self.dim, dtype=np.float64))

        # Rank-1 update
        self.A += np.outer(phi, phi)
        self.b += float(reward) * phi

        self.t += 1
        if self.t % int(cfg.recompute_inv_every) == 0:
            self._recompute()
        else:
            self._sherman_morrison_update(phi=phi, rho=rho)
            self.theta_hat = self.A_inv @ self.b

    def _sherman_morrison_update(self, *, phi: np.ndarray, rho: float) -> None:
        """Approximate the discounted precision update in O(dim^2).

        The exact pre-rank-one matrix is

            rho * A_old + (1-rho) * lam * I.

        The diagonal ridge shift is intentionally omitted here; the exact
        matrix ``A`` is still maintained and periodically re-inverted. This
        keeps the per-step update cheap while bounding approximation drift.
        """

        B = self.A_inv / float(rho)
        u = B @ phi
        denominator = 1.0 + float(phi @ u)
        if not np.isfinite(denominator) or denominator <= 1e-12:
            # A non-positive denominator indicates numerical drift. Recover
            # from the exact A immediately instead of publishing an invalid
            # covariance matrix.
            self._recompute()
            return

        self.A_inv = B - np.outer(u, u) / denominator
        # Keep the covariance symmetric after floating-point rank-1 updates.
        self.A_inv = 0.5 * (self.A_inv + self.A_inv.T)

    def _recompute(self) -> None:
        # Add jitter for stability.
        jitter = float(self.cfg.jitter)
        A = self.A + jitter * np.eye(self.dim, dtype=np.float64)
        self.A_inv = np.linalg.inv(A)
        self.theta_hat = self.A_inv @ self.b
