from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

import numpy as np

try:
    import torch
except Exception:  # CPU-only installations can continue using the NumPy backend.
    torch = None


@dataclass
class LinTSConfig:
    # Prior / ridge
    lam: float = 1.0
    # Posterior sampling noise scale (reward assumed roughly in [-1, 1])
    sigma: float = 0.2
    # Exponential forgetting (rho close to 1 keeps long memory)
    rho: float = 0.9999
    # Retained for checkpoint/CLI compatibility. A^{-1} is now recomputed
    # exactly after every update, so this value no longer controls the cadence.
    recompute_inv_every: int = 1
    # Numerical jitter
    jitter: float = 1e-6
    # Random seed
    seed: int = 0


class LinTS:
    """Linear Thompson Sampling with exponential forgetting.

    Maintains A,b and their exact posterior inverse/mean after every update.
    Selection uses theta~N(theta_hat, sigma^2 A^{-1}).
    """

    def __init__(self, dim: int, cfg: LinTSConfig, *, device: str = "cpu"):
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
        requested_device = str(device)
        if requested_device.startswith("cuda"):
            if torch is None or not torch.cuda.is_available():
                raise RuntimeError("CUDA was requested for LinTS, but PyTorch CUDA is unavailable")
            self.device = torch.device(requested_device)
            eye = torch.eye(self.dim, dtype=torch.float64, device=self.device)
            self.A = lam * eye
            self.b = torch.zeros((self.dim,), dtype=torch.float64, device=self.device)
            self.A_inv = (1.0 / lam) * eye.clone()
            self.theta_hat = torch.zeros((self.dim,), dtype=torch.float64, device=self.device)
        else:
            self.device = "cpu"
            self.A = lam * np.eye(self.dim, dtype=np.float64)
            self.b = np.zeros((self.dim,), dtype=np.float64)
            self.A_inv = (1.0 / lam) * np.eye(self.dim, dtype=np.float64)
            self.theta_hat = np.zeros((self.dim,), dtype=np.float64)

        self.t = 0
        self.rng = np.random.RandomState(int(cfg.seed))

    @property
    def uses_torch(self) -> bool:
        return torch is not None and isinstance(self.A, torch.Tensor)

    def tensor(self, values):
        """Move a feature/context array or cached matrix onto the policy device."""
        if not self.uses_torch:
            return np.asarray(values, dtype=np.float64)
        if isinstance(values, torch.Tensor):
            return values.to(device=self.device, dtype=torch.float64)
        return torch.as_tensor(np.asarray(values), dtype=torch.float64, device=self.device)

    def build_phi(self, *, x: np.ndarray, a_onehot):
        """Construct the selected action feature vector on the posterior device."""
        if not self.uses_torch:
            from bandit.features import phi

            return phi(x=x, a_onehot=np.asarray(a_onehot))
        x_t = self.tensor(x).reshape(-1)
        a_t = self.tensor(a_onehot).reshape(-1)
        cross = (x_t[:, None] * a_t[None, :]).reshape(-1)
        return torch.cat((torch.ones(1, dtype=x_t.dtype, device=self.device), x_t, a_t, cross))

    def synchronize(self) -> None:
        if self.uses_torch and self.device.type == "cuda":
            torch.cuda.synchronize(self.device)

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

        if self.uses_torch:
            x_t = self.tensor(x).reshape(-1)
            action_t = self.tensor(action_features)
            d = int(x_t.numel())
            m = int(action_t.shape[1])
            expected_dim = 1 + d + m + d * m
            if int(self.dim) != expected_dim:
                raise ValueError(
                    f"action feature shape implies dim={expected_dim}, but LinTS dim={self.dim}"
                )
            theta_tilde = self._sample_theta()
            off = 1 + d
            theta_a = theta_tilde[off : off + m]
            theta_xa = theta_tilde[off + m :].reshape(d, m)
            weights = theta_a + theta_xa.T @ x_t
            scores = action_t @ weights
            best = int(torch.argmax(scores).item())
            return best, theta_tilde.detach().cpu().numpy().astype(np.float64, copy=False)

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

    def score_action_features(self, *, x: np.ndarray, action_features):
        """Greedy posterior-mean action scores without materializing full Phi."""
        if self.uses_torch:
            x_t = self.tensor(x).reshape(-1)
            action_t = self.tensor(action_features)
            d = int(x_t.numel())
            m = int(action_t.shape[1])
            if self.dim != 1 + d + m + d * m:
                raise ValueError("action feature shape does not match LinTS feature dimension")
            off = 1 + d
            theta_a = self.theta_hat[off : off + m]
            theta_xa = self.theta_hat[off + m :].reshape(d, m)
            return action_t @ (theta_a + theta_xa.T @ x_t)

        x_arr = np.asarray(x, dtype=np.float64).reshape(-1)
        action_arr = np.asarray(action_features, dtype=np.float64)
        d = int(x_arr.size)
        m = int(action_arr.shape[1])
        off = 1 + d
        theta_a = self.theta_hat[off : off + m]
        theta_xa = self.theta_hat[off + m :].reshape(d, m)
        return action_arr @ (theta_a + theta_xa.T @ x_arr)

    def _sample_theta(self) -> np.ndarray:
        """Sample theta with a numerically robust covariance factorization.

        ``RandomState.multivariate_normal`` uses an SVD internally.  For this
        runner the covariance is 1925x1925. Cholesky is the natural
        factorization for the positive-definite LinTS covariance; retry with
        small diagonal jitter and refresh the inverse before falling back to
        an eigenvalue-clipped factorization.
        """

        if self.uses_torch:
            return self._sample_theta_torch()

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

        # Refresh from A and retry before using the more expensive
        # eigenvalue-clipped fallback.
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

    def _sample_theta_torch(self):
        sigma2 = float(self.cfg.sigma) ** 2
        if sigma2 == 0.0:
            return self.theta_hat.clone()
        if not bool(torch.isfinite(self.theta_hat).all().item()) or not bool(torch.isfinite(self.A_inv).all().item()):
            self._recompute()

        eye = torch.eye(self.dim, dtype=self.A.dtype, device=self.device)
        cov = sigma2 * (0.5 * (self.A_inv + self.A_inv.T))
        diag_scale = max(1.0, float(torch.max(torch.abs(torch.diagonal(cov))).item()))
        jitters = (0.0, 1e-12 * diag_scale, 1e-10 * diag_scale, 1e-8 * diag_scale, 1e-6 * diag_scale)
        for jitter in jitters:
            try:
                factor = torch.linalg.cholesky(cov + float(jitter) * eye)
                noise = torch.as_tensor(self.rng.normal(size=self.dim), dtype=self.A.dtype, device=self.device)
                return self.theta_hat + factor @ noise
            except RuntimeError:
                continue

        self._recompute()
        cov = sigma2 * (0.5 * (self.A_inv + self.A_inv.T))
        try:
            factor = torch.linalg.cholesky(cov + 1e-8 * diag_scale * eye)
            noise = torch.as_tensor(self.rng.normal(size=self.dim), dtype=self.A.dtype, device=self.device)
            return self.theta_hat + factor @ noise
        except RuntimeError:
            eigvals, eigvecs = torch.linalg.eigh(cov)
            eigvals = torch.clamp(eigvals, min=0.0)
            noise = torch.as_tensor(self.rng.normal(size=self.dim), dtype=self.A.dtype, device=self.device)
            return self.theta_hat + eigvecs @ (torch.sqrt(eigvals) * noise)

    def update(self, *, phi: np.ndarray, reward: float) -> None:
        """Online update with exponential forgetting."""

        cfg = self.cfg
        rho = float(cfg.rho)
        lam = float(cfg.lam)
        if self.uses_torch:
            phi_t = self.tensor(phi).reshape(-1)
            if phi_t.numel() != self.dim:
                raise ValueError("phi dim mismatch")
            self._update_torch(phi=phi_t, reward=float(reward))
            return

        phi = np.asarray(phi, dtype=np.float64).reshape(-1)
        if phi.size != self.dim:
            raise ValueError("phi dim mismatch")

        # Keep the ridge term fixed while discounting the data contribution.
        self.A *= rho
        self.b *= rho
        self.A += (1.0 - rho) * (lam * np.eye(self.dim, dtype=np.float64))

        # Rank-1 update
        self.A += np.outer(phi, phi)
        self.b += float(reward) * phi

        self.t += 1
        self._recompute()

    def _update_torch(self, *, phi: "torch.Tensor", reward: float) -> None:
        rho = float(self.cfg.rho)
        lam = float(self.cfg.lam)
        self.A.mul_(rho)
        self.b.mul_(rho)
        self.A.diagonal().add_((1.0 - rho) * lam)
        self.A.add_(torch.outer(phi, phi))
        self.b.add_(float(reward) * phi)

        self.t += 1
        self._recompute()

    def _recompute(self) -> None:
        if self.uses_torch:
            eye = torch.eye(self.dim, dtype=self.A.dtype, device=self.device)
            A = self.A + float(self.cfg.jitter) * eye
            self.A_inv = torch.linalg.inv(A)
            self.A_inv = 0.5 * (self.A_inv + self.A_inv.T)
            self.theta_hat = self.A_inv @ self.b
            return
        # Add jitter for stability.
        jitter = float(self.cfg.jitter)
        A = self.A + jitter * np.eye(self.dim, dtype=np.float64)
        self.A_inv = np.linalg.inv(A)
        self.theta_hat = self.A_inv @ self.b
