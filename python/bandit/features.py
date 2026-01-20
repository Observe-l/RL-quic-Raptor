from __future__ import annotations

import numpy as np


def phi(*, x: np.ndarray, a_onehot: np.ndarray) -> np.ndarray:
    """Feature map phi(x,a) = [1, x, onehot(a), x ⊗ onehot(a)].

    Shapes:
      x: (d,)
      a_onehot: (m,)
      phi: (1 + d + m + d*m,)
    """

    x = np.asarray(x, dtype=np.float32).reshape(-1)
    a_onehot = np.asarray(a_onehot, dtype=np.float32).reshape(-1)

    cross = (x[:, None] * a_onehot[None, :]).reshape(-1)
    return np.concatenate(
        [
            np.ones((1,), dtype=np.float32),
            x,
            a_onehot,
            cross,
        ],
        axis=0,
    )
