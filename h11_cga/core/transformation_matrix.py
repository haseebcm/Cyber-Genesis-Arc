from __future__ import annotations
import logging
import numpy as np
import time
from collections import deque
from h11_cga.types import SecurityState, DomainVector, CascadePath, NUM_DIMENSIONS, DIMENSION_INDEX, DIMENSION_NAMES

logger = logging.getLogger(__name__)

class TransformationMatrix:
    """
    11×11 Transformation Matrix (T_c) modeling the 121 influence nodes
    between structural cyber security dimensions.
    """
    def __init__(self, matrix: np.ndarray | None = None):
        if matrix is None:
            self._matrix = self._build_default_matrix()
        else:
            self._matrix = matrix.copy()

    def get_influence(self, source: int | str, target: int | str) -> float:
        """Returns the directional influence scalar from source to target."""
        src_idx = source if isinstance(source, int) else DIMENSION_INDEX.get(source.lower())
        tgt_idx = target if isinstance(target, int) else DIMENSION_INDEX.get(target.lower())
        
        if src_idx is not None and tgt_idx is not None:
            return float(self._matrix[src_idx, tgt_idx])
        return 0.0

    def set_influence(self, source: int | str, target: int | str, value: float) -> None:
        """Adjusts the direct transformation scalar from source to target."""
        src_idx = source if isinstance(source, int) else DIMENSION_INDEX.get(source.lower())
        tgt_idx = target if isinstance(target, int) else DIMENSION_INDEX.get(target.lower())
        
        if src_idx is not None and tgt_idx is not None:
            self._matrix[src_idx, tgt_idx] = float(value)

    def propagate_state(self, state: SecurityState, perturbation: np.ndarray, dt: float = 1.0, domain_vector: DomainVector | None = None) -> SecurityState:
        """
        Propagates state forward in time applying matrix influences.
        X_c(t+dt) = X_c(t) + dt * (T_c @ perturbation) * a
        """
        activations = domain_vector.activations if domain_vector else np.ones(NUM_DIMENSIONS)
        delta = dt * (self._matrix @ perturbation) * activations
        
        new_state = state.copy()
        new_state.vector = state.vector + delta
        new_state.timestamp = time.time()
        return new_state

    def find_cascade_path(self, source: int | str, min_influence: float = 0.1, max_depth: int = 8) -> list[CascadePath]:
        """
        Discovers systemic chain-reaction pathways across the transformation matrix.
        """
        src_idx = source if isinstance(source, int) else DIMENSION_INDEX.get(source.lower())
        if src_idx is None:
            return []
            
        paths = []
        queue = deque([(src_idx, [src_idx], 1.0)])
        
        while queue:
            current_dim, current_path, current_influence = queue.popleft()
            
            if len(current_path) > 1:
                path_names = [DIMENSION_NAMES[i] for i in current_path]
                paths.append(CascadePath(path=current_path, total_influence=current_influence, path_names=path_names))
            
            if len(current_path) > max_depth:
                continue
                
            for target_dim in range(NUM_DIMENSIONS):
                if target_dim in current_path:
                    continue
                
                influence = self._matrix[current_dim, target_dim]
                if influence > 0:
                    new_influence = current_influence * influence
                    if new_influence >= min_influence:
                        queue.append((target_dim, current_path + [target_dim], new_influence))
        return paths

    def get_vulnerability_amplification(self) -> np.ndarray:
        """Extracts systemic vulnerabilities via eigenvalue analysis."""
        eigenvalues = np.linalg.eigvals(self._matrix)
        return np.abs(eigenvalues)

    def get_most_vulnerable_dimension(self) -> tuple[str, float]:
        """Identifies the dimension with the largest combined incoming influence."""
        incoming_sum = np.sum(self._matrix, axis=0)
        max_idx = int(np.argmax(incoming_sum))
        return DIMENSION_NAMES[max_idx], float(incoming_sum[max_idx])

    def get_strongest_coupling(self) -> tuple[str, str, float]:
        """Finds the maximum transformation coefficient currently in the system."""
        idx = np.unravel_index(np.argmax(self._matrix, axis=None), self._matrix.shape)
        return DIMENSION_NAMES[idx[0]], DIMENSION_NAMES[idx[1]], float(self._matrix[idx])

    def _build_default_matrix(self) -> np.ndarray:
        """Initializes the baseline 11x11 matrix with realistic internal cyber influences."""
        mat = np.random.uniform(0.05, 0.15, (NUM_DIMENSIONS, NUM_DIMENSIONS))
        np.fill_diagonal(mat, 0.0)
        
        def set_val(src: str, dst: str, val: float):
            i = DIMENSION_INDEX.get(src)
            j = DIMENSION_INDEX.get(dst)
            if i is not None and j is not None:
                mat[i, j] = val

        set_val("identity", "authorization", 0.85)
        set_val("authorization", "compute", 0.70)
        set_val("authorization", "execution", 0.75)
        set_val("compute", "memory", 0.72)
        set_val("memory", "data", 0.80)
        set_val("network", "compute", 0.55)
        set_val("network", "data", 0.45)
        set_val("execution", "memory", 0.65)
        set_val("execution", "resource", 0.50)
        set_val("trust", "authorization", 0.60)
        set_val("trust", "governance", 0.55)
        set_val("governance", "authorization", 0.50)
        set_val("data", "recovery", 0.40)
        set_val("recovery", "trust", 0.35)
        set_val("identity", "trust", 0.70)
        
        return mat
