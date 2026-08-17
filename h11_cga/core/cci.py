from __future__ import annotations
import numpy as np
import logging
from collections import deque
from h11_cga.types import CGAConfig, CascadePath, NUM_DIMENSIONS, DIMENSION_INDEX, DIMENSION_NAMES

logger = logging.getLogger(__name__)

class CascadeAnalyzer:
    """
    Cascade Collapse Index (CCI) Engine for computing risk propagation
    and critical cascade paths across the 11-dimensional cyber security space.
    """
    def __init__(self, config: CGAConfig, coupling_matrix: np.ndarray | None = None):
        self.config = config
        if coupling_matrix is None:
            self._coupling_matrix = self._build_default_coupling_matrix()
        else:
            self._coupling_matrix = coupling_matrix.copy()

    def _build_default_coupling_matrix(self) -> np.ndarray:
        """Builds a default 11x11 matrix with realistic cyber coupling values."""
        mat = np.zeros((NUM_DIMENSIONS, NUM_DIMENSIONS))
        
        def set_coupling(src: str, dst: str, val: float):
            i = DIMENSION_INDEX.get(src)
            j = DIMENSION_INDEX.get(dst)
            if i is not None and j is not None:
                mat[i, j] = val

        set_coupling("identity", "authorization", 0.8)
        set_coupling("authorization", "compute", 0.6)
        set_coupling("compute", "memory", 0.7)
        set_coupling("memory", "data", 0.8)
        set_coupling("network", "compute", 0.5)
        set_coupling("authorization", "execution", 0.6)
        set_coupling("execution", "memory", 0.6)
        set_coupling("execution", "resource", 0.5)
        set_coupling("trust", "authorization", 0.7)
        set_coupling("governance", "authorization", 0.5)
        set_coupling("data", "recovery", 0.5)
        set_coupling("identity", "trust", 0.7)
        
        return mat

    def compute_cci(self, errors: np.ndarray, weights: np.ndarray | None = None) -> float:
        """
        Computes the Cascade Collapse Index CCI_c(t).
        CCI_c(t) = w^T e_c(t) + γ ||A_c^T e_c(t)||^2

        A_c is indexed [source, target], so error arriving at a target is
        summed down its column — the transpose product.
        """
        if weights is None:
            weights = np.ones(NUM_DIMENSIONS)
            
        linear_term = float(np.dot(weights, errors))
        coupled_errors = self._coupling_matrix.T @ errors
        quadratic_term = self.config.cci_coupling_gamma * float(np.sum(coupled_errors**2))
        return linear_term + quadratic_term

    def is_subcritical(self, cci: float) -> bool:
        """Returns True if the current CCI is below the subcritical threshold."""
        return cci < self.config.cci_threshold

    def identify_cascade_paths(self, source_dim: int, threshold: float = 0.1, max_depth: int = 6) -> list[CascadePath]:
        """
        Explores the coupling matrix using BFS to find all potential cascade paths
        emanating from the given source dimension.
        """
        paths = []
        queue = deque([(source_dim, [source_dim], 1.0)])
        
        while queue:
            current_dim, current_path, current_influence = queue.popleft()
            
            if len(current_path) > 1:
                path_names = [DIMENSION_NAMES[i] for i in current_path]
                paths.append(CascadePath(path=current_path, total_influence=current_influence))
            
            if len(current_path) > max_depth:
                continue
                
            for target_dim in range(NUM_DIMENSIONS):
                if target_dim in current_path:
                    continue  # prevent cycles
                    
                influence = self._coupling_matrix[current_dim, target_dim]
                if influence > 0:
                    new_influence = current_influence * influence
                    if new_influence > threshold:
                        queue.append((target_dim, current_path + [target_dim], new_influence))
        return paths

    def get_most_critical_path(self, errors: np.ndarray) -> CascadePath | None:
        """
        Identifies the cascade path representing the highest immediate risk,
        weighted by the magnitude of current errors.
        """
        best_path = None
        max_weighted_influence = -1.0
        
        for i in range(NUM_DIMENSIONS):
            if errors[i] <= 0:
                continue
            paths = self.identify_cascade_paths(i, threshold=0.01)
            for path in paths:
                weighted_influence = path.total_influence * errors[i]
                if weighted_influence > max_weighted_influence:
                    max_weighted_influence = weighted_influence
                    best_path = path
                    
        return best_path

    def get_coupling_matrix(self) -> np.ndarray:
        """Returns a copy of the active coupling matrix."""
        return self._coupling_matrix.copy()
