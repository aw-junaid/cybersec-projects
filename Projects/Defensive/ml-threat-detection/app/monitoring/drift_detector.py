import numpy as np
from scipy import stats
from sklearn.covariance import EllipticEnvelope
import logging
from datetime import datetime, timedelta
import warnings

logger = logging.getLogger(__name__)

class DataDriftDetector:
    """Detect data drift in feature distributions"""
    
    def __init__(self, reference_data=None, alpha=0.05):
        self.reference_data = reference_data
        self.alpha = alpha
        self.drift_detected = False
        self.drift_metrics = {}
        
    def set_reference_data(self, reference_data):
        """Set reference data for drift detection"""
        self.reference_data = reference_data
        logger.info(f"Reference data set with shape: {reference_data.shape}")
    
    def detect_drift(self, current_data, method='ks'):
        """Detect data drift between reference and current data"""
        if self.reference_data is None:
            raise ValueError("Reference data must be set before drift detection")
        
        if self.reference_data.shape[1] != current_data.shape[1]:
            raise ValueError("Reference and current data must have same number of features")
        
        drift_results = {}
        drift_detected = False
        
        for feature_idx in range(self.reference_data.shape[1]):
            ref_feature = self.reference_data[:, feature_idx]
            curr_feature = current_data[:, feature_idx]
            
            try:
                if method == 'ks':
                    # Kolmogorov-Smirnov test
                    stat, p_value = stats.ks_2samp(ref_feature, curr_feature)
                    drift_detected_feature = p_value < self.alpha
                    
                elif method == 'anderson':
                    # Anderson-Darling test
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore")
                        result = stats.anderson_ksamp([ref_feature, curr_feature])
                    stat, p_value = result.statistic, result.significance_level
                    drift_detected_feature = p_value < self.alpha
                
                elif method == 'wasserstein':
                    # Wasserstein distance
                    from scipy.stats import wasserstein_distance
                    stat = wasserstein_distance(ref_feature, curr_feature)
                    p_value = None
                    # Simple threshold-based detection
                    drift_detected_feature = stat > 0.1  # Adjust threshold as needed
                
                else:
                    raise ValueError(f"Unknown drift detection method: {method}")
                
                drift_results[feature_idx] = {
                    'statistic': stat,
                    'p_value': p_value,
                    'drift_detected': drift_detected_feature
                }
                
                if drift_detected_feature:
                    drift_detected = True
                    logger.warning(f"Data drift detected in feature {feature_idx}")
                    
            except Exception as e:
                logger.error(f"Error detecting drift for feature {feature_idx}: {e}")
                drift_results[feature_idx] = {
                    'statistic': None,
                    'p_value': None,
                    'drift_detected': False,
                    'error': str(e)
                }
        
        self.drift_detected = drift_detected
        self.drift_metrics = {
            'method': method,
            'alpha': self.alpha,
            'results': drift_results,
            'overall_drift': drift_detected,
            'timestamp': datetime.utcnow()
        }
        
        return self.drift_metrics
    
    def get_drift_summary(self):
        """Get summary of drift detection results"""
        if not self.drift_metrics:
            return {"message": "No drift detection performed yet"}
        
        total_features = len(self.drift_metrics['results'])
        drifted_features = sum(1 for r in self.drift_metrics['results'].values() 
                             if r.get('drift_detected', False))
        
        summary = {
            'total_features': total_features,
            'drifted_features': drifted_features,
            'drift_percentage': (drifted_features / total_features) * 100,
            'overall_drift_detected': self.drift_detected,
            'detection_method': self.drift_metrics['method'],
            'timestamp': self.drift_metrics['timestamp']
        }
        
        return summary

class ConceptDriftDetector:
    """Detect concept drift in model performance"""
    
    def __init__(self, window_size=1000, drift_threshold=0.1):
        self.window_size = window_size
        self.drift_threshold = drift_threshold
        self.performance_history = []
        self.drift_detected = False
        
    def add_performance_metrics(self, metrics):
        """Add performance metrics to history"""
        self.performance_history.append({
            'timestamp': datetime.utcnow(),
            'metrics': metrics
        })
        
        # Keep only recent history
        if len(self.performance_history) > self.window_size:
            self.performance_history = self.performance_history[-self.window_size:]
    
    def detect_concept_drift(self, metric_name='f1_score'):
        """Detect concept drift based on performance metrics"""
        if len(self.performance_history) < 2:
            return {"message": "Insufficient data for concept drift detection"}
        
        # Extract metric values
        metric_values = [entry['metrics'].get(metric_name, 0) 
                        for entry in self.performance_history]
        
        if len(metric_values) < 10:
            return {"message": "Need more data points for reliable detection"}
        
        # Split into windows for comparison
        window1 = metric_values[:len(metric_values)//2]
        window2 = metric_values[len(metric_values)//2:]
        
        # Statistical test for difference in means
        try:
            t_stat, p_value = stats.ttest_ind(window1, window2, equal_var=False)
            
            # Calculate performance degradation
            mean1 = np.mean(window1)
            mean2 = np.mean(window2)
            degradation = (mean1 - mean2) / mean1 if mean1 > 0 else 0
            
            drift_detected = (p_value < 0.05) and (degradation > self.drift_threshold)
            
            result = {
                'metric': metric_name,
                't_statistic': t_stat,
                'p_value': p_value,
                'degradation_percentage': degradation * 100,
                'drift_detected': drift_detected,
                'window1_mean': mean1,
                'window2_mean': mean2,
                'timestamp': datetime.utcnow()
            }
            
            if drift_detected:
                self.drift_detected = True
                logger.warning(f"Concept drift detected for metric {metric_name}: "
                             f"degradation {degradation:.2%}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error detecting concept drift: {e}")
            return {'error': str(e)}
