import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import precision_score, recall_score, f1_score
import logging
import joblib
from pathlib import Path

logger = logging.getLogger(__name__)

class IsolationForestDetector:
    """Isolation Forest for anomaly detection"""
    
    def __init__(self, contamination=0.1, random_state=42):
        self.contamination = contamination
        self.random_state = random_state
        self.model = None
        self.is_trained = False
        self.feature_names = []
        
    def train(self, X, feature_names=None):
        """Train the Isolation Forest model"""
        logger.info("Training Isolation Forest model...")
        
        try:
            self.model = IsolationForest(
                contamination=self.contamination,
                random_state=self.random_state,
                n_estimators=100,
                max_samples='auto'
            )
            
            self.model.fit(X)
            self.is_trained = True
            
            if feature_names:
                self.feature_names = feature_names
            else:
                self.feature_names = [f"feature_{i}" for i in range(X.shape[1])]
            
            logger.info("Isolation Forest training completed")
            
        except Exception as e:
            logger.error(f"Error training Isolation Forest: {e}")
            raise
    
    def predict(self, X):
        """Predict anomalies (-1 for anomalies, 1 for normal)"""
        if not self.is_trained:
            raise ValueError("Model must be trained before prediction")
        
        return self.model.predict(X)
    
    def predict_proba(self, X):
        """Predict anomaly scores (lower scores indicate higher anomaly probability)"""
        if not self.is_trained:
            raise ValueError("Model must be trained before prediction")
        
        return self.model.decision_function(X)
    
    def evaluate(self, X, y_true):
        """Evaluate model performance"""
        if not self.is_trained:
            raise ValueError("Model must be trained before evaluation")
        
        y_pred = self.predict(X)
        
        # Convert to binary (1 for normal, 0 for anomaly)
        y_pred_binary = (y_pred == 1).astype(int)
        y_true_binary = (y_true == 1).astype(int)
        
        precision = precision_score(y_true_binary, y_pred_binary)
        recall = recall_score(y_true_binary, y_pred_binary)
        f1 = f1_score(y_true_binary, y_pred_binary)
        
        metrics = {
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'contamination': self.contamination
        }
        
        return metrics
    
    def get_anomaly_explanations(self, X, top_features=5):
        """Get feature importance for anomaly explanations"""
        if not self.is_trained:
            raise ValueError("Model must be trained before getting explanations")
        
        # For Isolation Forest, we can use feature importance based on path lengths
        explanations = []
        
        for i, sample in enumerate(X):
            anomaly_score = self.predict_proba([sample])[0]
            is_anomaly = self.predict([sample])[0] == -1
            
            # Simple feature contribution based on deviation from mean
            if hasattr(self, 'training_data_mean'):
                feature_deviations = np.abs(sample - self.training_data_mean)
                top_indices = np.argsort(feature_deviations)[-top_features:][::-1]
                
                feature_contributions = []
                for idx in top_indices:
                    feature_name = self.feature_names[idx] if idx < len(self.feature_names) else f"feature_{idx}"
                    feature_contributions.append({
                        'feature': feature_name,
                        'deviation': float(feature_deviations[idx]),
                        'value': float(sample[idx]),
                        'mean_value': float(self.training_data_mean[idx])
                    })
            else:
                feature_contributions = []
            
            explanations.append({
                'sample_index': i,
                'anomaly_score': float(anomaly_score),
                'is_anomaly': bool(is_anomaly),
                'feature_contributions': feature_contributions
            })
        
        return explanations
    
    def save_model(self, filepath):
        """Save trained model to file"""
        if not self.is_trained:
            raise ValueError("Model must be trained before saving")
        
        model_data = {
            'model': self.model,
            'feature_names': self.feature_names,
            'contamination': self.contamination,
            'is_trained': self.is_trained
        }
        
        joblib.dump(model_data, filepath)
        logger.info(f"Model saved to {filepath}")
    
    def load_model(self, filepath):
        """Load model from file"""
        model_data = joblib.load(filepath)
        
        self.model = model_data['model']
        self.feature_names = model_data['feature_names']
        self.contamination = model_data['contamination']
        self.is_trained = model_data['is_trained']
        
        logger.info(f"Model loaded from {filepath}")
