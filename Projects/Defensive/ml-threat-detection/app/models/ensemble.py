import numpy as np
from sklearn.ensemble import VotingClassifier
from sklearn.calibration import CalibratedClassifierCV
import logging
import joblib
from .isolation_forest import IsolationForestDetector
from .autoencoder import AutoencoderDetector
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor

logger = logging.getLogger(__name__)

class EnsembleAnomalyDetector:
    """Ensemble of multiple anomaly detection models"""
    
    def __init__(self, models_config=None):
        self.models = {}
        self.model_weights = {}
        self.is_trained = False
        self.feature_names = []
        
        # Default models configuration
        if models_config is None:
            self.models_config = {
                'isolation_forest': {
                    'class': IsolationForestDetector,
                    'params': {'contamination': 0.1, 'random_state': 42},
                    'weight': 0.4
                },
                'autoencoder': {
                    'class': AutoencoderDetector,
                    'params': {'encoding_dim': 32, 'hidden_layers': [64, 32]},
                    'weight': 0.4
                },
                'local_outlier_factor': {
                    'class': LocalOutlierFactor,
                    'params': {'contamination': 0.1, 'novelty': True},
                    'weight': 0.2
                }
            }
        else:
            self.models_config = models_config
    
    def initialize_models(self):
        """Initialize all models"""
        for name, config in self.models_config.items():
            model_class = config['class']
            model_params = config['params']
            self.model_weights[name] = config.get('weight', 1.0)
            
            try:
                self.models[name] = model_class(**model_params)
                logger.info(f"Initialized model: {name}")
            except Exception as e:
                logger.error(f"Error initializing model {name}: {e}")
    
    def train(self, X, feature_names=None):
        """Train all models in the ensemble"""
        logger.info("Training ensemble of anomaly detection models...")
        
        if not self.models:
            self.initialize_models()
        
        self.feature_names = feature_names or [f"feature_{i}" for i in range(X.shape[1])]
        
        # Train each model
        for name, model in self.models.items():
            try:
                logger.info(f"Training {name}...")
                
                if hasattr(model, 'train'):
                    # Custom models with train method
                    if hasattr(model, 'feature_names'):
                        model.train(X, self.feature_names)
                    else:
                        model.train(X)
                else:
                    # Scikit-learn models with fit method
                    model.fit(X)
                
                logger.info(f"Completed training {name}")
                
            except Exception as e:
                logger.error(f"Error training {name}: {e}")
                # Remove failed model from ensemble
                del self.models[name]
                del self.model_weights[name]
        
        self.is_trained = True
        logger.info(f"Ensemble training completed with {len(self.models)} models")
    
    def predict(self, X):
        """Predict using ensemble voting"""
        if not self.is_trained:
            raise ValueError("Ensemble must be trained before prediction")
        
        # Get predictions from all models
        all_predictions = []
        all_weights = []
        
        for name, model in self.models.items():
            try:
                if hasattr(model, 'predict'):
                    predictions = model.predict(X)
                    
                    # Convert to binary (0 for normal, 1 for anomaly)
                    binary_predictions = (predictions == -1).astype(int)
                    all_predictions.append(binary_predictions)
                    all_weights.append(self.model_weights[name])
                
            except Exception as e:
                logger.error(f"Error getting predictions from {name}: {e}")
        
        if not all_predictions:
            raise ValueError("No models produced valid predictions")
        
        # Weighted voting
        all_predictions = np.array(all_predictions)
        all_weights = np.array(all_weights).reshape(-1, 1)
        
        # Calculate weighted sum
        weighted_predictions = np.sum(all_predictions * all_weights, axis=0)
        
        # Threshold for final prediction (weighted majority)
        threshold = np.sum(all_weights) / 2
        ensemble_predictions = np.where(weighted_predictions > threshold, -1, 1)
        
        return ensemble_predictions
    
    def predict_proba(self, X):
        """Predict anomaly probabilities using ensemble"""
        if not self.is_trained:
            raise ValueError("Ensemble must be trained before prediction")
        
        # Get anomaly scores from all models
        all_scores = []
        all_weights = []
        
        for name, model in self.models.items():
            try:
                if hasattr(model, 'predict_proba'):
                    scores = model.predict_proba(X)
                elif hasattr(model, 'decision_function'):
                    scores = model.decision_function(X)
                elif hasattr(model, 'get_reconstruction_errors'):
                    scores = model.get_reconstruction_errors(X)
                else:
                    # Fallback to predictions
                    predictions = model.predict(X)
                    scores = (predictions == -1).astype(float)
                
                # Normalize scores to 0-1 range
                if scores is not None:
                    scores_normalized = (scores - np.min(scores)) / (np.max(scores) - np.min(scores) + 1e-8)
                    all_scores.append(scores_normalized)
                    all_weights.append(self.model_weights[name])
                
            except Exception as e:
                logger.error(f"Error getting scores from {name}: {e}")
        
        if not all_scores:
            raise ValueError("No models produced valid scores")
        
        # Weighted average of scores
        all_scores = np.array(all_scores)
        all_weights = np.array(all_weights).reshape(-1, 1)
        
        ensemble_scores = np.average(all_scores, axis=0, weights=all_weights)
        
        return ensemble_scores
    
    def get_model_performance(self, X, y_true):
        """Get performance metrics for each model and ensemble"""
        if not self.is_trained:
            raise ValueError("Ensemble must be trained before evaluation")
        
        from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score
        
        performance = {}
        
        # Evaluate individual models
        for name, model in self.models.items():
            try:
                if hasattr(model, 'predict'):
                    y_pred = model.predict(X)
                    y_pred_binary = (y_pred == -1).astype(int)
                    y_true_binary = (y_true == -1).astype(int)
                    
                    precision = precision_score(y_true_binary, y_pred_binary)
                    recall = recall_score(y_true_binary, y_pred_binary)
                    f1 = f1_score(y_true_binary, y_pred_binary)
                    
                    performance[name] = {
                        'precision': precision,
                        'recall': recall,
                        'f1_score': f1
                    }
                    
            except Exception as e:
                logger.error(f"Error evaluating {name}: {e}")
                performance[name] = {'error': str(e)}
        
        # Evaluate ensemble
        y_pred_ensemble = self.predict(X)
        y_pred_ensemble_binary = (y_pred_ensemble == -1).astype(int)
        y_true_binary = (y_true == -1).astype(int)
        
        ensemble_precision = precision_score(y_true_binary, y_pred_ensemble_binary)
        ensemble_recall = recall_score(y_true_binary, y_pred_ensemble_binary)
        ensemble_f1 = f1_score(y_true_binary, y_pred_ensemble_binary)
        
        performance['ensemble'] = {
            'precision': ensemble_precision,
            'recall': ensemble_recall,
            'f1_score': ensemble_f1
        }
        
        return performance
    
    def get_feature_importance(self):
        """Get feature importance from ensemble (if available)"""
        feature_importance = {}
        
        for name, model in self.models.items():
            try:
                if hasattr(model, 'get_feature_importance'):
                    importance = model.get_feature_importance()
                    feature_importance[name] = importance
                elif hasattr(model, 'feature_importances_'):
                    feature_importance[name] = dict(zip(
                        self.feature_names, 
                        model.feature_importances_
                    ))
            except Exception as e:
                logger.error(f"Error getting feature importance from {name}: {e}")
        
        return feature_importance
    
    def save_ensemble(self, filepath):
        """Save ensemble to file"""
        if not self.is_trained:
            raise ValueError("Ensemble must be trained before saving")
        
        ensemble_data = {
            'models_config': self.models_config,
            'model_weights': self.model_weights,
            'feature_names': self.feature_names,
            'is_trained': self.is_trained
        }
        
        # Save individual models
        for name, model in self.models.items():
            if hasattr(model, 'save_model'):
                model_path = f"{filepath}_{name}.joblib"
                model.save_model(model_path)
                ensemble_data[f'{name}_path'] = model_path
        
        joblib.dump(ensemble_data, filepath)
        logger.info(f"Ensemble saved to {filepath}")
    
    def load_ensemble(self, filepath):
        """Load ensemble from file"""
        ensemble_data = joblib.load(filepath)
        
        self.models_config = ensemble_data['models_config']
        self.model_weights = ensemble_data['model_weights']
        self.feature_names = ensemble_data['feature_names']
        self.is_trained = ensemble_data['is_trained']
        
        # Load individual models
        self.initialize_models()
        
        for name, model in self.models.items():
            model_path = ensemble_data.get(f'{name}_path')
            if model_path and hasattr(model, 'load_model'):
                try:
                    model.load_model(model_path)
                    logger.info(f"Loaded model: {name}")
                except Exception as e:
                    logger.error(f"Error loading model {name}: {e}")
        
        logger.info(f"Ensemble loaded from {filepath}")
