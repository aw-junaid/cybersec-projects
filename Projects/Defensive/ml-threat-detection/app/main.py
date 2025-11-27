import pandas as pd
import numpy as np
import logging
from datetime import datetime, timedelta
import json
import warnings
warnings.filterwarnings('ignore')

from app.data.preprocessor import DataPreprocessor
from app.models.ensemble import EnsembleAnomalyDetector
from app.monitoring.drift_detector import DataDriftDetector, ConceptDriftDetector
from app.utils.visualization import ThreatVisualizer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('threat_detection.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class MLThreatDetector:
    """Main ML-based threat detection system"""
    
    def __init__(self, config_path=None):
        self.config = self._load_config(config_path)
        self.preprocessor = DataPreprocessor()
        self.ensemble_detector = EnsembleAnomalyDetector()
        self.data_drift_detector = DataDriftDetector()
        self.concept_drift_detector = ConceptDriftDetector()
        self.visualizer = ThreatVisualizer()
        
        self.is_trained = False
        self.reference_data = None
        
    def _load_config(self, config_path):
        """Load configuration from file"""
        default_config = {
            'training': {
                'validation_split': 0.2,
                'contamination': 0.1,
                'feature_selection_k': 20
            },
            'monitoring': {
                'drift_detection_interval': 24,  # hours
                'performance_threshold': 0.7,
                'retraining_interval': 30  # days
            },
            'alerts': {
                'high_confidence_threshold': 0.8,
                'medium_confidence_threshold': 0.6
            }
        }
        
        if config_path:
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                # Merge with default config
                default_config.update(user_config)
            except Exception as e:
                logger.warning(f"Error loading config file: {e}. Using default config.")
        
        return default_config
    
    def generate_sample_data(self, n_samples=10000, n_anomalies=100):
        """Generate sample network data for testing"""
        logger.info("Generating sample network data...")
        
        np.random.seed(42)
        
        data = []
        
        for i in range(n_samples):
            # Normal traffic patterns
            if i < n_samples - n_anomalies:
                src_ip = f"192.168.{np.random.randint(1, 3)}.{np.random.randint(1, 50)}"
                dst_ip = f"10.0.{np.random.randint(1, 3)}.{np.random.randint(1, 100)}"
                protocol = np.random.choice(['TCP', 'UDP', 'ICMP'], p=[0.7, 0.25, 0.05])
                dst_port = np.random.choice([80, 443, 22, 53, 3389, 1433], p=[0.4, 0.3, 0.1, 0.1, 0.05, 0.05])
                packet_size = np.random.normal(500, 200)
                duration = np.random.exponential(10)
                
            # Anomalous traffic patterns
            else:
                src_ip = f"192.168.{np.random.randint(1, 3)}.{np.random.randint(100, 255)}"
                dst_ip = f"10.0.{np.random.randint(3, 10)}.{np.random.randint(1, 50)}"
                protocol = np.random.choice(['TCP', 'UDP'], p=[0.5, 0.5])
                dst_port = np.random.randint(10000, 65535)
                packet_size = np.random.normal(1500, 500)
                duration = np.random.exponential(60)
            
            timestamp = datetime.now() - timedelta(hours=np.random.randint(0, 24))
            
            data.append({
                'timestamp': timestamp,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': protocol,
                'dst_port': dst_port,
                'packet_size': max(64, packet_size),
                'duration': max(1, duration),
                'is_anomaly': 1 if i >= n_samples - n_anomalies else -1
            })
        
        df = pd.DataFrame(data)
        logger.info(f"Generated {len(df)} samples with {n_anomalies} anomalies")
        
        return df
    
    def train_models(self, data=None):
        """Train the ensemble of ML models"""
        logger.info("Starting model training...")
        
        try:
            # Generate sample data if none provided
            if data is None:
                data = self.generate_sample_data()
            
            # Separate features and target
            X = data.drop('is_anomaly', axis=1)
            y = data['is_anomaly']
            
            # Preprocess data
            X_processed = self.preprocessor.preprocess_network_data(X)
            
            # Select features
            X_selected = self.preprocessor.select_features(
                X_processed, 
                y, 
                k=self.config['training']['feature_selection_k']
            )
            
            # Set reference data for drift detection
            self.reference_data = X_selected
            self.data_drift_detector.set_reference_data(X_selected)
            
            # Train ensemble
            self.ensemble_detector.train(X_selected)
            
            # Evaluate performance
            performance = self.ensemble_detector.get_model_performance(X_selected, y)
            
            self.is_trained = True
            logger.info("Model training completed successfully")
            
            return performance
            
        except Exception as e:
            logger.error(f"Error training models: {e}")
            raise
    
    def detect_threats(self, new_data):
        """Detect threats in new data"""
        if not self.is_trained:
            raise ValueError("Models must be trained before threat detection")
        
        logger.info("Detecting threats in new data...")
        
        try:
            # Preprocess new data
            X_processed = self.preprocessor.preprocess_network_data(new_data)
            X_selected = self.preprocessor.select_features(X_processed)
            
            # Check for data drift
            drift_metrics = self.data_drift_detector.detect_drift(X_selected)
            
            # Get predictions
            predictions = self.ensemble_detector.predict(X_selected)
            probabilities = self.ensemble_detector.predict_proba(X_selected)
            
            # Create results
            results = []
            for i, (pred, prob) in enumerate(zip(predictions, probabilities)):
                confidence_level = 'high' if prob > self.config['alerts']['high_confidence_threshold'] else \
                                 'medium' if prob > self.config['alerts']['medium_confidence_threshold'] else 'low'
                
                result = {
                    'index': i,
                    'is_anomaly': bool(pred == -1),
                    'anomaly_score': float(prob),
                    'confidence': confidence_level,
                    'timestamp': datetime.utcnow()
                }
                
                # Add feature explanations for high-confidence anomalies
                if result['is_anomaly'] and confidence_level in ['high', 'medium']:
                    try:
                        explanations = self.ensemble_detector.get_feature_importance()
                        result['explanations'] = explanations
                    except Exception as e:
                        logger.warning(f"Could not generate explanations: {e}")
                
                results.append(result)
            
            threat_report = {
                'total_samples': len(new_data),
                'anomalies_detected': sum(1 for r in results if r['is_anomaly']),
                'high_confidence_threats': sum(1 for r in results if r['confidence'] == 'high' and r['is_anomaly']),
                'data_drift_detected': drift_metrics['overall_drift'],
                'results': results,
                'drift_metrics': drift_metrics
            }
            
            logger.info(f"Threat detection completed: {threat_report['anomalies_detected']} anomalies found")
            
            return threat_report
            
        except Exception as e:
            logger.error(f"Error detecting threats: {e}")
            raise
    
    def monitor_performance(self, X_test, y_test):
        """Monitor model performance and detect concept drift"""
        if not self.is_trained:
            raise ValueError("Models must be trained before performance monitoring")
        
        logger.info("Monitoring model performance...")
        
        try:
            # Preprocess test data
            X_processed = self.preprocessor.preprocess_network_data(X_test)
            X_selected = self.preprocessor.select_features(X_processed)
            
            # Get performance metrics
            performance = self.ensemble_detector.get_model_performance(X_selected, y_test)
            ensemble_performance = performance.get('ensemble', {})
            
            # Add to concept drift detector
            self.concept_drift_detector.add_performance_metrics(ensemble_performance)
            
            # Check for concept drift
            concept_drift = self.concept_drift_detector.detect_concept_drift('f1_score')
            
            monitoring_report = {
                'performance_metrics': ensemble_performance,
                'concept_drift_detected': concept_drift.get('drift_detected', False),
                'concept_drift_metrics': concept_drift,
                'meets_performance_threshold': ensemble_performance.get('f1_score', 0) >= self.config['monitoring']['performance_threshold'],
                'timestamp': datetime.utcnow()
            }
            
            return monitoring_report
            
        except Exception as e:
            logger.error(f"Error monitoring performance: {e}")
            return {'error': str(e)}
    
    def generate_visualizations(self, threat_report, output_path='threat_report.html'):
        """Generate visualizations for threat detection results"""
        try:
            self.visualizer.create_threat_report(threat_report, output_path)
            logger.info(f"Visualizations saved to {output_path}")
        except Exception as e:
            logger.error(f"Error generating visualizations: {e}")
    
    def save_system(self, filepath):
        """Save the entire threat detection system"""
        if not self.is_trained:
            raise ValueError("System must be trained before saving")
        
        system_data = {
            'config': self.config,
            'preprocessor': self.preprocessor,
            'ensemble_detector': self.ensemble_detector,
            'reference_data': self.reference_data,
            'is_trained': self.is_trained,
            'save_timestamp': datetime.utcnow()
        }
        
        import joblib
        joblib.dump(system_data, filepath)
        logger.info(f"Threat detection system saved to {filepath}")
    
    def load_system(self, filepath):
        """Load a saved threat detection system"""
        import joblib
        system_data = joblib.load(filepath)
        
        self.config = system_data['config']
        self.preprocessor = system_data['preprocessor']
        self.ensemble_detector = system_data['ensemble_detector']
        self.reference_data = system_data['reference_data']
        self.is_trained = system_data['is_trained']
        
        # Reinitialize drift detectors with reference data
        if self.reference_data is not None:
            self.data_drift_detector.set_reference_data(self.reference_data)
        
        logger.info(f"Threat detection system loaded from {filepath}")

def main():
    """Main function to demonstrate the ML threat detection system"""
    print("ML-Based Threat Detection System")
    print("================================")
    
    # Initialize system
    threat_detector = MLThreatDetector()
    
    try:
        # Train models
        print("\n1. Training ML models...")
        performance = threat_detector.train_models()
        print(f"Training completed. Ensemble F1-score: {performance['ensemble']['f1_score']:.3f}")
        
        # Generate new test data
        print("\n2. Generating test data...")
        test_data = threat_detector.generate_sample_data(n_samples=1000, n_anomalies=50)
        X_test = test_data.drop('is_anomaly', axis=1)
        y_test = test_data['is_anomaly']
        
        # Detect threats
        print("\n3. Detecting threats...")
        threat_report = threat_detector.detect_threats(X_test)
        print(f"Detected {threat_report['anomalies_detected']} anomalies "
              f"({threat_report['high_confidence_threats']} high confidence)")
        
        # Monitor performance
        print("\n4. Monitoring performance...")
        monitoring_report = threat_detector.monitor_performance(X_test, y_test)
        print(f"Performance F1-score: {monitoring_report['performance_metrics']['f1_score']:.3f}")
        print(f"Concept drift detected: {monitoring_report['concept_drift_detected']}")
        
        # Generate visualizations
        print("\n5. Generating visualizations...")
        threat_detector.generate_visualizations(threat_report, 'threat_report.html')
        print("Visualizations saved to threat_report.html")
        
        # Save system
        print("\n6. Saving system...")
        threat_detector.save_system('threat_detection_system.joblib')
        print("System saved to threat_detection_system.joblib")
        
        print("\n✅ ML Threat Detection System demonstration completed successfully!")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
