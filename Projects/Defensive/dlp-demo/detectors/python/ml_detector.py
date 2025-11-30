#!/usr/bin/env python3
"""
ML-based Anomaly Detection for DLP Demo
Simple unsupervised learning for network behavior
LAB USE ONLY - FOR DEMONSTRATION PURPOSES
"""

import numpy as np
import pandas as pd
import json
import pickle
import os
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from typing import Dict, List
from dlptools.safety import SafetyChecker

class MLAnomalyDetector:
    def __init__(self, model_path: str = None):
        SafetyChecker.verify_lab_mode()
        
        self.features = [
            'bytes_sent', 'bytes_received', 'packets_per_minute',
            'unique_domains', 'avg_packet_size', 'payload_entropy'
        ]
        
        self.scaler = StandardScaler()
        
        if model_path and os.path.exists(model_path):
            self.load_model(model_path)
        else:
            self.model = IsolationForest(
                contamination=0.1,  # Expected anomaly rate
                random_state=42,
                n_estimators=100
            )
            self.is_trained = False
    
    def generate_training_data(self, n_samples: int = 1000) -> pd.DataFrame:
        """Generate synthetic training data for lab use"""
        np.random.seed(42)
        
        data = {
            'bytes_sent': np.random.exponential(1000, n_samples),
            'bytes_received': np.random.exponential(500, n_samples),
            'packets_per_minute': np.random.poisson(50, n_samples),
            'unique_domains': np.random.poisson(5, n_samples),
            'avg_packet_size': np.random.normal(500, 100, n_samples),
            'payload_entropy': np.random.uniform(3, 6, n_samples)
        }
        
        # Add some anomalies
        n_anomalies = int(n_samples * 0.1)
        anomaly_indices = np.random.choice(n_samples, n_anomalies, replace=False)
        
        for idx in anomaly_indices:
            data['bytes_sent'][idx] = np.random.exponential(10000)
            data['unique_domains'][idx] = np.random.poisson(50)
            data['payload_entropy'][idx] = np.random.uniform(7, 8)
        
        return pd.DataFrame(data)
    
    def train(self, training_data: pd.DataFrame = None):
        """Train the anomaly detection model"""
        if training_data is None:
            training_data = self.generate_training_data()
        
        # Scale features
        X = training_data[self.features]
        X_scaled = self.scaler.fit_transform(X)
        
        # Train model
        self.model.fit(X_scaled)
        self.is_trained = True
        
        print(f"Model trained on {len(training_data)} samples")
    
    def detect_anomalies(self, flow_data: List[Dict]) -> List[Dict]:
        """Detect anomalies in flow data"""
        if not self.is_trained:
            raise ValueError("Model not trained. Call train() first.")
        
        results = []
        
        for flow in flow_data:
            # Extract features
            features = np.array([[
                flow.get('bytes_sent', 0),
                flow.get('bytes_received', 0),
                flow.get('packets_per_minute', 0),
                flow.get('unique_domains', 0),
                flow.get('avg_packet_size', 0),
                flow.get('payload_entropy', 0)
            ]])
            
            # Scale and predict
            features_scaled = self.scaler.transform(features)
            score = self.model.decision_function(features_scaled)[0]
            is_anomaly = self.model.predict(features_scaled)[0] == -1
            
            results.append({
                **flow,
                'anomaly_score': float(score),
                'is_anomaly': bool(is_anomaly),
                'ml_confidence': abs(score)  # Higher absolute value = more confident
            })
        
        return results
    
    def save_model(self, path: str):
        """Save trained model"""
        with open(path, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'scaler': self.scaler,
                'is_trained': self.is_trained
            }, f)
    
    def load_model(self, path: str):
        """Load trained model"""
        with open(path, 'rb') as f:
            saved = pickle.load(f)
            self.model = saved['model']
            self.scaler = saved['scaler']
            self.is_trained = saved['is_trained']

# Example usage and limitations documentation
def demonstrate_ml_detector():
    """Demonstrate the ML detector with example data"""
    SafetyChecker.verify_lab_mode()
    
    print("ML Anomaly Detector Demonstration")
    print("=" * 50)
    
    # Initialize and train detector
    detector = MLAnomalyDetector()
    detector.train()
    
    # Test data - mix of normal and suspicious behavior
    test_flows = [
        # Normal behavior
        {
            'src_ip': '10.1.1.100',
            'bytes_sent': 500,
            'bytes_received': 2000,
            'packets_per_minute': 30,
            'unique_domains': 3,
            'avg_packet_size': 600,
            'payload_entropy': 4.2
        },
        # Suspicious behavior (data exfiltration)
        {
            'src_ip': '10.1.1.101',
            'bytes_sent': 15000,
            'bytes_received': 100,
            'packets_per_minute': 200,
            'unique_domains': 45,
            'avg_packet_size': 75,
            'payload_entropy': 7.5
        },
        # Beaconing behavior
        {
            'src_ip': '10.1.1.102',
            'bytes_sent': 50,
            'bytes_received': 100,
            'packets_per_minute': 2,  # Very regular
            'unique_domains': 1,
            'avg_packet_size': 75,
            'payload_entropy': 3.8
        }
    ]
    
    # Detect anomalies
    results = detector.detect_anomalies(test_flows)
    
    print("\nDetection Results:")
    print("-" * 50)
    for result in results:
        status = "ANOMALY" if result['is_anomaly'] else "Normal"
        print(f"IP: {result['src_ip']:15} | {status:8} | Score: {result['anomaly_score']:7.3f} | Confidence: {result['ml_confidence']:.3f}")
    
    print("\nLimitations and Considerations:")
    print("-" * 50)
    print("1. Training data is synthetic - real models need actual baseline data")
    print("2. Feature selection is basic - real deployments need domain expertise")
    print("3. Model requires regular retraining for concept drift")
    print("4. High false positive rate expected without tuning")
    print("5. Human review required for all ML-based detections")
    print("6. Model explainability is limited with Isolation Forest")

if __name__ == "__main__":
    demonstrate_ml_detector()
