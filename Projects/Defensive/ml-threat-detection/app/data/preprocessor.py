import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.feature_selection import SelectKBest, f_classif
import logging
from datetime import datetime, timedelta
import re

logger = logging.getLogger(__name__)

class DataPreprocessor:
    """Preprocess security data for ML models"""
    
    def __init__(self):
        self.scalers = {}
        self.encoders = {}
        self.feature_selector = None
        self.feature_names = []
        
    def preprocess_network_data(self, df):
        """Preprocess network traffic data"""
        logger.info("Preprocessing network data...")
        
        # Create copy to avoid modifying original
        processed_df = df.copy()
        
        # Handle missing values
        processed_df = self._handle_missing_values(processed_df)
        
        # Feature engineering for network data
        processed_df = self._engineer_network_features(processed_df)
        
        # Encode categorical variables
        processed_df = self._encode_categorical_features(processed_df)
        
        # Select and scale features
        processed_df = self._scale_features(processed_df)
        
        return processed_df
    
    def preprocess_system_logs(self, df):
        """Preprocess system log data"""
        logger.info("Preprocessing system logs...")
        
        processed_df = df.copy()
        
        # Handle missing values
        processed_df = self._handle_missing_values(processed_df)
        
        # Feature engineering for logs
        processed_df = self._engineer_log_features(processed_df)
        
        # Encode categorical variables
        processed_df = self._encode_categorical_features(processed_df)
        
        # Select and scale features
        processed_df = self._scale_features(processed_df)
        
        return processed_df
    
    def _handle_missing_values(self, df):
        """Handle missing values in the dataset"""
        # Fill numerical columns with median
        numerical_cols = df.select_dtypes(include=[np.number]).columns
        df[numerical_cols] = df[numerical_cols].fillna(df[numerical_cols].median())
        
        # Fill categorical columns with mode
        categorical_cols = df.select_dtypes(include=['object']).columns
        for col in categorical_cols:
            df[col] = df[col].fillna(df[col].mode()[0] if len(df[col].mode()) > 0 else 'unknown')
        
        return df
    
    def _engineer_network_features(self, df):
        """Engineer features from network data"""
        # Basic network features
        if 'src_ip' in df.columns:
            df['src_ip_prefix'] = df['src_ip'].apply(lambda x: '.'.join(x.split('.')[:2]) if isinstance(x, str) else 'unknown')
        
        if 'dst_ip' in df.columns:
            df['dst_ip_prefix'] = df['dst_ip'].apply(lambda x: '.'.join(x.split('.')[:2]) if isinstance(x, str) else 'unknown')
        
        # Protocol features
        if 'protocol' in df.columns:
            df['is_tcp'] = (df['protocol'] == 'TCP').astype(int)
            df['is_udp'] = (df['protocol'] == 'UDP').astype(int)
            df['is_icmp'] = (df['protocol'] == 'ICMP').astype(int)
        
        # Port features
        if 'dst_port' in df.columns:
            df['is_well_known_port'] = (df['dst_port'] <= 1024).astype(int)
            df['is_http_port'] = df['dst_port'].isin([80, 443, 8080, 8443]).astype(int)
            df['is_database_port'] = df['dst_port'].isin([1433, 1521, 3306, 5432, 27017]).astype(int)
        
        # Traffic features
        if 'packet_size' in df.columns:
            df['packet_size_bin'] = pd.cut(df['packet_size'], bins=[0, 64, 512, 1500, 9000], labels=['tiny', 'small', 'medium', 'large'])
        
        # Time-based features
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df['hour'] = df['timestamp'].dt.hour
            df['day_of_week'] = df['timestamp'].dt.dayofweek
            df['is_weekend'] = (df['day_of_week'] >= 5).astype(int)
            df['is_business_hours'] = ((df['hour'] >= 9) & (df['hour'] <= 17)).astype(int)
        
        return df
    
    def _engineer_log_features(self, df):
        """Engineer features from system logs"""
        # Event type features
        if 'event_type' in df.columns:
            df['is_auth_event'] = df['event_type'].str.contains('auth|login|ssh', case=False, na=False).astype(int)
            df['is_file_event'] = df['event_type'].str.contains('file|access|permission', case=False, na=False).astype(int)
            df['is_network_event'] = df['event_type'].str.contains('network|connection|port', case=False, na=False).astype(int)
        
        # Severity features
        if 'severity' in df.columns:
            severity_map = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
            df['severity_numeric'] = df['severity'].map(severity_map).fillna(1)
        
        # Message length features
        if 'message' in df.columns:
            df['message_length'] = df['message'].str.len().fillna(0)
            df['has_special_chars'] = df['message'].str.contains(r'[^\w\s]', na=False).astype(int)
            df['has_numbers'] = df['message'].str.contains(r'\d', na=False).astype(int)
        
        # Time-based features for logs
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df['log_hour'] = df['timestamp'].dt.hour
            df['log_minute'] = df['timestamp'].dt.minute
            df['events_per_minute'] = self._calculate_events_rate(df, 'minute')
        
        return df
    
    def _calculate_events_rate(self, df, frequency):
        """Calculate events rate per time frequency"""
        if frequency == 'minute':
            time_group = df['timestamp'].dt.floor('min')
        elif frequency == 'hour':
            time_group = df['timestamp'].dt.floor('H')
        else:
            return np.zeros(len(df))
        
        event_counts = time_group.value_counts()
        return df['timestamp'].dt.floor(frequency).map(event_counts).fillna(0)
    
    def _encode_categorical_features(self, df):
        """Encode categorical features"""
        categorical_cols = df.select_dtypes(include=['object']).columns
        
        for col in categorical_cols:
            if col not in self.encoders:
                self.encoders[col] = LabelEncoder()
                # Handle unseen categories by fitting on current data
                self.encoders[col].fit(df[col].astype(str))
            
            # Transform and handle unseen categories
            try:
                df[col] = self.encoders[col].transform(df[col].astype(str))
            except ValueError:
                # Handle unseen categories by assigning -1
                known_categories = set(self.encoders[col].classes_)
                current_categories = set(df[col].astype(str))
                unseen_categories = current_categories - known_categories
                
                if unseen_categories:
                    logger.warning(f"Unseen categories in {col}: {unseen_categories}")
                    # For unseen categories, use most frequent category
                    df[col] = df[col].astype(str).apply(
                        lambda x: self.encoders[col].transform([x])[0] 
                        if x in known_categories else -1
                    )
        
        return df
    
    def _scale_features(self, df):
        """Scale numerical features"""
        numerical_cols = df.select_dtypes(include=[np.number]).columns
        
        for col in numerical_cols:
            if col not in self.scalers:
                self.scalers[col] = StandardScaler()
                self.scalers[col].fit(df[[col]])
            
            df[col] = self.scalers[col].transform(df[[col]])
        
        return df
    
    def select_features(self, X, y=None, k=20):
        """Select most important features"""
        if y is not None and self.feature_selector is None:
            self.feature_selector = SelectKBest(score_func=f_classif, k=min(k, X.shape[1]))
            self.feature_selector.fit(X, y)
        
        if self.feature_selector is not None:
            X_selected = self.feature_selector.transform(X)
            self.feature_names = [f"feature_{i}" for i in range(X_selected.shape[1])]
            return X_selected
        else:
            self.feature_names = [f"feature_{i}" for i in range(X.shape[1])]
            return X
    
    def get_feature_importance(self):
        """Get feature importance scores"""
        if self.feature_selector:
            return dict(zip(self.feature_names, self.feature_selector.scores_))
        return {}
