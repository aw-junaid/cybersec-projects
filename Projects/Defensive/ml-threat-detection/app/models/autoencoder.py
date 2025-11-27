import tensorflow as tf
from tensorflow.keras.models import Model, Sequential
from tensorflow.keras.layers import Dense, Input, Dropout, BatchNormalization
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
import numpy as np
import logging
from sklearn.metrics import mean_squared_error
import joblib

logger = logging.getLogger(__name__)

class AutoencoderDetector:
    """Autoencoder for anomaly detection"""
    
    def __init__(self, encoding_dim=32, hidden_layers=[64, 32], dropout_rate=0.2, learning_rate=0.001):
        self.encoding_dim = encoding_dim
        self.hidden_layers = hidden_layers
        self.dropout_rate = dropout_rate
        self.learning_rate = learning_rate
        self.model = None
        self.encoder = None
        self.is_trained = False
        self.reconstruction_threshold = None
        self.feature_names = []
        
    def build_model(self, input_dim):
        """Build the autoencoder model"""
        logger.info(f"Building autoencoder with input dimension: {input_dim}")
        
        # Input layer
        input_layer = Input(shape=(input_dim,))
        
        # Encoder
        encoded = input_layer
        for units in self.hidden_layers:
            encoded = Dense(units, activation='relu')(encoded)
            encoded = BatchNormalization()(encoded)
            encoded = Dropout(self.dropout_rate)(encoded)
        
        # Bottleneck
        encoded = Dense(self.encoding_dim, activation='relu')(encoded)
        
        # Decoder
        decoded = encoded
        for units in reversed(self.hidden_layers):
            decoded = Dense(units, activation='relu')(decoded)
            decoded = BatchNormalization()(decoded)
            decoded = Dropout(self.dropout_rate)(decoded)
        
        # Output layer
        output_layer = Dense(input_dim, activation='sigmoid')(decoded)
        
        # Create models
        self.model = Model(input_layer, output_layer)
        self.encoder = Model(input_layer, encoded)
        
        # Compile model
        self.model.compile(
            optimizer=Adam(learning_rate=self.learning_rate),
            loss='mse',
            metrics=['mae']
        )
        
        logger.info("Autoencoder model built successfully")
    
    def train(self, X, validation_data=None, epochs=100, batch_size=32, patience=10):
        """Train the autoencoder"""
        if self.model is None:
            self.build_model(X.shape[1])
        
        logger.info("Training autoencoder...")
        
        # Callbacks
        callbacks = [
            EarlyStopping(monitor='val_loss', patience=patience, restore_best_weights=True),
            ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=5, min_lr=1e-7)
        ]
        
        # Train model
        if validation_data is not None:
            history = self.model.fit(
                X, X,
                epochs=epochs,
                batch_size=batch_size,
                validation_data=(validation_data, validation_data),
                callbacks=callbacks,
                verbose=1,
                shuffle=True
            )
        else:
            history = self.model.fit(
                X, X,
                epochs=epochs,
                batch_size=batch_size,
                validation_split=0.2,
                callbacks=callbacks,
                verbose=1,
                shuffle=True
            )
        
        # Set reconstruction threshold (95th percentile of training reconstruction errors)
        train_reconstructions = self.model.predict(X)
        train_errors = np.mean(np.square(X - train_reconstructions), axis=1)
        self.reconstruction_threshold = np.percentile(train_errors, 95)
        
        self.is_trained = True
        logger.info(f"Autoencoder training completed. Reconstruction threshold: {self.reconstruction_threshold:.4f}")
        
        return history
    
    def predict(self, X):
        """Predict anomalies based on reconstruction error"""
        if not self.is_trained:
            raise ValueError("Model must be trained before prediction")
        
        reconstructions = self.model.predict(X)
        errors = np.mean(np.square(X - reconstructions), axis=1)
        
        # -1 for anomalies, 1 for normal
        predictions = np.where(errors > self.reconstruction_threshold, -1, 1)
        
        return predictions
    
    def predict_proba(self, X):
        """Predict anomaly scores based on reconstruction error"""
        if not self.is_trained:
            raise ValueError("Model must be trained before prediction")
        
        reconstructions = self.model.predict(X)
        errors = np.mean(np.square(X - reconstructions), axis=1)
        
        # Normalize errors to probability-like scores (0-1)
        max_error = np.max(errors) if np.max(errors) > 0 else 1
        scores = errors / max_error
        
        return scores
    
    def get_reconstruction_errors(self, X):
        """Get reconstruction errors for each sample"""
        if not self.is_trained:
            raise ValueError("Model must be trained before getting errors")
        
        reconstructions = self.model.predict(X)
        errors = np.mean(np.square(X - reconstructions), axis=1)
        
        return errors
    
    def get_latent_representations(self, X):
        """Get latent space representations"""
        if not self.is_trained:
            raise ValueError("Model must be trained before getting latent representations")
        
        return self.encoder.predict(X)
    
    def evaluate(self, X, y_true):
        """Evaluate model performance"""
        if not self.is_trained:
            raise ValueError("Model must be trained before evaluation")
        
        y_pred = self.predict(X)
        
        # Convert to binary (1 for normal, 0 for anomaly)
        y_pred_binary = (y_pred == 1).astype(int)
        y_true_binary = (y_true == 1).astype(int)
        
        from sklearn.metrics import precision_score, recall_score, f1_score
        
        precision = precision_score(y_true_binary, y_pred_binary)
        recall = recall_score(y_true_binary, y_pred_binary)
        f1 = f1_score(y_true_binary, y_pred_binary)
        
        metrics = {
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'reconstruction_threshold': self.reconstruction_threshold
        }
        
        return metrics
    
    def save_model(self, filepath):
        """Save trained model to file"""
        if not self.is_trained:
            raise ValueError("Model must be trained before saving")
        
        model_data = {
            'model_config': self.model.get_config(),
            'model_weights': self.model.get_weights(),
            'encoder_config': self.encoder.get_config(),
            'encoder_weights': self.encoder.get_weights(),
            'reconstruction_threshold': self.reconstruction_threshold,
            'feature_names': self.feature_names,
            'is_trained': self.is_trained
        }
        
        joblib.dump(model_data, filepath)
        logger.info(f"Autoencoder model saved to {filepath}")
    
    def load_model(self, filepath):
        """Load model from file"""
        model_data = joblib.load(filepath)
        
        # Rebuild model from config
        self.model = Model.from_config(model_data['model_config'])
        self.model.set_weights(model_data['model_weights'])
        
        self.encoder = Model.from_config(model_data['encoder_config'])
        self.encoder.set_weights(model_data['encoder_weights'])
        
        self.reconstruction_threshold = model_data['reconstruction_threshold']
        self.feature_names = model_data['feature_names']
        self.is_trained = model_data['is_trained']
        
        # Recompile model
        self.model.compile(
            optimizer=Adam(learning_rate=self.learning_rate),
            loss='mse',
            metrics=['mae']
        )
        
        logger.info(f"Autoencoder model loaded from {filepath}")
