from sklearn.ensemble import RandomForestClassifier
import joblib
import numpy as np

class RiskClassifier:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=100)
        self.feature_names = [
            # Existing features
            'dangerous_permission_count',
            'total_permission_count',
            'dangerous_permission_ratio',
            'location_permission_count',
            'storage_permission_count',
            'camera_mic_permission_count',
            'phone_permission_count',
            'contacts_permission_count',
            # New features
            'network_permission_count',
            'suspicious_url_count',
            'data_collection_api_count',
            'file_access_api_count',
            'network_api_count'
        ]
    
    def train(self, X, y):
        self.model.fit(X, y)
        
    def save_model(self, path='model.joblib'):
        joblib.dump(self.model, path)
        
    def load_model(self, path='model.joblib'):
        self.model = joblib.load(path)
        
    def predict_risk(self, features):
        X = self._prepare_features(features)
        
        # Enhanced heuristic approach
        dangerous_ratio = features['dangerous_permission_ratio']
        location_count = features['location_permission_count']
        camera_mic_count = features['camera_mic_permission_count']
        network_score = features.get('network_permission_count', 0) * 0.1
        suspicious_urls = features.get('suspicious_url_count', 0) * 0.15
        
        # Calculate comprehensive risk score
        risk_score = (
            dangerous_ratio * 0.3 +
            (location_count > 0) * 0.15 +
            (camera_mic_count > 0) * 0.15 +
            network_score +
            suspicious_urls
        )
        
        # Generate detailed recommendations
        recommendations = []
        if dangerous_ratio > 0.5:
            recommendations.append("High number of dangerous permissions detected")
        if location_count > 0:
            recommendations.append("App requests location access")
        if camera_mic_count > 0:
            recommendations.append("App requests camera/microphone access")
        if features.get('suspicious_url_count', 0) > 0:
            recommendations.append(f"Found {features['suspicious_url_count']} suspicious URLs")
        
        return {
            'risk_score': min(risk_score, 1.0),
            'risk_level': 'High' if risk_score > 0.7 else 'Medium' if risk_score > 0.4 else 'Low',
            'confidence': 0.85,
            'recommendations': recommendations
        }
    
    def _prepare_features(self, features):
        # Ensure features are in the correct order based on feature_names
        X = [features[name] for name in self.feature_names]
        return X