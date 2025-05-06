from sklearn.ensemble import RandomForestClassifier
import numpy as np

class PrivacyRiskClassifier:
    def __init__(self):
        self.model = RandomForestClassifier()
        self.feature_columns = [
            'permission_count',
            'dangerous_permission_count',
            'network_usage',
            'storage_access',
            'location_access'
        ]
    
    def train(self, X, y):
        self.model.fit(X, y)
    
    def predict_risk(self, features):
        features = np.array(features).reshape(1, -1)
        risk_score = self.model.predict_proba(features)[0][1]
        return {
            'risk_score': risk_score,
            'risk_level': self._get_risk_level(risk_score),
            'recommendations': self._generate_recommendations(features)
        }
    
    def _get_risk_level(self, score):
        if score < 0.3:
            return 'LOW'
        elif score < 0.7:
            return 'MEDIUM'
        return 'HIGH'
    
    def _generate_recommendations(self, features):
        recommendations = []
        if features[0][1] > 5:  # dangerous permission count
            recommendations.append("Reduce number of dangerous permissions")
        if features[0][3] > 0.8:  # storage access
            recommendations.append("Limit storage access patterns")
        return recommendations