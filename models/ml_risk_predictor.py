from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import numpy as np
import joblib

class MLRiskPredictor:
    def __init__(self):
        # Initialize multiple models for ensemble
        self.rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.rf_model_permissions = RandomForestClassifier(n_estimators=50, random_state=42)
        self.rf_model_network = RandomForestClassifier(n_estimators=50, random_state=42)
        
        self.scaler = StandardScaler()
        self.is_fitted = False  # Add a flag to track if scaler is fitted
        self.feature_importance = {}
        
        # Enhanced feature columns
        self.feature_columns = [
            # Core features
            'dangerous_permission_count',
            'network_permission_count',
            'storage_permission_count',
            'location_permission_count',
            'camera_mic_permission_count',
            'contacts_permission_count',
            'phone_permission_count',
            'total_permission_count',
            'dangerous_permission_ratio',
            'suspicious_url_count',
            'tracker_count',
            'suspicious_api_count',
            'policy_compliance_score',
            # Advanced features
            'data_leak_risk',
            'privacy_impact_score',
            'security_score'
        ]
    
    def train(self, X, y):
        """Train multiple models for different aspects of risk"""
        # Ensure y has both classes for robust training
        if len(np.unique(y)) < 2:
            print("Warning: Training data contains only one class. Model performance may be limited.")
            # Depending on requirements, you might raise an error or proceed cautiously

        # Fit and transform the data
        X_scaled = self.scaler.fit_transform(X)
        self.is_fitted = True  # Set the flag after fitting
        
        # Train main model
        self.rf_model.fit(X_scaled, y)
        
        # Calculate feature importance
        self.feature_importance = dict(zip(
            self.feature_columns,
            self.rf_model.feature_importances_
        ))
        
        # Train specialized models only if data subset has both classes
        perm_features = [col for col in self.feature_columns if 'permission' in col]
        network_features = [col for col in self.feature_columns if any(x in col for x in ['network', 'url', 'tracker'])]
        
        if perm_features:
            perm_indices = [self.feature_columns.index(f) for f in perm_features]
            # --- ADD CHECK HERE --- 
            if len(np.unique(y)) > 1: # Check if the original y has both classes
                self.rf_model_permissions.fit(X_scaled[:, perm_indices], y)
            else:
                print("Skipping permission model training: Only one class present in training data.")
            
        if network_features:
            net_indices = [self.feature_columns.index(f) for f in network_features]
            # --- ADD CHECK HERE --- 
            if len(np.unique(y)) > 1: # Check if the original y has both classes
                self.rf_model_network.fit(X_scaled[:, net_indices], y)
            else:
                print("Skipping network model training: Only one class present in training data.")
        
        return self  # Move return statement to the end
        
    def predict_risk(self, features):
        """Enhanced risk prediction with specialized models"""
        # Check if the model (and scaler) is fitted
        if not self.is_fitted:
            return {
                'risk_score': 0.5,  # Default neutral score
                'risk_level': 'Unknown',
                'confidence': 0.0,
                'risk_factors': ['Model not trained or loaded correctly. Please train the model first.'],
                'feature_importance': []
            }
    
        # Prepare features
        feature_vector = self._prepare_features(features)
        
        # Scaler is checked implicitly by is_fitted flag now
        X_scaled = self.scaler.transform([feature_vector])
        
        # Get predictions from all models
        main_pred = self.rf_model.predict_proba(X_scaled)[0][1]
        
        # Get specialized predictions if available
        perm_pred = self._get_permission_risk(X_scaled)
        network_pred = self._get_network_risk(X_scaled)
        
        # Weighted ensemble prediction
        risk_score = (main_pred * 0.5 + 
                     perm_pred * 0.3 + 
                     network_pred * 0.2)
        
        # Generate detailed analysis
        risk_factors = self._analyze_risk_factors(features)
        confidence = self._calculate_confidence(features)
        
        return {
            'risk_score': risk_score,
            'risk_level': self._get_risk_level(risk_score),
            'confidence': confidence,
            'risk_factors': risk_factors,
            'feature_importance': self._get_top_features(features)
        }
    
    def _get_permission_risk(self, X_scaled):
        """Get risk score from permission-specific model"""
        if not hasattr(self.rf_model_permissions, 'classes_'):
            return 0.5  # Default neutral score if model not trained
    
        perm_features = [col for col in self.feature_columns if 'permission' in col]
        if perm_features:
            perm_indices = [self.feature_columns.index(f) for f in perm_features]
            try:
                proba = self.rf_model_permissions.predict_proba(X_scaled[:, perm_indices])
                # --- ADD CHECK FOR PROBA SHAPE --- 
                if proba.shape[1] == 2:
                    return proba[0][1] # Return probability of class 1
                else:
                    # If only one class probability is returned, infer based on the class label
                    # Assuming class 0 is safe, class 1 is risky
                    if self.rf_model_permissions.classes_[0] == 1: # If the only class is 'risky'
                        return proba[0][0] # Return the probability of the risky class
                    else: # If the only class is 'safe'
                        return 0.0 # Probability of risky class is 0
            except Exception as e:
                print(f"Error in permission risk prediction: {e}")
                return 0.5 # Default on error
        return 0.5
    
    def _get_network_risk(self, X_scaled):
        """Get risk score from network-specific model"""
        if not hasattr(self.rf_model_network, 'classes_'):
            return 0.5  # Default neutral score if model not trained
    
        network_features = [col for col in self.feature_columns if any(x in col for x in ['network', 'url', 'tracker'])]
        if network_features:
            net_indices = [self.feature_columns.index(f) for f in network_features]
            try:
                proba = self.rf_model_network.predict_proba(X_scaled[:, net_indices])
                # --- ADD CHECK FOR PROBA SHAPE --- 
                if proba.shape[1] == 2:
                    return proba[0][1] # Return probability of class 1
                else:
                    # If only one class probability is returned, infer based on the class label
                    if self.rf_model_network.classes_[0] == 1: # If the only class is 'risky'
                        return proba[0][0] # Return the probability of the risky class
                    else: # If the only class is 'safe'
                        return 0.0 # Probability of risky class is 0
            except Exception as e:
                print(f"Error in network risk prediction: {e}")
                return 0.5 # Default on error
        return 0.5
    
    def _get_risk_level(self, score):
        """Determine risk level based on score"""
        if score > 0.7:
            return 'High'
        elif score > 0.4:
            return 'Medium'
        return 'Low'
    
    def _calculate_confidence(self, features):
        """Calculate confidence score based on available data"""
        available_features = sum(1 for f in features if features.get(f, 0) != 0)
        confidence = 0.5 + (available_features / len(self.feature_columns)) * 0.5
        return min(confidence, 0.95)
    
    def _get_top_features(self, features):
        """Get top contributing features to risk score"""
        feature_impacts = []
        for feature, importance in self.feature_importance.items():
            if feature in features:
                feature_impacts.append({
                    'feature': feature,
                    'importance': importance,
                    'value': features[feature]
                })
        return sorted(feature_impacts, key=lambda x: x['importance'], reverse=True)[:5]
    
    def _prepare_features(self, features):
        """Prepare feature vector ensuring all required features are present"""
        return [features.get(col, 0) for col in self.feature_columns]
    
    # --- REMOVE THIS ENTIRE METHOD --- 
    def save_model(self, path='ml_model.joblib'):
        """Save all models and scalers"""
        joblib.dump({
            'main_model': self.rf_model,
            'permission_model': self.rf_model_permissions,
            'network_model': self.rf_model_network,
            'scaler': self.scaler,
            'feature_importance': self.feature_importance
        }, path)
    # --- END OF METHOD TO REMOVE --- 
    
    # Correct the default path in load_model
    def load_model(self, path='trained_model.joblib'): # <-- CHANGE THIS LINE
        """Load all models and scalers"""
        try:
            data = joblib.load(path)
            self.rf_model = data['main_model']
            self.rf_model_permissions = data['permission_model']
            self.rf_model_network = data['network_model']
            self.scaler = data['scaler']
            self.feature_importance = data['feature_importance']
            self.is_fitted = True  # Set the flag to True when loading a trained model
            print(f"Model loaded successfully from {path}") # Add print statement
        except FileNotFoundError:
            print(f"Error: Model file not found at {path}. Please train the model first.")
            self.is_fitted = False # Ensure flag is false if loading fails
        except Exception as e:
            print(f"Error loading model from {path}: {e}")
            self.is_fitted = False # Ensure flag is false if loading fails

    # REMOVE THE PREVIOUS save_model definition that was here
    
    # KEEP THIS CORRECT save_model definition
    def save_model(self, path='trained_model.joblib'): # Ensure this default path is correct
        """Save all models and scalers"""
        joblib.dump({
            'main_model': self.rf_model,
            'permission_model': self.rf_model_permissions,
            'network_model': self.rf_model_network,
            'scaler': self.scaler,
            'feature_importance': self.feature_importance
            # Ensure is_fitted doesn't need explicit saving; it's inferred from loading scaler/models
        }, path)
        print(f"Model saved successfully to {path}") # Add print statement

    def _analyze_risk_factors(self, features):
        """Analyze features to determine specific risk factors"""
        risk_factors = []
        
        # Permission-related risks (Lowered threshold)
        if features.get('dangerous_permission_count', 0) > 3: # Lowered from 5
            risk_factors.append(f"High number of dangerous permissions ({features['dangerous_permission_count']})")
        if features.get('dangerous_permission_ratio', 0) > 0.4: # Lowered from 0.5
            risk_factors.append("High ratio (>40%) of permissions are dangerous")
            
        # Network-related risks
        if features.get('suspicious_url_count', 0) > 0:
            risk_factors.append(f"Found {features['suspicious_url_count']} suspicious URLs/Hosts (Trackers, Malicious, etc.)")
        if features.get('tracker_count', 0) > 0:
            risk_factors.append(f"Detected {features['tracker_count']} tracking components")
        # --- ADDED: Check for insecure HTTP URLs --- 
        if features.get('insecure_http_url_count', 0) > 0:
            risk_factors.append(f"Uses {features['insecure_http_url_count']} insecure HTTP URLs (potential for data interception)")
            
        # Code-related risks
        if features.get('suspicious_api_count', 0) > 0:
            risk_factors.append(f"Found {features['suspicious_api_count']} suspicious API calls")
            
        # Privacy policy check (remains conditional)
        if features.get('policy_text_provided', False):
            if features.get('policy_compliance_score', 1.0) < 0.5: 
                risk_factors.append("Privacy policy may not fully cover app's data practices")
            
        # Data leak risks (Lowered threshold)
        if features.get('data_leak_risk', 0) > 0.4: # Lowered from 0.5
            risk_factors.append("Potential risk of data leaks detected")
        if features.get('privacy_impact_score', 0) > 0.6: # Lowered from 0.7
            risk_factors.append("Moderate-to-Significant privacy impact detected")
            
        # General security score check (Lowered threshold)
        if not risk_factors and features.get('security_score', 1.0) < 0.7: # Lowered from 0.6
            risk_factors.append("Multiple minor security concerns detected or low overall security score")
            
        # If no risk factors identified
        if not risk_factors:
            risk_factors.append("No major risk factors identified based on current thresholds")
            
        return risk_factors