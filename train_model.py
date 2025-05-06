from models.ml_risk_predictor import MLRiskPredictor
import numpy as np

# Create sample training data
def generate_training_data():
    # Generate synthetic data for training
    n_samples = 1000
    np.random.seed(42)
    
    # Create MLRiskPredictor instance to get feature order
    model = MLRiskPredictor()
    
    # Generate feature data using the correct order
    features = {}
    for feature in model.feature_columns:
        if 'permission_count' in feature:
            features[feature] = np.random.randint(0, 5, n_samples)
        elif feature == 'total_permission_count':
            features[feature] = np.random.randint(5, 20, n_samples)
        elif feature == 'dangerous_permission_ratio':
            features[feature] = np.random.uniform(0, 1, n_samples)
        elif '_score' in feature or '_risk' in feature:
            features[feature] = np.random.uniform(0, 1, n_samples)
        else:
            features[feature] = np.random.randint(0, 5, n_samples)
    
    # Convert features to numpy array in the correct order
    feature_matrix = np.array([features[col] for col in model.feature_columns]).T
    
    # Generate labels (0: safe, 1: risky) based on weighted average
    weights = {
        'dangerous_permission_count': 2.0,
        'suspicious_url_count': 1.5,
        'data_leak_risk': 2.0,
        'privacy_impact_score': 1.5,
        'security_score': 1.5
    }
    
    weighted_scores = np.zeros(n_samples)
    for i, col in enumerate(model.feature_columns):
        weight = weights.get(col, 1.0)
        weighted_scores += feature_matrix[:, i] * weight
    
    # Normalize scores (optional but good practice)
    # weighted_scores /= sum(weights.values()) # You can keep or remove this normalization
    
    # --- CHANGE THIS LINE --- 
    # Use the median score as the threshold instead of a fixed 0.5
    threshold = np.median(weighted_scores)
    labels = np.where(weighted_scores > threshold, 1, 0)
    # --- END OF CHANGE --- 
    
    return feature_matrix, labels

def main():
    # Create and train the model
    model = MLRiskPredictor()
    
    # Generate training data
    X_train, y_train = generate_training_data()
    
    # --- ADD THIS CHECK --- 
    unique_labels, counts = np.unique(y_train, return_counts=True)
    print(f"Generated labels distribution: {dict(zip(unique_labels, counts))}")
    # --- END OF CHECK --- 
    
    # Train the model
    model.train(X_train, y_train)
    
    # Save the trained model
    model.save_model('trained_model.joblib')
    print("Model trained and saved successfully!")

if __name__ == "__main__":
    main()