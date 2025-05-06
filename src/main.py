from permission_analyzer import PermissionAnalyzer
from ml_model import PrivacyRiskClassifier
import streamlit as st

def main():
    st.title("AI-Based Privacy Leak Detector")
    
    uploaded_file = st.file_uploader("Upload APK file", type=['apk'])
    
    if uploaded_file:
        analyzer = PermissionAnalyzer()
        classifier = PrivacyRiskClassifier()
        
        # Analyze permissions
        analysis_result = analyzer.analyze_apk(uploaded_file)
        
        # Display results
        st.header("Analysis Results")
        st.subheader("Permission Analysis")
        st.write(f"Total Permissions: {analysis_result['total_permissions']}")
        st.write(f"Dangerous Permissions: {analysis_result['dangerous_permissions']}")
        
        # Display risk assessment
        st.subheader("Risk Assessment")
        risk_features = [
            analysis_result['total_permissions'],
            analysis_result['dangerous_permissions'],
            0.5,  # placeholder for network usage
            0.5,  # placeholder for storage access
            0.5   # placeholder for location access
        ]
        
        risk_assessment = classifier.predict_risk(risk_features)
        
        st.write(f"Risk Level: {risk_assessment['risk_level']}")
        st.write(f"Risk Score: {risk_assessment['risk_score']:.2f}")
        
        # Display recommendations
        st.subheader("Recommendations")
        for rec in risk_assessment['recommendations']:
            st.write(f"- {rec}")

if __name__ == "__main__":
    main()