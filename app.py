import streamlit as st
from models.permission_analyzer import PermissionAnalyzer
from models.network_analyzer import NetworkAnalyzer
from models.code_analyzer import CodeAnalyzer
from models.policy_analyzer import PrivacyPolicyAnalyzer
from models.ml_risk_predictor import MLRiskPredictor
import plotly.express as px
# Add to imports
from models.security_analyzer import SecurityAnalyzer
import plotly.graph_objects as go
import pandas as pd
import os # Added for file path handling
from flask import Flask, request, jsonify # Added Flask imports
from werkzeug.utils import secure_filename # Added for secure file handling
from models.monitor_analyzer import PrivacyMonitor, AlertHandler

# --- Add this import --- 
from androguard.misc import AnalyzeAPK

# In your app initialization
ml_predictor = MLRiskPredictor()
try:
    print("Attempting to load model...") # Add print statement
    ml_predictor.load_model('trained_model.joblib')
    if not hasattr(ml_predictor.rf_model, 'classes_'):
        st.error("Model not properly trained. Running training script...")
        import subprocess
        subprocess.run(['python', 'train_model.py'])
        ml_predictor.load_model('trained_model.joblib')
    print("Model loaded successfully!")
except Exception as e:
    st.error(f"Error loading model: {str(e)}. Running training script...")
    import subprocess
    subprocess.run(['python', 'train_model.py'])
    try:
        ml_predictor.load_model('trained_model.joblib')
        print("Model trained and loaded successfully!")
    except Exception as e:
        st.error(f"Failed to train and load model: {str(e)}")
    if not ml_predictor.is_fitted:
        st.warning("Model loaded but might be invalid. Please retrain using 'python train_model.py'.")
except Exception as e:
    # The load_model method now handles printing specific errors
    st.error("Failed to load the prediction model. Please ensure 'trained_model.joblib' exists and is valid. Run 'python train_model.py' to create/update it.")
    # Optionally print the exception e if needed for debugging

# --- Refactored Analysis Function --- 
def perform_full_analysis(apk_path, policy_text=None):
    """Performs all analyses on the given APK path and optional policy text."""
    a = None # Define 'a' outside try block for cleanup
    d = None # Define 'd' outside try block
    dx = None # Define 'dx' outside try block
    try:
        # Initialize APK analysis FIRST
        # Now AnalyzeAPK is recognized
        a, d, dx = AnalyzeAPK(apk_path)
        if not a or not d or not dx:
            raise Exception("Failed to analyze APK.")

        # Initialize analyzers, passing the 'a' object to PermissionAnalyzer
        analyzers = {
            'permission': PermissionAnalyzer(a),
            'network': NetworkAnalyzer(),
            'code': CodeAnalyzer(),
            'policy': PrivacyPolicyAnalyzer(),
            'security': SecurityAnalyzer()
        }
        
        # Use the global ml_predictor instead of creating a new instance
        analyzers['ml'] = ml_predictor
        
        # Get permissions and features using the analyzer instance
        permissions = analyzers['permission'].get_permissions() # Uses self.apk
        features = analyzers['permission'].extract_features() # Now takes no arguments
        manifest_xml = a.get_android_manifest_xml()

        # Network analyzer needs the permissions list and APK path
        network_permissions = analyzers['network'].analyze_network_permissions(permissions)
        network_urls = analyzers['network'].analyze_network_urls(apk_path)
        network_data = {**network_permissions, **network_urls}

        # Pass 'dx' to code analyzer methods
        code_patterns = analyzers['code'].analyze_code_patterns(dx)
        detected_trackers = analyzers['code'].detect_trackers(dx)
        suspicious_api_count = sum(len(v) for k, v in code_patterns.items() if k in analyzers['code'].suspicious_apis)

        compliance_report = None
        policy_compliance_score = 0.0
        if policy_text:
            policy_analysis = analyzers['policy'].analyze_policy(policy_text, permissions)
            compliance_report = analyzers['policy'].generate_compliance_report(policy_analysis)
            total_categories = len(compliance_report['compliant_categories']) + len(compliance_report['non_compliant_categories'])
            if total_categories > 0:
                policy_compliance_score = len(compliance_report['compliant_categories']) / total_categories

        # --- MODIFICATION START ---
        # Calculate insecure http url count
        insecure_http_url_count = len(network_data.get('insecure_http_urls', []))

        all_features = {
            **features, 
            **network_data, # Keep this for other network details if needed elsewhere
            'policy_compliance_score': policy_compliance_score,
            'tracker_count': len(detected_trackers),
            'suspicious_api_count': suspicious_api_count, # Corrected this line from previous snippet
            # 'insecure_http_urls': network_data.get('insecure_http_urls', []), # Keep if needed for technical details, but count is separate
            'insecure_http_url_count': insecure_http_url_count, # <-- ADD THIS LINE
            'malicious_domains': network_data.get('malicious_domains', []), 
            'malicious_ips': network_data.get('malicious_ips', []),
            'policy_text_provided': bool(policy_text)
        }
        # --- MODIFICATION END ---

        # --- ADD THIS CHECK --- 
        # Explicitly check if the global predictor is fitted before prediction
        if not analyzers['ml'].is_fitted:
            risk_prediction = {
                'risk_score': 0.5,
                'risk_level': 'Unknown',
                'risk_factors': ['Model is not ready. Please ensure training completed and restart the app.'],
                'confidence': 0.0,
                'feature_importance': []
            }
        else:
            # Modify the risk prediction part to handle untrained model
            try:
                risk_prediction = analyzers['ml'].predict_risk(all_features) # Pass the updated all_features
            except Exception as e:
                risk_prediction = {
                    'risk_score': 0.5,
                    'risk_level': 'Unknown',
                    'risk_factors': [f'Error during prediction: {str(e)}. Please train the model first.'],
                    'confidence': 0.0,
                    'feature_importance': []
                }
        
        # Pass 'code_patterns' (now with vulnerabilities) to security score calculation
        security_analysis = analyzers['security'].calculate_security_score(
            permissions,
            network_data,
            code_patterns, # Pass the enhanced code_patterns
            manifest_xml, 
            policy_score=all_features.get('policy_compliance_score'),
            tracker_count=all_features.get('tracker_count')
        )

        # Combine results into a single dictionary
        results = {
            'risk_prediction': risk_prediction,
            'security_analysis': security_analysis,
            'compliance_report': compliance_report,
            'policy_compliance_score': policy_compliance_score,
            'technical_details': {
                'permissions': permissions,
                'features': features,
                'network_data': network_data,
                'code_patterns': code_patterns, # This now includes vulnerabilities
                'detected_trackers': detected_trackers
            }
        }
        return results

    except Exception as e:
        # Handle potential errors during analysis
        return {'error': f"Analysis failed: {str(e)}"}
    finally:
        # Cleanup
        if a and hasattr(a, 'finish'):
             try:
                 a.finish()
             except Exception as e:
                 print(f"Error during Androguard session cleanup: {e}")
        elif os.path.exists(apk_path) and apk_path.startswith("temp_"):
             try:
                 os.remove(apk_path)
             except OSError as e:
                 print(f"Error removing temporary file {apk_path}: {e}") 

# --- Helper function for Gauge Chart --- 
def create_gauge_chart(gauge_data):
    """Creates a Plotly gauge chart."""
    fig = go.Figure(go.Indicator(
        mode = "gauge+number",
        value = gauge_data['value'] * 100, # Convert score to percentage
        domain = {'x': [0, 1], 'y': [0, 1]},
        title = {'text': gauge_data['label'], 'font': {'size': 20}},
        gauge = {
            'axis': {'range': [gauge_data['min'] * 100, gauge_data['max'] * 100], 'tickwidth': 1, 'tickcolor': "darkblue"},
            'bar': {'color': "darkblue"},
            'bgcolor': "white",
            'borderwidth': 2,
            'bordercolor': "gray",
            'steps': [
                {'range': [0, 40], 'color': 'green'},
                {'range': [40, 70], 'color': 'orange'},
                {'range': [70, 100], 'color': 'red'}],
            'threshold': {
                'line': {'color': "black", 'width': 4},
                'thickness': 0.75,
                'value': gauge_data['value'] * 100
            }
        }
    ))
    fig.update_layout(height=250, margin={'t':0, 'b':0, 'l':0, 'r':0})
    return fig

# --- Helper function for Recommendations --- 
def generate_recommendations(risk_prediction, security_analysis, compliance_report, tech_details):
    """Generates actionable recommendations based on analysis results."""
    recommendations = []
    risk_score = risk_prediction.get('risk_score', 0.5)
    risk_level = risk_prediction.get('risk_level', 'Unknown')
    security_score = security_analysis.get('overall_score', 0.5)

    # General Risk Level
    if risk_level == 'High' or risk_level == 'Critical':
        recommendations.append(f"**High/Critical Risk ({risk_score:.2f}):** Prioritize addressing identified risk factors immediately. Focus on reducing dangerous permissions, securing network connections, and removing trackers.")
    elif risk_level == 'Medium':
        recommendations.append(f"**Medium Risk ({risk_score:.2f}):** Review permissions, network activity, and code patterns. Consider reducing unnecessary data access and improving security practices.")
    else:
        recommendations.append(f"**Low Risk ({risk_score:.2f}):** Maintain good practices. Regularly review permissions and dependencies.")

    # Security Score
    if security_score < 0.5:
        recommendations.append(f"**Low Security Score ({security_score:.2f}):** Significant security improvements needed. Address manifest issues, insecure code patterns, and network vulnerabilities identified in the Security Analysis tab.")
    elif security_score < 0.8:
        recommendations.append(f"**Moderate Security Score ({security_score:.2f}):** Review component scores in the Security Analysis tab for specific areas needing improvement (e.g., permissions, network, code).")

    # Specific Technical Details
    if tech_details['network_data'].get('insecure_http_urls'):
        recommendations.append("**Network Security:** Migrate all network communication to HTTPS to prevent data interception.")
    if tech_details['network_data'].get('malicious_domains') or tech_details['network_data'].get('malicious_ips'):
        recommendations.append("**Network Security:** Remove connections to known malicious domains/IPs immediately.")
    if tech_details['detected_trackers']:
        recommendations.append(f"**Trackers:** Review the {len(tech_details['detected_trackers'])} detected trackers. Consider removing non-essential ones to enhance user privacy.")
    
    # Manifest Issues from Security Analysis
    if security_analysis.get('manifest_issues'):
        high_severity_issues = [i['description'] for i in security_analysis['manifest_issues'] if i.get('severity') in ['HIGH', 'CRITICAL']]
        if high_severity_issues:
            recommendations.append(f"**Manifest Security:** Critical issues found in AndroidManifest.xml need immediate attention: {'; '.join(high_severity_issues)}")

    # Policy Compliance
    if compliance_report and compliance_report['non_compliant_categories']:
        recommendations.append("**Privacy Policy:** Address non-compliant categories identified in the policy analysis. Ensure the policy accurately reflects data practices.")
    if compliance_report and compliance_report['recommendations']:
        recommendations.extend([f"**Policy Suggestion:** {rec}" for rec in compliance_report['recommendations']])

    if not recommendations:
        recommendations.append("No specific high-priority recommendations based on current analysis. Maintain vigilance.")

    return recommendations

# --- Flask API Endpoint --- 
flask_app = Flask(__name__)
UPLOAD_FOLDER = '.' # Save uploads in the current directory
flask_app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@flask_app.route('/analyze', methods=['POST'])
def analyze_apk_api():
    if 'apk_file' not in request.files:
        return jsonify({'error': 'No apk_file part in the request'}), 400
    
    file = request.files['apk_file']
    policy = request.form.get('privacy_policy', None) # Optional policy text

    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file and file.filename.endswith('.apk'):
        filename = secure_filename("temp_api_upload.apk") # Use a fixed temp name for API uploads
        apk_save_path = os.path.join(flask_app.config['UPLOAD_FOLDER'], filename)
        try:
            file.save(apk_save_path)
            
            # Perform the analysis using the refactored function
            analysis_results = perform_full_analysis(apk_save_path, policy)
            
            if 'error' in analysis_results:
                 return jsonify(analysis_results), 500 # Internal server error if analysis fails
            else:
                 return jsonify(analysis_results), 200

        except Exception as e:
            # Clean up if saving or analysis fails mid-way
            if os.path.exists(apk_save_path):
                os.remove(apk_save_path)
            return jsonify({'error': f'Error processing file: {str(e)}'}), 500
    else:
        return jsonify({'error': 'Invalid file type, only .apk allowed'}), 400

# --- Streamlit UI Code --- 

# <<< KEEP THIS >>> (Ensure it's the FIRST Streamlit command after imports)
st.set_page_config(page_title="Advanced Privacy Leak Detector", layout="wide")

# <<< KEEP THIS >>>
st.title("📱 Android App Privacy Analyzer")

# <<< KEEP THIS >>> (File upload section)
col1, col2 = st.columns(2)
with col1:
    # Use variable names 'uploaded_apk' and 'privacy_policy'
    uploaded_apk = st.file_uploader("Upload Android APK", type=['apk'])
with col2:
    privacy_policy = st.text_area("Paste Privacy Policy Text", height=150)

# <<< REMOVE THE DUPLICATE SECTION THAT WAS HERE >>>
# (Remove lines corresponding to the old lines ~197 to ~214 which had 
# comments, another set_page_config, title, and file_uploader)

# <<< MODIFY THIS PART >>> 
# Display analysis results (triggered by UI upload)
# Use the variables from the uploader above: 'uploaded_apk' and 'privacy_policy'
if uploaded_apk is not None:
    with st.spinner('Analyzing application...'):
        # Save the uploaded file temporarily for analysis
        apk_ui_path = "temp_ui_upload.apk"
        with open(apk_ui_path, "wb") as f:
            f.write(uploaded_apk.getbuffer()) # Use uploaded_apk here
        
        # Call the refactored analysis function
        # Use privacy_policy here
        analysis_results = perform_full_analysis(apk_ui_path, privacy_policy) 

        # Cleanup is handled within perform_full_analysis's finally block now
        # if os.path.exists(apk_ui_path):
        #     os.remove(apk_ui_path)

        if 'error' in analysis_results:
            st.error(analysis_results['error'])
        else:
            # --- Display Logic --- 
            # Extract results for display
            risk_prediction = analysis_results['risk_prediction']
            security_analysis = analysis_results['security_analysis']
            compliance_report = analysis_results['compliance_report']
            policy_compliance_score = analysis_results['policy_compliance_score']
            tech_details = analysis_results['technical_details']
            features = tech_details['features']
            network_data = tech_details['network_data']
            code_patterns = tech_details['code_patterns']
            detected_trackers = tech_details['detected_trackers']
            
            # Get analyzers instance for domain info (needed for display)
            # This is a bit awkward, maybe pass analyzers dict or domain info separately?
            # For now, creating a temporary instance just for this.
            temp_network_analyzer = NetworkAnalyzer()

            tabs = st.tabs(["Risk Assessment", "Security Analysis", "Privacy Policy", "Technical Analysis", "Recommendations"])
            
            # --- Risk Assessment Tab --- 
            with tabs[0]:
                st.header("🎯 Risk Assessment")
                # ... (rest of the display code using extracted variables: risk_prediction, security_analysis)
                risk_col1, risk_col2 = st.columns(2)
            
                with risk_col1:
                    risk_gauge = {
                        'value': risk_prediction['risk_score'],
                        'min': 0,
                        'max': 1,
                        'label': 'Privacy Risk Score'
                    }
                    # Now this function call should work
                    st.plotly_chart(create_gauge_chart(risk_gauge))
                
                with risk_col2:
                    st.subheader("Key Risk Factors")
                    if risk_prediction.get('risk_factors'):
                        for factor in risk_prediction['risk_factors']:
                            st.warning(factor)
                    else:
                        st.info("No specific risk factors identified.")
                    
                    # Add security score breakdown here
                    st.subheader("📊 Security Score Breakdown")
                    if security_analysis.get('component_scores'):
                        categories = list(security_analysis['component_scores'].keys())
                        values = list(security_analysis['component_scores'].values())
                        
                        fig = go.Figure(data=go.Scatterpolar(
                            r=values,
                            theta=categories,
                            fill='toself',
                            name='Security Scores'
                        ))
                        
                        fig.update_layout(
                            polar=dict(
                                radialaxis=dict(
                                    visible=True,
                                    range=[0, 1]
                                )),
                            showlegend=False,
                            title='Security Component Scores'
                        )
                        st.plotly_chart(fig)
                    else:
                        st.info("Component scores not available.")

            # --- Security Analysis Tab --- 
            with tabs[1]:
                st.header("🛡️ Security Analysis")
                score = security_analysis.get('overall_score', 0)
                color = 'green' if score > 0.7 else 'orange' if score > 0.4 else 'red'
                st.markdown(f"### Overall Security Score: <span style='color:{color}'>{score:.2f}</span>", unsafe_allow_html=True)

                st.subheader("Component Analysis")
                if security_analysis.get('component_scores'):
                    # Dynamically adjust columns based on number of components
                    num_components = len(security_analysis['component_scores'])
                    cols = st.columns(num_components)
                    component_items = list(security_analysis['component_scores'].items())
                    
                    for i in range(num_components):
                        component, score = component_items[i]
                        with cols[i]:
                            color = 'green' if score > 0.7 else 'orange' if score > 0.4 else 'red'
                            # Calculate delta relative to a baseline (e.g., 0.5 or average)
                            # Simple delta calculation (can be refined)
                            delta_val = (score - 0.5) * 100 # Percentage points from 0.5
                            st.metric(
                                label=component.title(), 
                                value=f"{score:.2f}",
                                delta=f"{delta_val:.1f}% vs Mid" if abs(delta_val) > 1 else None, # Show delta if significant
                                delta_color='normal' # Color based on value itself
                            )
                else:
                    st.info("Component scores not available.")
                
                # *** NEW: Display Manifest Issues ***
                st.subheader("AndroidManifest.xml Issues")
                if security_analysis.get('manifest_issues'):
                    manifest_issues = security_analysis['manifest_issues']
                    if manifest_issues:
                        for issue in manifest_issues:
                            severity = issue.get('severity', 'Info').upper()
                            description = issue.get('description', 'No details.')
                            if severity == 'HIGH' or severity == 'CRITICAL':
                                st.error(f"**[{severity}]** {description}")
                            elif severity == 'MEDIUM':
                                st.warning(f"**[{severity}]** {description}")
                            else:
                                st.info(f"**[{severity}]** {description}")
                    else:
                         st.success("No significant security issues found in the Manifest.")
                else:
                    st.info("Manifest analysis results not available.")

                st.subheader("Permission Impact Analysis")
                if security_analysis.get('risk_breakdown'):
                    for risk in security_analysis['risk_breakdown']:
                        col1, col2 = st.columns([1, 2])
                        with col1:
                            st.metric(
                                label=risk['permission'],
                                value=risk['impact'],
                                delta=None
                            )
                        with col2:
                            if risk.get('exploits'):
                                for exploit in risk['exploits']:
                                    st.warning(exploit)
                            else:
                                st.info("No specific exploits listed for this permission.")
                else:
                    st.info("Permission risk breakdown not available.")

            # --- Privacy Policy Tab --- 
            with tabs[2]:
                # Use 'privacy_policy' here instead of 'privacy_policy_ui'
                if privacy_policy:
                    st.header("📋 Privacy Policy Analysis")
                    st.metric("Policy Compliance Score",
                            f"{policy_compliance_score*100:.1f}%")

                    col1, col2 = st.columns(2)
                    with col1:
                        st.subheader("✅ Compliant Categories")
                        if compliance_report and compliance_report['compliant_categories']:
                            for category in compliance_report['compliant_categories']:
                                st.success(category.title())
                        else:
                            st.info("No fully compliant categories found based on contextual analysis.")

                    with col2:
                        st.subheader("❌ Non-Compliant Categories/Issues")
                        if compliance_report and compliance_report['non_compliant_categories']:
                            for category in compliance_report['non_compliant_categories']:
                                st.error(category.title())
                        else:
                            st.info("No specific non-compliant categories identified.")

                    if compliance_report and compliance_report['recommendations']:
                        st.subheader("Policy Recommendations")
                        for rec in compliance_report['recommendations']:
                            st.warning(rec)
                else:
                    st.info("No privacy policy text was provided for analysis.")

            # --- Technical Analysis Tab --- 
            with tabs[3]:
                st.header("⚙️ Technical Details")

                # --- Network Details Sub-section --- 
                st.subheader("🌐 Network Analysis")
                net_col1, net_col2 = st.columns(2)
                with net_col1:
                    st.metric("Total URLs Found", network_data.get('total_urls_found', 0))
                    st.metric("Unique Hosts Found", network_data.get('unique_hosts_found', 0))
                    st.metric("Network Permissions", network_data.get('network_permission_count', 0))
                with net_col2:
                    st.metric("Tracker Domains Found", len(network_data.get('tracker_domains', [])), delta_color="inverse")
                    st.metric("Malicious Domains Found", len(network_data.get('malicious_domains', [])), delta_color="inverse")
                    st.metric("Malicious IPs Found", len(network_data.get('malicious_ips', [])), delta_color="inverse")
                    st.metric("Insecure HTTP URLs", len(network_data.get('insecure_http_urls', [])), delta_color="inverse")

                # Display Insecure HTTP URLs
                if network_data.get('insecure_http_urls'):
                    with st.expander("🚨 Insecure HTTP URLs Detected"):
                        for url in network_data['insecure_http_urls']:
                            st.warning(f"- `{url}`")
                
                # Display Tracker Domains
                if network_data.get('tracker_domains'):
                    with st.expander("📡 Tracker Domains Identified (Network)"):
                        for domain in network_data['tracker_domains']:
                            st.info(f"- `{domain}`")

                # Display Malicious Domains/IPs
                if network_data.get('malicious_domains') or network_data.get('malicious_ips'):
                    with st.expander("💀 Potentially Malicious Endpoints Detected"):
                        if network_data.get('malicious_domains'):
                            st.error("**Malicious Domains:**")
                            for domain in network_data['malicious_domains']:
                                st.code(domain, language='text')
                        if network_data.get('malicious_ips'):
                            st.error("**Malicious IPs:**")
                            for ip in network_data['malicious_ips']:
                                st.code(ip, language='text')
                
                # Display Suspicious Details (Categorized URLs/Hosts)
                if network_data.get('suspicious_details'):
                    with st.expander("⚠️ Detailed Endpoint Analysis (Trackers/Suspicious)"):
                        st.dataframe(network_data['suspicious_details'])
                
                # Display Network Permissions Threats
                if network_data.get('threat_details'):
                    with st.expander("🔒 Network Permissions & Threats"):
                        for threat in network_data['threat_details']:
                            st.markdown(f"**{threat['permission']}** (Risk: {threat['risk_level']})")
                            st.caption(threat['description'])
                            with st.container():
                                st.write("Potential Threats:")
                                for pt in threat['potential_threats']:
                                    st.markdown(f"  - {pt}")
                            st.divider()

                # --- Code Analysis Sub-section --- 
                st.subheader("💻 Code Analysis Findings")
                # Use the enhanced code_patterns directly
                total_code_findings = sum(len(v) for v in code_patterns.values())
                st.metric("Total Code Issues Found", total_code_findings)
                st.metric("Detected Trackers (Code Signatures)", len(detected_trackers))

                if detected_trackers:
                    with st.expander("Known Tracker Libraries Found in Code"):
                        for tracker_name, package_prefix in detected_trackers.items():
                            st.info(f"- **{tracker_name}**: `{package_prefix}`")
                
                # *** UPDATED: Display detailed code patterns/vulnerabilities ***
                if code_patterns:
                    with st.expander("Detailed Code Analysis Results"):
                        # Sort categories (optional, e.g., put vulnerabilities first)
                        sorted_categories = sorted(code_patterns.keys(), key=lambda x: ('Vulnerability' not in x, x))
                        
                        for category in sorted_categories:
                            findings = code_patterns[category]
                            if findings:
                                st.markdown(f"#### {category}")
                                for finding in findings:
                                    severity = finding.get('severity', 'Info').upper()
                                    description = finding.get('description', 'N/A')
                                    details = finding.get('details', 'N/A')
                                    
                                    # Display with color coding based on severity
                                    if severity == 'HIGH' or severity == 'CRITICAL':
                                        st.error(f"**[{severity}]** {description}")
                                    elif severity == 'MEDIUM':
                                        st.warning(f"**[{severity}]** {description}")
                                    else:
                                        st.info(f"**[{severity}]** {description}")
                                    # Show details in a code block for clarity
                                    st.code(f"Location/Details: {details}", language='text')
                                st.divider()
                else:
                    st.success("No significant code patterns or vulnerabilities identified.")

                # --- Permissions Sub-section --- 
                st.subheader("🔑 Permissions Requested")
                if tech_details.get('permissions'):
                    with st.expander("View All Permissions"):
                        for perm in tech_details['permissions']:
                            st.code(perm, language='text')

            # --- Recommendations Tab --- 
            with tabs[4]:
                st.header("💡 Recommendations")
                # Now this function call should work
                recommendations = generate_recommendations(
                    risk_prediction,
                    security_analysis,
                    compliance_report,
                    tech_details
                )
                if recommendations:
                    for i, rec in enumerate(recommendations):
                        st.info(f"{i+1}. {rec}")
                else:
                    st.success("No specific recommendations generated based on the analysis.")

# --- Flask App Runner --- 
if __name__ == '__main__':
    # Run Flask in a separate thread
    from threading import Thread
    flask_thread = Thread(target=lambda: flask_app.run(host='0.0.0.0', port=5001, debug=False, use_reloader=False))
    flask_thread.daemon = True
    flask_thread.start()
    # Streamlit runs in the main thread implicitly when script is executed

    # Add privacy leak analysis
    # At the global level, define analyzers
    analyzers = {
        'permission': None,
        'network': NetworkAnalyzer(),
        'code': CodeAnalyzer()
    }
    
    # Then in your function where you have APK analysis
    def analyze_apk(apk_path):
        # Initialize the APK analysis
        a, d, dx = AnalyzeAPK(apk_path)
        
        # Update the permission analyzer with the current APK
        analyzers['permission'] = PermissionAnalyzer(a)
        
        # Perform your analysis
        privacy_leaks = analyzers['code'].analyze_privacy_leaks(dx)
    
        # Update all_features with privacy leak information
        all_features.update({
            'privacy_leak_count': sum(len(findings) for findings in privacy_leaks.values()),
            'high_risk_leaks': sum(
                1 for category in privacy_leaks.values()
                for finding in category
                if finding['severity'] == 'High'
            )
        })
    
        # Update results with privacy leak findings
        results['technical_details']['privacy_leaks'] = privacy_leaks
    
    from models.monitor_analyzer import PrivacyMonitor, AlertHandler
    
    # Initialize privacy monitor
    privacy_monitor = PrivacyMonitor()
    
    # Register alert handlers
    privacy_monitor.register_alert_handler(AlertHandler.console_handler)
    privacy_monitor.register_alert_handler(AlertHandler.file_handler)
    
    # Start monitoring
    privacy_monitor.start_monitoring()