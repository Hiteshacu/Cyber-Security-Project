import xml.etree.ElementTree as ET # Add XML parsing

class SecurityAnalyzer:
    def __init__(self):
        self.impact_weights = {
            'dangerous_permissions': 0.25, # Adjusted weight
            'network_security': 0.20, # Adjusted weight
            'code_patterns': 0.15, # Adjusted weight
            'trackers': 0.10,
            'policy_compliance': 0.10, # Adjusted weight
            'manifest_security': 0.20 # Added weight for manifest
        }

        # Expanded permission impact details
        self.permission_impact = {
            # Critical Permissions
            'INTERNET': {'impact': 'Critical', 'weight': 1.0, 'exploits': ['Data exfiltration', 'C&C communication', 'Malware downloads']},
            'SEND_SMS': {'impact': 'Critical', 'weight': 1.0, 'exploits': ['Premium SMS fraud', 'Spam', 'Phishing']},
            'WRITE_EXTERNAL_STORAGE': {'impact': 'Critical', 'weight': 0.9, 'exploits': ['Ransomware', 'Data modification', 'Malware installation']},
            'ACCESS_FINE_LOCATION': {'impact': 'Critical', 'weight': 0.9, 'exploits': ['Precise user tracking', 'Stalking', 'Physical security risk']},

            # High Impact Permissions
            'READ_EXTERNAL_STORAGE': {'impact': 'High', 'weight': 0.8, 'exploits': ['Data theft', 'Privacy breaches', 'Access to sensitive files']},
            'CAMERA': {'impact': 'High', 'weight': 0.8, 'exploits': ['Unauthorized photography/video', 'Spying', 'Privacy invasion']},
            'RECORD_AUDIO': {'impact': 'High', 'weight': 0.8, 'exploits': ['Eavesdropping', 'Spying', 'Voice recording theft']},
            'READ_CONTACTS': {'impact': 'High', 'weight': 0.7, 'exploits': ['Contact list theft', 'Spam/Phishing targets', 'Social engineering']},
            'READ_SMS': {'impact': 'High', 'weight': 0.7, 'exploits': ['SMS content theft', 'OTP interception', 'Phishing']},
            'READ_PHONE_STATE': {'impact': 'High', 'weight': 0.7, 'exploits': ['Device ID theft', 'Call monitoring', 'User tracking']},

            # Medium Impact Permissions
            'ACCESS_COARSE_LOCATION': {'impact': 'Medium', 'weight': 0.5, 'exploits': ['Approximate user tracking', 'Location-based profiling']},
            'GET_ACCOUNTS': {'impact': 'Medium', 'weight': 0.5, 'exploits': ['Account enumeration', 'Targeted attacks', 'Phishing']},
            # Add more permissions as needed
        }

    # Updated method signature to accept manifest_xml
    def calculate_security_score(self, permissions, network_data, code_patterns, manifest_xml, policy_score=None, tracker_count=0):
        # Permission score
        perm_score = self._calculate_permission_score(permissions)

        # Network security score
        network_score = self._calculate_network_score(network_data)

        # Code patterns score
        code_score = self._calculate_code_score(code_patterns)

        # Tracker score
        tracker_score = max(0, 1.0 - (tracker_count * 0.15))

        # Policy compliance score
        policy_score_val = policy_score if policy_score is not None else 1.0
        
        # *** NEW: Manifest security score ***
        manifest_analysis = self.analyze_manifest_security(manifest_xml)
        manifest_score = manifest_analysis['score']

        # Calculate weighted average
        final_score = (
            perm_score * self.impact_weights['dangerous_permissions'] +
            network_score * self.impact_weights['network_security'] +
            code_score * self.impact_weights['code_patterns'] +
            tracker_score * self.impact_weights['trackers'] +
            policy_score_val * self.impact_weights['policy_compliance'] +
            manifest_score * self.impact_weights['manifest_security'] # Include manifest score
        )
        # Normalize score based on actual weights used (in case some components are missing)
        total_weight = sum(self.impact_weights.values())
        final_score = min(1.0, max(0.0, final_score / total_weight if total_weight > 0 else 0)) # Normalize and clamp

        return {
            'overall_score': final_score,
            'component_scores': {
                'Permissions': perm_score,
                'Network': network_score,
                'Code': code_score,
                'Trackers': tracker_score,
                'Policy': policy_score_val,
                'Manifest': manifest_score # Add manifest component score
            },
            'risk_breakdown': self._generate_risk_breakdown(permissions),
            'manifest_issues': manifest_analysis['issues'] # Add detailed manifest issues
        }

    def _calculate_permission_score(self, permissions):
        total_possible_weight = sum(p['weight'] for p in self.permission_impact.values()) # Theoretical max weight
        actual_weight_sum = 0
        permission_count = 0

        for perm in permissions:
            perm_name = perm.split('.')[-1]
            if perm_name in self.permission_impact:
                impact = self.permission_impact[perm_name]
                actual_weight_sum += impact['weight']
                permission_count += 1

        if permission_count == 0:
            return 1.0 # No risky permissions found

        average_risk_weight = actual_weight_sum / permission_count
        score = 1.0 - average_risk_weight
        return max(0, score)

    def _calculate_network_score(self, network_data):
        base_score = 1.0
        # Penalties for specific issues
        if network_data.get('has_internet_access'):
            base_score -= 0.1 # Base penalty for internet access
        if len(network_data.get('insecure_http_urls', [])) > 0:
            base_score -= 0.3 # Higher penalty for insecure connections
        if len(network_data.get('malicious_domains', [])) > 0 or len(network_data.get('malicious_ips', [])) > 0:
            base_score -= 0.4 # Highest penalty for known malicious endpoints
        elif network_data.get('suspicious_url_count', 0) > 0:
             base_score -= 0.1 * min(network_data['suspicious_url_count'], 3) # Penalty for other suspicious URLs
        
        return max(0, base_score)

    def _calculate_code_score(self, code_patterns):
        # Consider adding severity to code patterns later
        total_findings = sum(len(findings) for findings in code_patterns.values())
        # Reduce penalty per finding slightly
        return max(0, 1.0 - (0.05 * total_findings))

    def _generate_risk_breakdown(self, permissions):
        breakdown = []
        for perm in permissions:
            perm_name = perm.split('.')[-1]
            if perm_name in self.permission_impact:
                impact = self.permission_impact[perm_name]
                breakdown.append({
                    'permission': perm_name,
                    'impact': impact['impact'],
                    'exploits': impact['exploits']
                })
        return breakdown

    # *** NEW METHOD: Analyze Manifest Security ***
    def analyze_manifest_security(self, manifest_xml):
        issues = []
        score_penalty = 0.0
        max_penalty = 1.0 # Max possible penalty
        android_ns = '{http://schemas.android.com/apk/res/android}'

        if not manifest_xml:
            return {'score': 1.0, 'issues': ['Manifest XML not available for analysis.']}

        try:
            root = manifest_xml # Assuming manifest_xml is already parsed ET object
            application = root.find('application')

            if application is not None:
                # 1. Check android:debuggable
                debuggable = application.get(f'{android_ns}debuggable')
                if debuggable == 'true':
                    issues.append({'severity': 'High', 'description': 'Application is debuggable (android:debuggable="true"). Should be false in production.'})
                    score_penalty += 0.3

                # 2. Check android:allowBackup
                allow_backup = application.get(f'{android_ns}allowBackup')
                # Default is true if not specified and targetSDK < 31
                # For simplicity, flag if explicitly true or not present (assume default true is risky)
                if allow_backup == 'true' or allow_backup is None:
                    issues.append({'severity': 'Medium', 'description': 'Application data backup enabled (android:allowBackup="true" or not set). Sensitive data might be backed up.'})
                    score_penalty += 0.15
                
                # 3. Check for exported components without required permissions
                component_tags = ['activity', 'service', 'receiver', 'provider']
                exported_components = []
                for tag in component_tags:
                    for component in application.findall(tag):
                        name = component.get(f'{android_ns}name')
                        exported = component.get(f'{android_ns}exported')
                        permission = component.get(f'{android_ns}permission')
                        
                        # Determine if implicitly or explicitly exported
                        is_exported = False
                        if exported == 'true':
                            is_exported = True
                        elif exported is None:
                            # Check for intent filters which imply exported=true by default
                            if component.find('intent-filter') is not None:
                                is_exported = True
                        
                        if is_exported and not permission:
                            # Check if it's a main launcher activity (common case, less risky)
                            is_launcher = False
                            intent_filter = component.find('intent-filter')
                            if intent_filter is not None:
                                action = intent_filter.find(f"action[@{android_ns}name='android.intent.action.MAIN']")
                                category = intent_filter.find(f"category[@{android_ns}name='android.intent.category.LAUNCHER']")
                                if action is not None and category is not None:
                                    is_launcher = True
                            
                            if not is_launcher:
                                exported_components.append({'tag': tag, 'name': name})
                
                if exported_components:
                    issue_desc = f"Found {len(exported_components)} exported components without required permissions: "
                    issue_desc += ', '.join([f"{c['tag']} '{c['name']}'" for c in exported_components[:3]]) # Show first few
                    if len(exported_components) > 3: issue_desc += "..."
                    issues.append({'severity': 'High', 'description': issue_desc})
                    score_penalty += 0.1 * len(exported_components) # Add penalty per component

            # Calculate final score (1.0 is best, 0.0 is worst)
            final_score = max(0.0, 1.0 - (score_penalty / max_penalty if max_penalty > 0 else 0))
            
        except ET.ParseError as e:
            issues.append({'severity': 'Error', 'description': f'Failed to parse Manifest XML: {e}'})
            final_score = 0.5 # Assign neutral score on parse error
        except Exception as e:
             issues.append({'severity': 'Error', 'description': f'Error during manifest analysis: {e}'})
             final_score = 0.5

        return {'score': final_score, 'issues': issues}

    def detect_advanced_anomalies(self, usage_patterns):
        """Detect complex behavioral patterns using ML"""

    def generate_certificate(self, scores):
        """Generate privacy compliance certificate"""

    def advanced_security_analysis(self, permissions, network_data, code_patterns):
        """Perform advanced security analysis with machine learning"""