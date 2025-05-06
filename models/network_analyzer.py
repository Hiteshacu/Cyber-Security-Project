from androguard.core.bytecodes.apk import APK
from androguard.misc import AnalyzeAPK
import socket
import re
import ssl
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict

# --- Placeholder for external reputation data --- 
# You could load these from files or a simple database
KNOWN_MALICIOUS_IPS = {
    # "192.0.2.1": "Known C&C Server",
    # "203.0.113.10": "Reported Phishing Source"
}
KNOWN_MALICIOUS_DOMAINS = {
    # "malicious-domain.example": "Malware Distribution",
    # "phishing-site.example": "Phishing"
}

class NetworkAnalyzer:
    def __init__(self):
        self.network_permissions = [
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.ACCESS_WIFI_STATE',
            'android.permission.CHANGE_WIFI_STATE',
            'android.permission.CHANGE_NETWORK_STATE'
        ]

        # Enhanced threat information database
        self.permission_threats = {
            'android.permission.INTERNET': {
                'risk_level': 'High',
                'description': 'Allows the app to open network sockets and access the internet',
                'potential_threats': [
                    'Data exfiltration to unknown servers',
                    'Communication with malicious domains',
                    'Downloading malicious content'
                ],
                'mitigation': 'Monitor network traffic and restrict background data access'
            },
            'android.permission.ACCESS_NETWORK_STATE': {
                'risk_level': 'Medium',
                'description': 'Allows the app to view network connectivity status',
                'potential_threats': [
                    'Network state monitoring',
                    'User behavior tracking',
                    'Connection timing analysis'
                ],
                'mitigation': 'Review app network usage patterns'
            },
            'android.permission.ACCESS_WIFI_STATE': {
                'risk_level': 'Medium',
                'description': 'Allows the app to view WiFi network information',
                'potential_threats': [
                    'WiFi network enumeration',
                    'Location tracking via WiFi',
                    'Network environment mapping'
                ],
                'mitigation': 'Disable WiFi access when not needed'
            }
        }

        # Expanded and refined high-risk/tracker domain categories
        # (Consider sourcing more comprehensive lists externally, e.g., EasyList, Disconnect lists)
        self.high_risk_domains = {
            'analytics': {
                'description': 'Data analytics and tracking services',
                'threats': ['User behavior tracking', 'Data collection', 'Profile building'],
                'examples': [
                    'google-analytics.com', 'googletagmanager.com', 'mixpanel.com',
                    'amplitude.com', 'flurry.com', 'segment.com', 'heap.io',
                    'stats.g.doubleclick.net'
                ]
            },
            'tracker': {
                'description': 'User tracking, attribution, and fingerprinting platforms',
                'threats': ['Location tracking', 'Activity monitoring', 'Cross-app tracking', 'Device fingerprinting'],
                'examples': [
                    'adjust.com', 'appsflyer.com', 'branch.io', 'kochava.com',
                    'singular.net', 'tune.com', 'app-measurement.com', # Firebase/Google
                    'scorecardresearch.com', 'crwdcntrl.net', 'criteo.com'
                ]
            },
            'ads': {
                'description': 'Advertising networks and services',
                'threats': ['Ad tracking', 'Personal data collection for ads', 'Behavioral profiling'],
                'examples': [
                    'admob.com', 'mopub.com', 'unityads.unity3d.com', 'applovin.com',
                    'doubleclick.net', 'googleadservices.com', 'googlesyndication.com',
                    'facebook.com', 'fbcdn.net', # Includes FB ads/tracking
                    'advertising.com', 'yieldmo.com', 'pubmatic.com', 'openx.net'
                ]
            },
            'social_media_sdk': {
                'description': 'Social media platform SDKs (often include tracking)',
                'threats': ['Social graph linking', 'Data sharing with platform', 'Extensive user profiling'],
                'examples': [
                    'connect.facebook.net', 'graph.facebook.com', # Facebook SDK
                    'api.twitter.com', # Twitter SDK
                    'snapkit.com', # Snapchat SDK
                    # Add others like TikTok, LinkedIn if relevant
                ]
            },
            'cloud_storage': {
                'description': 'Cloud storage providers (potential for data exfiltration if misused)',
                'threats': ['Unauthorized data upload/download', 'Data leakage if misconfigured'],
                'examples': [
                    'dropbox.com', 'drive.google.com', 'mega.nz', 'box.com',
                    'amazonaws.com', # AWS S3 - very broad, use with caution
                    'blob.core.windows.net' # Azure Blob - very broad
                ]
            },
            'known_malicious': {
                'description': 'Domains known to be associated with malware or phishing (Example - use real feeds)',
                'threats': ['Malware C&C', 'Phishing', 'Data Theft'],
                'examples': list(KNOWN_MALICIOUS_DOMAINS.keys()) # Populate from external source
            }
        }

    # *** CHANGE PARAMETER HERE from 'apk' to 'permissions_list' ***
    def analyze_network_permissions(self, permissions_list):
        # *** Filter the provided list directly ***
        network_perms = [p for p in permissions_list if p in self.network_permissions]
        threat_details = []
        
        for perm in network_perms:
            if perm in self.permission_threats:
                threat_details.append({
                    'permission': perm,
                    **self.permission_threats[perm]
                })
        
        return {
            'network_permission_count': len(network_perms),
            'has_internet_access': 'android.permission.INTERNET' in network_perms,
            'network_permissions': network_perms,
            'threat_details': threat_details,
            'suspicious_url_count': 0 # This will be updated by analyze_network_urls
        }

    # *** CHANGE PARAMETER HERE from 'apk' to 'apk_path' ***
    def analyze_network_urls(self, apk_path):
        urls_from_manifest = []
        urls_from_code = []
        suspicious_urls_details = []
        tracker_domains_found = set()
        malicious_domains_found = set()
        malicious_ips_found = set()
        insecure_http_urls = set()
        all_urls = []
        unique_hosts = set()

        a = None # Define 'a' outside try block for cleanup in finally

        try:
            # *** Use AnalyzeAPK to get the APK object 'a' from the path ***
            a, _, _ = AnalyzeAPK(apk_path)
            if not a:
                raise Exception("Failed to analyze APK for network URLs.")

            # --- Extract URLs (Manifest) --- 
            # *** Use the 'a' object obtained above ***
            manifest = a.get_android_manifest_xml()
            if manifest:
                # Check intent filters for deep links/hosts
                for intent_filter in manifest.findall('.//intent-filter'):
                    for data in intent_filter.findall('.//data'):
                        scheme = data.get('{http://schemas.android.com/apk/res/android}scheme')
                        host = data.get('{http://schemas.android.com/apk/res/android}host')
                        path = data.get('{http://schemas.android.com/apk/res/android}pathPrefix') or data.get('{http://schemas.android.com/apk/res/android}path')
                        if host:
                            # Normalize scheme if missing
                            if not scheme:
                                scheme = 'http' # Assume http if scheme missing, flag later
                            url = f"{scheme}://{host}{path or ''}"
                            urls_from_manifest.append(url)

                # Check meta-data
                for meta_data in manifest.findall('.//meta-data'):
                    value = meta_data.get('{http://schemas.android.com/apk/res/android}value')
                    # Basic check if value looks like a URL - refine regex?
                    if value and isinstance(value, str) and ('://' in value or '.' in value):
                         # More robust URL check might be needed
                         if re.match(r'^https?://', value) or '.' in urlparse(value).netloc:
                            urls_from_manifest.append(value)

            # --- Extract URLs (Code - Optional, Basic) ---
            # *** Pass the 'a' object to the helper method ***
            urls_from_code = self._extract_urls_from_code(a)

            all_urls = list(set(urls_from_manifest + urls_from_code))
            unique_hosts = set()
            host_map = {}

            # --- Pre-process URLs and Hosts ---
            for url in all_urls:
                try:
                    parsed = urlparse(url)
                    if parsed.hostname:
                        unique_hosts.add(parsed.hostname)
                        host_map[parsed.hostname] = url # Store one URL example per host
                        if parsed.scheme == 'http':
                            insecure_http_urls.add(url)
                except Exception as parse_err:
                    print(f"Skipping invalid URL {url}: {parse_err}")

            # --- Resolve IPs (Batch) ---
            resolved_ips = self.resolve_ips(list(unique_hosts))
            ip_to_host = {res['ip']: res['hostname'] for res in resolved_ips if res.get('ip')}

            # --- Analyze Hosts/IPs ---
            for host in unique_hosts:
                matched_categories = []
                is_tracker = False
                is_malicious_domain = False

                # Check against high-risk/tracker lists
                for category, data in self.high_risk_domains.items():
                    # Check if host itself or its parent domains match examples
                    host_parts = host.lower().split('.')
                    for i in range(len(host_parts) - 1):
                        sub_domain = '.'.join(host_parts[i:])
                        if any(example == sub_domain for example in data['examples']): 
                            matched_categories.append(category)
                            if category in ['analytics', 'tracker', 'ads', 'social_media_sdk']:
                                is_tracker = True
                            if category == 'known_malicious':
                                is_malicious_domain = True
                            break # Found a match for this category
                
                if is_tracker:
                    tracker_domains_found.add(host)
                if is_malicious_domain:
                    malicious_domains_found.add(host)

                # Find corresponding IP and check reputation
                ip_address = None
                ip_reputation = None
                for res in resolved_ips:
                    if res.get('hostname') == host and res.get('ip'):
                        ip_address = res['ip']
                        ip_reputation = self.check_ip_reputation(ip_address)
                        if ip_reputation:
                            malicious_ips_found.add(ip_address)
                        break

                # Add to suspicious list if categorized, malicious, or has bad IP rep
                if matched_categories or ip_reputation:
                    suspicious_urls_details.append({
                        'url_example': host_map.get(host, 'N/A'),
                        'host': host,
                        'categories': matched_categories,
                        'ip_address': ip_address,
                        'ip_reputation': ip_reputation # None if not malicious, description if malicious
                    })

            # *** RETURN SUCCESSFUL RESULTS AT THE END OF TRY BLOCK ***
            return {
                'total_urls_found': len(all_urls),
                'unique_hosts_found': len(unique_hosts),
                'insecure_http_urls': list(insecure_http_urls),
                'tracker_domains': list(tracker_domains_found),
                'malicious_domains': list(malicious_domains_found),
                'malicious_ips': list(malicious_ips_found),
                'suspicious_details': suspicious_urls_details, # Renamed for clarity
                'suspicious_url_count': len(suspicious_urls_details) # Count based on hosts with issues
            }
        except Exception as e:
            print(f"Error analyzing network URLs: {e}")
            # Return safe defaults
            return {
                'total_urls_found': 0,
                'unique_hosts_found': 0,
                'insecure_http_urls': [],
                'tracker_domains': [],
                'malicious_domains': [],
                'malicious_ips': [],
                'suspicious_details': [],
                'suspicious_url_count': 0
            }

    # *** CHANGE PARAMETER HERE from 'apk' to 'a' (APK object) ***
    def _extract_urls_from_code(self, a):
        """Helper to extract potential URLs from DEX code strings."""
        urls = []
        if not a:
            return urls
        try:
            # Basic regex for URLs in strings (can be improved)
            # *** ADD '+' to match one or more characters ***
            url_regex = re.compile(r"https?://[^\s'\"<>]+")
            
            # Access DalvikVMFormat through the APK object 'a'
            dvm = a.get_dalvik_vm_format()
            if dvm:
                for s in dvm.get_strings():
                    # Find all potential URLs in the string
                    found = url_regex.findall(s)
                    urls.extend(found)
            return list(set(urls)) # Return unique URLs
        except Exception as e:
            print(f"Error extracting URLs from code: {e}")
            return urls

    def resolve_ips(self, hostnames):
        """Resolve domain names to IP addresses."""
        results = []
        # Limit concurrent resolutions if needed
        for hostname in hostnames:
            try:
                # Use getaddrinfo for potentially better IPv4/IPv6 handling
                addr_info = socket.getaddrinfo(hostname, None)
                # Prefer IPv4 if available, otherwise take first IP
                ip = next((info[4][0] for info in addr_info if info[0] == socket.AF_INET), None)
                if not ip and addr_info:
                    ip = addr_info[0][4][0] # Fallback to first available (might be IPv6)
                
                if ip:
                    results.append({'hostname': hostname, 'ip': ip})
                else:
                    results.append({'hostname': hostname, 'ip': None, 'error': 'No address found'})
            except socket.gaierror:
                results.append({'hostname': hostname, 'ip': None, 'error': 'Resolution failed'})
            except Exception as e:
                 results.append({'hostname': hostname, 'ip': None, 'error': str(e)})
        return results

    def check_ip_reputation(self, ip_address):
        """Placeholder: Check IP against known malicious lists or external API."""
        if not ip_address:
            return None
        
        # 1. Check internal blocklist
        if ip_address in KNOWN_MALICIOUS_IPS:
            return f"Known Malicious: {KNOWN_MALICIOUS_IPS[ip_address]}"

        # 2. Placeholder for external API call (e.g., AbuseIPDB, VirusTotal)
        # try:
        #     # Example using requests (needs 'pip install requests')
        #     # headers = {'Key': 'YOUR_ABUSEIPDB_API_KEY', 'Accept': 'application/json'}
        #     # params = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
        #     # response = requests.get('https://api.abuseipdb.com/api/v2/check', headers=headers, params=params)
        #     # if response.status_code == 200:
        #     #     data = response.json()['data']
        #     #     if data['abuseConfidenceScore'] > 50: # Example threshold
        #     #         return f"AbuseIPDB Score: {data['abuseConfidenceScore']}% ({data['totalReports']} reports)"
        # except Exception as e:
        #     print(f"Error checking IP reputation for {ip_address}: {e}")

        return None # No malicious reputation found

    # --- Placeholder for Certificate Analysis ---
    # def analyze_certificates(self, urls):
    #     """Placeholder: Analyze SSL/TLS certificates for validity, issuer, etc."""
    #     # Requires libraries like 'ssl', 'pyopenssl', 'requests'

    def check_domain_reputation(self, domain):
        """Check domain reputation using cached results or external API"""
        now = datetime.now()
        
        # Check cache first
        if domain in self.threat_intel_cache:
            cache_entry = self.threat_intel_cache[domain]
            if now - cache_entry['timestamp'] < self.cache_duration:
                return cache_entry['data']
        
        # Implement actual threat intelligence API call here
        # For example, using VirusTotal, AbuseIPDB, or other services
        reputation_data = self._query_threat_intelligence(domain)
        
        # Cache the result
        self.threat_intel_cache[domain] = {
            'timestamp': now,
            'data': reputation_data
        }
        
        return reputation_data

    def analyze_ssl_security(self, url):
        """Analyze SSL/TLS security of endpoints"""
        try:
            response = requests.get(url, verify=True)
            cert = response.raw.connection.sock.getpeercert()
            
            issues = []
            if cert:
                # Check certificate validity
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                if not_after < datetime.now():
                    issues.append('Certificate expired')
                
                # Check certificate chain
                if 'subjectAltName' not in cert:
                    issues.append('Missing Subject Alternative Name')
            
            return {
                'has_ssl': True,
                'issues': issues,
                'cert_details': cert if cert else None
            }
        except requests.exceptions.SSLError as e:
            return {
                'has_ssl': False,
                'issues': ['SSL verification failed'],
                'error': str(e)
            }
        except Exception as e:
            return {
                'has_ssl': False,
                'issues': ['Connection failed'],
                'error': str(e)
            }

    def analyze_api_security(self, url):
        """Analyze API endpoint security patterns"""
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        findings = []
        for category, info in self.api_security_patterns.items():
            if any(pattern in path for pattern in info['patterns']):
                findings.append({
                    'category': category,
                    'risk': info['risk'],
                    'description': info['description'],
                    'url': url
                })
        
        return findings

    def analyze_network_security(self, apk_path):
        """Comprehensive network security analysis"""
        # Get basic network analysis first
        basic_analysis = self.analyze_network_urls(apk_path)
        
        # Enhanced security analysis
        security_findings = {
            'ssl_issues': [],
            'api_security': [],
            'domain_reputation': [],
            'data_leak_risks': []
        }
        
        # Analyze each unique URL
        for url in basic_analysis.get('all_urls', []):
            # SSL/TLS Analysis
            if url.startswith('https'):
                ssl_check = self.analyze_ssl_security(url)
                if ssl_check['issues']:
                    security_findings['ssl_issues'].append({
                        'url': url,                        'issues': ssl_check['issues']
                    })
            
            # API Security Analysis
            api_risks = self.analyze_api_security(url)
            if api_risks:
                security_findings['api_security'].extend(api_risks)
            
            # Domain Reputation Check
            domain = urlparse(url).netloc
            reputation = self.check_domain_reputation(domain)
            if reputation.get('risk_level', 'low').lower() != 'low':
                security_findings['domain_reputation'].append({
                    'domain': domain,
                    'reputation': reputation
                })
        
        # Calculate risk scores
        risk_scores = self._calculate_security_risk_scores(security_findings)
        
        return {
            **basic_analysis,
            'security_findings': security_findings,
            'risk_scores': risk_scores
        }

    def _calculate_security_risk_scores(self, findings):
        """Calculate detailed security risk scores"""
        scores = {
            'ssl_security': 1.0,
            'api_security': 1.0,
            'domain_reputation': 1.0,
            'overall_security': 1.0
        }
        
        # SSL Security Score
        if findings['ssl_issues']:
            scores['ssl_security'] -= len(findings['ssl_issues']) * 0.1
        
        # API Security Score
        high_risk_apis = sum(1 for api in findings['api_security'] if api['risk'] == 'High')
        medium_risk_apis = sum(1 for api in findings['api_security'] if api['risk'] == 'Medium')
        scores['api_security'] -= (high_risk_apis * 0.15 + medium_risk_apis * 0.1)
        
        # Domain Reputation Score
        bad_domains = len(findings['domain_reputation'])
        scores['domain_reputation'] -= bad_domains * 0.2
        
        # Normalize scores
        for key in scores:
            scores[key] = max(0.0, min(1.0, scores[key]))
        
        # Calculate overall score
        scores['overall_security'] = sum(scores.values()) / len(scores)
        
        return scores