from androguard.core.bytecodes import dvm
from androguard.misc import AnalyzeAPK
import re

class CodeAnalyzer:
    def __init__(self):
        # Initialize basic attributes
        self.suspicious_apis = self._init_suspicious_apis()
        self.vulnerability_patterns = self._init_vulnerability_patterns()
        self.tracker_packages = self._init_tracker_packages()
        self.data_leak_patterns = self._init_data_leak_patterns()
        self.privacy_sensitive_apis = self._init_privacy_sensitive_apis()

    def _init_suspicious_apis(self):
        return {
            'Potentially Sensitive Data Access': [
                'getDeviceId', 'getSubscriberId', 'getSimSerialNumber', 'getLine1Number',
                'android/provider/ContactsContract',
                'android/provider/Telephony$Sms',
                'android/location/LocationManager;->getLastKnownLocation',
            ],
            'Dynamic Code Execution': [
                'Ldalvik/system/DexClassLoader;',
                'Ljava/lang/Runtime;->exec',
                'Ljava/lang/reflect/Method;->invoke',
            ],
            'Network Communication': [
                'Ljava/net/HttpURLConnection;',
                'Ljava/net/Socket;',
                'Landroid/net/ConnectivityManager;->getActiveNetworkInfo'
            ],
            'File System Access': [
                'Ljava/io/File;->openFileOutput',
                'Landroid/os/Environment;->getExternalStorageDirectory',
                'Landroid/content/Context;->getSharedPreferences'
            ]
        }

    def _init_vulnerability_patterns(self):
        return {
            'Insecure WebView': [
                {'method': 'setJavaScriptEnabled', 'class': 'Landroid/webkit/WebSettings;', 'desc': 'JavaScript enabled in WebView (Risk if loading untrusted content)'},
                {'method': 'setAllowFileAccess', 'class': 'Landroid/webkit/WebSettings;', 'desc': 'File access enabled in WebView with JavaScript (Security risk)', 'related_check': 'setJavaScriptEnabled'}
            ],
            'Weak Cryptography': [
                {'api': 'Ljavax/crypto/Cipher;->getInstance', 'pattern': r'DES|DESede|MD5|SHA1', 'desc': 'Use of potentially weak cryptographic algorithm (DES, DESede, MD5, SHA1)', 'severity': 'High'},
                {'class': 'Ljava/security/MessageDigest;', 'pattern': r'MD5|SHA1', 'desc': 'Use of weak hashing algorithm (MD5, SHA1)', 'severity': 'High'}
            ],
            'Insecure Randomness': [
                {'class': 'Ljava/util/Random;', 'desc': 'Use of insecure java.util.Random (Use SecureRandom for security-sensitive contexts)', 'severity': 'Medium'}
            ],
            'Sensitive Data Logging': [
                {'method': 'Log', 'class': 'Landroid/util/Log;', 'pattern': r'[dviwe]', 'desc': 'Potentially logging sensitive data (Check Log calls)', 'severity': 'Medium'}
            ],
            'Hardcoded Secrets (Basic)': [
                {'string_pattern': r'(key|token|secret|password)\s*[:=]\s*["]([^"]{8,})["]', 'desc': 'Potential hardcoded secret found in string (Needs verification)', 'severity': 'High'}
            ]
        }

    def _init_tracker_packages(self):
        return {
            'Google AdMob': 'com.google.android.gms.ads',
            'Google Analytics': 'com.google.android.gms.analytics',
            'Facebook Ads': 'com.facebook.ads',
            'Facebook Analytics': 'com.facebook.appevents',
            'Firebase Analytics': 'com.google.firebase.analytics',
            'Adjust': 'com.adjust.sdk',
            'AppsFlyer': 'com.appsflyer.sdk',
            'Mixpanel': 'com.mixpanel.android',
            'Amplitude': 'com.amplitude.api',
            'Unity Ads': 'com.unity3d.ads'
        }

    def _init_data_leak_patterns(self):
        return {
            'File System Leaks': [
                {'method': 'writeFile', 'class': 'Ljava/io/FileOutputStream;', 'desc': 'Writing data to external storage', 'severity': 'High'},
                {'method': 'write', 'class': 'Ljava/io/OutputStream;', 'desc': 'Writing data to output stream', 'severity': 'Medium'}
            ],
            'Network Leaks': [
                {'method': 'send', 'class': 'Lokhttp3/Request;', 'desc': 'Data transmission via OkHttp', 'severity': 'High'},
                {'method': 'execute', 'class': 'Lorg/apache/http/impl/client/HttpClient;', 'desc': 'Data transmission via HttpClient', 'severity': 'High'}
            ],
            'Data Persistence': [
                {'method': 'putString', 'class': 'Landroid/content/SharedPreferences$Editor;', 'desc': 'Storing data in SharedPreferences', 'severity': 'Medium'},
                {'method': 'insert', 'class': 'Landroid/database/sqlite/SQLiteDatabase;', 'desc': 'Storing data in SQLite database', 'severity': 'Medium'}
            ]
        }

    def _init_privacy_sensitive_apis(self):
        return {
            'Location': [
                'android/location/LocationManager;->getLastKnownLocation',
                'android/location/LocationManager;->requestLocationUpdates'
            ],
            'Device Info': [
                'android/provider/Settings$Secure;->getString',
                'android/telephony/TelephonyManager;->getDeviceId',
                'android/telephony/TelephonyManager;->getSubscriberId'
            ],
            'User Data': [
                'android/accounts/AccountManager;->getAccounts',
                'android/provider/ContactsContract$Contacts;->query',
                'android/provider/CalendarContract;->query'
            ]
        }

    def analyze_code_patterns(self, dx):
        findings = {category: [] for category in self.suspicious_apis}
        # Add categories for new vulnerabilities
        for category in self.vulnerability_patterns:
            findings[category] = []

        if not dx:
            return findings # Return empty findings if analysis object is missing

        try:
            # Remove the APK path check as it's not needed
            # The dx object already contains all the information we need

            # 1. Check Suspicious API Calls (using xrefs for context)
            for category, apis in self.suspicious_apis.items():
                for api_pattern in apis:
                    # Search for cross-references to methods/classes matching the pattern
                    # Example: Searching for calls *to* a specific method
                    # Note: Androguard search might need refinement based on pattern type (class, method, etc.)
                    target_methods = dx.find_methods(classname=f"^{api_pattern.split(';->')[0]}.*" if ';->' in api_pattern else f"^{api_pattern}.*", methodname=api_pattern.split(';->')[1] if ';->' in api_pattern else ".*")
                    for method_analysis in target_methods:
                        # Find where this method is called *from*
                        for _, call, _ in method_analysis.get_xref_from():
                            caller_info = f"{call.class_name}->{call.name}{call.descriptor}"
                            if caller_info not in [f['details'] for f in findings[category]]: # Avoid duplicates
                                findings[category].append({
                                    'severity': 'Medium', # Default severity, can be refined
                                    'description': f"Suspicious API call to '{api_pattern}' found.",
                                    'details': caller_info
                                })
            
            # 2. Check Specific Vulnerability Patterns
            for category, patterns in self.vulnerability_patterns.items():
                for pattern_info in patterns:
                    # Search based on pattern type (method call, class usage, string regex, api call with param check)
                    if 'method' in pattern_info and 'class' in pattern_info:
                        target_methods = dx.find_methods(classname=pattern_info['class'], methodname=pattern_info['method'])
                        for method_analysis in target_methods:
                             for _, call, _ in method_analysis.get_xref_from():
                                caller_info = f"{call.class_name}->{call.name}{call.descriptor}"
                                if caller_info not in [f['details'] for f in findings[category]]:
                                    findings[category].append({
                                        'severity': pattern_info.get('severity', 'Medium'),
                                        'description': pattern_info['desc'],
                                        'details': caller_info
                                    })
                    elif 'api' in pattern_info and 'pattern' in pattern_info: # e.g., Cipher.getInstance with specific algorithm
                        target_methods = dx.find_methods(classname=pattern_info['api'].split(';->')[0], methodname=pattern_info['api'].split(';->')[1])
                        algo_regex = re.compile(pattern_info['pattern'], re.IGNORECASE)
                        for method_analysis in target_methods:
                            for _, call, _ in method_analysis.get_xref_from():
                                # Check parameters passed to the call (requires deeper analysis of instructions)
                                # Basic check: Look for string constants nearby in caller
                                caller_method = dx.get_method(call)
                                if caller_method:
                                    for instruction in caller_method.get_instructions():
                                        if instruction.get_op_code() == 0x1a: # const-string
                                            param_string = instruction.get_string()
                                            if algo_regex.search(param_string):
                                                caller_info = f"{call.class_name}->{call.name}{call.descriptor}"
                                                if caller_info not in [f['details'] for f in findings[category]]:
                                                    findings[category].append({
                                                        'severity': pattern_info.get('severity', 'High'),
                                                        'description': f"{pattern_info['desc']} (Algorithm: {param_string})",
                                                        'details': caller_info
                                                    })
                                                    break # Found relevant param for this call
                    elif 'class' in pattern_info and 'pattern' not in pattern_info: # e.g., Usage of java.util.Random
                         target_classes = dx.find_classes(pattern_info['class'])
                         for class_analysis in target_classes:
                             for _, call, _ in class_analysis.get_xref_from(): # Where is this class used?
                                caller_info = f"{call.class_name}->{call.name}{call.descriptor}"
                                if caller_info not in [f['details'] for f in findings[category]]:
                                     findings[category].append({
                                         'severity': pattern_info.get('severity', 'Low'),
                                         'description': pattern_info['desc'],
                                         'details': caller_info
                                     })
                    elif 'string_pattern' in pattern_info:
                        str_regex = re.compile(pattern_info['string_pattern'])
                        strings = dx.find_strings(str_regex)
                        for string_analysis in strings:
                            # Get usage context if possible
                            usage_info = "In string constant: " + string_analysis.get_value()
                            # Try to find where the string is used (can be complex)
                            # xref_meth = string_analysis.get_xref_from() # Might need adjustment based on Androguard version/API
                            # if xref_meth: usage_info = f"Used in {xref_meth[0][0].class_name}->{xref_meth[0][0].name}"
                            
                            if usage_info not in [f['details'] for f in findings[category]]:
                                findings[category].append({
                                    'severity': pattern_info.get('severity', 'Low'),
                                    'description': pattern_info['desc'],
                                    'details': usage_info
                                })

            # Clean up empty categories
            findings = {k: v for k, v in findings.items() if v}
            return findings
        
        except Exception as e:
            print(f"Error during code pattern analysis: {e}")
            # Return potentially partial findings or empty dict on error
            return {k: v for k, v in findings.items() if v} 

    # detect_trackers remains largely the same, but could also use dx if needed
    def detect_trackers(self, dx):
        detected_trackers = {}
        if not dx:
            return detected_trackers
            
        try:
            # Use dx.get_classes() which is already available
            class_analyses = dx.get_classes()
            class_names = [cls.name.replace('/', '.') for cls in class_analyses]

            for tracker_name, package_prefix in self.tracker_packages.items():
                # Check if any class name starts with the tracker's package prefix
                if any(name.startswith(package_prefix) for name in class_names):
                    # Optionally, find specific methods/classes for confirmation
                    # Example: Find init method of a known tracker class
                    # tracker_init_methods = dx.find_methods(classname=f"^{package_prefix}.*", methodname='<init>')
                    # if tracker_init_methods:
                    detected_trackers[tracker_name] = package_prefix
            
            return detected_trackers
        except Exception as e:
            print(f"Error during tracker detection: {e}")
            return detected_trackers

    def analyze_privacy_leaks(self, dx):
        """Analyze potential privacy leaks in the code"""
        leak_findings = {}
        
        # Analyze data leak patterns
        for category, patterns in self.data_leak_patterns.items():
            findings = []
            for pattern in patterns:
                matches = self._find_api_usage(dx, pattern['class'], pattern['method'])
                for match in matches:
                    # Check if sensitive data is being leaked
                    data_source = self._trace_data_source(dx, match)
                    if data_source:
                        findings.append({
                            'severity': pattern['severity'],
                            'description': pattern['desc'],
                            'location': match,
                            'data_source': data_source
                        })
            if findings:
                leak_findings[category] = findings
        
        return leak_findings

    def _find_api_usage(self, dx, class_name, method_name):
        """Find usage of specific APIs in the code"""
        matches = []
        try:
            target_methods = dx.find_methods(classname=class_name, methodname=method_name)
            for method in target_methods:
                for _, call, _ in method.get_xref_from():
                    matches.append({
                        'class': call.class_name,
                        'method': call.name,
                        'descriptor': call.descriptor
                    })
        except Exception as e:
            print(f"Error finding API usage: {e}")
        return matches

    def _trace_data_source(self, dx, api_call):
        """Trace the source of data being leaked"""
        try:
            method = dx.get_method(f"{api_call['class']}->{api_call['method']}{api_call['descriptor']}")
            if not method:
                return None

            # Look for privacy-sensitive API calls in the method's code
            for category, apis in self.privacy_sensitive_apis.items():
                for api in apis:
                    if self._check_api_in_method(method, api):
                        return {
                            'type': category,
                            'api': api
                        }
            return None
        except Exception as e:
            print(f"Error tracing data source: {e}")
            return None

    def _check_api_in_method(self, method, api_signature):
        """Check if a specific API is used within a method"""
        try:
            class_name, method_name = api_signature.split(';->')
            target_methods = method.get_xref_to()
            return any(
                call.class_name.startswith(class_name) and
                call.name == method_name
                for call in target_methods
            )
        except Exception:
            return False