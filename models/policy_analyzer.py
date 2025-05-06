from nltk.tokenize import sent_tokenize, word_tokenize
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np

class PrivacyPolicyAnalyzer:
    def __init__(self):
        self.permission_keywords = {
            'location': ['location', 'gps', 'geographical', 'geo-location'],
            'camera': ['camera', 'photo', 'picture', 'image'],
            'microphone': ['microphone', 'audio', 'voice', 'record'],
            'contacts': ['contacts', 'address book', 'phone book'],
            'storage': ['storage', 'files', 'media', 'documents', 'content'],
            'phone': ['phone', 'call', 'telephone', 'dialer', 'number'],
            'identifiers': ['device id', 'advertising id', 'identifier', 'imei', 'subscriber id']
        }
        # Add action keywords for context
        self.action_keywords = [
            'collect', 'share', 'use', 'process', 'store', 'transfer', 'disclose', 'access', 'obtain'
        ]

        # Add data handling categories
        self.data_handling_categories = {
            'collection': ['collect', 'gather', 'obtain', 'receive', 'acquire'],
            'storage': ['store', 'save', 'retain', 'keep', 'maintain'],
            'processing': ['process', 'analyze', 'use', 'utilize', 'handle'],
            'sharing': ['share', 'disclose', 'transfer', 'provide', 'send'],
            'deletion': ['delete', 'remove', 'erase', 'destroy', 'dispose']
        }

        # Add privacy principles
        self.privacy_principles = {
            'transparency': ['inform', 'notify', 'explain', 'describe', 'clear'],
            'consent': ['consent', 'permission', 'authorize', 'agree', 'opt'],
            'purpose': ['purpose', 'reason', 'goal', 'objective', 'aim'],
            'minimization': ['necessary', 'required', 'essential', 'minimum', 'limit'],
            'security': ['secure', 'protect', 'encrypt', 'safeguard', 'confidential']
        }

        self.lemmatizer = WordNetLemmatizer()
        self.stop_words = set(stopwords.words('english'))
        self.vectorizer = TfidfVectorizer()

    def analyze_policy(self, policy_text, app_permissions):
        # Existing permission analysis
        basic_findings = super().analyze_policy(policy_text, app_permissions)
        
        # Enhanced analysis
        sentences = sent_tokenize(policy_text.lower())
        processed_sentences = self._preprocess_text(sentences)
        
        # Analyze data handling practices
        data_handling = self._analyze_data_handling(processed_sentences)
        
        # Analyze privacy principles
        principles = self._analyze_privacy_principles(processed_sentences)
        
        # Analyze policy completeness
        completeness = self._analyze_completeness(data_handling, principles)
        
        return {
            **basic_findings,
            'data_handling': data_handling,
            'privacy_principles': principles,
            'completeness_score': completeness
        }

    def _preprocess_text(self, sentences):
        """Preprocess text for analysis"""
        processed = []
        for sentence in sentences:
            # Tokenize and lemmatize
            words = word_tokenize(sentence)
            words = [self.lemmatizer.lemmatize(word) for word in words 
                    if word not in self.stop_words and word.isalnum()]
            processed.append(' '.join(words))
        return processed

    def _analyze_data_handling(self, processed_sentences):
        """Analyze data handling practices"""
        findings = {}
        for category, keywords in self.data_handling_categories.items():
            category_sentences = []
            for sentence in processed_sentences:
                if any(keyword in sentence for keyword in keywords):
                    category_sentences.append(sentence)
            
            findings[category] = {
                'present': len(category_sentences) > 0,
                'coverage': len(category_sentences),
                'sentences': category_sentences
            }
        return findings

    def _analyze_privacy_principles(self, processed_sentences):
        """Analyze privacy principles coverage"""
        findings = {}
        for principle, keywords in self.privacy_principles.items():
            principle_sentences = []
            for sentence in processed_sentences:
                if any(keyword in sentence for keyword in keywords):
                    principle_sentences.append(sentence)
            
            findings[principle] = {
                'present': len(principle_sentences) > 0,
                'coverage': len(principle_sentences),
                'sentences': principle_sentences
            }
        return findings

    def _analyze_completeness(self, data_handling, principles):
        """Calculate policy completeness score"""
        data_handling_score = sum(1 for cat in data_handling.values() if cat['present']) / len(self.data_handling_categories)
        principles_score = sum(1 for prin in principles.values() if prin['present']) / len(self.privacy_principles)
        return (data_handling_score + principles_score) / 2

    def generate_advanced_policy(self, permissions, network_data, code_patterns=None):
        """Generate comprehensive privacy policy using advanced analysis"""
        # Analyze permissions and data usage
        data_collection = self._analyze_data_collection(permissions)
        data_usage = self._analyze_data_usage(network_data, code_patterns)
        security_measures = self._generate_security_section(code_patterns)

        policy = f"""Privacy Policy

1. Data Collection and Usage
{data_collection}

2. Data Processing and Storage
{data_usage}

3. Security Measures
{security_measures}

4. Your Rights and Choices
- You can control app permissions through your device settings
- You can request data deletion by contacting us
- You can opt-out of non-essential data collection

5. Updates to This Policy
We may update this privacy policy to reflect changes in our practices. We will notify you of any material changes.
"""
        return policy

    def _analyze_data_collection(self, permissions):
        """Analyze and describe data collection practices"""
        sections = []
        for category, perms in self._group_permissions(permissions).items():
            if perms:
                section = f"\n{category} Data:\n"
                section += "\n".join(f"- {self._describe_permission(p)}" for p in perms)
                sections.append(section)
        return "\n".join(sections)

    def _analyze_data_usage(self, network_data, code_patterns):
        """Analyze and describe data usage practices"""
        usage = ["We process your data for the following purposes:"]
        
        if network_data.get('has_internet_access'):
            usage.append("- To provide online features and services")
        if code_patterns and any('analytics' in p.lower() for p in code_patterns):
            usage.append("- To analyze app performance and improve our services")
        
        return "\n".join(usage)

    def _generate_security_section(self, code_patterns):
        """Generate security measures section based on code analysis"""
        measures = ["We implement appropriate security measures to protect your data:"]
        
        if code_patterns:
            if any('encryption' in p.lower() for p in code_patterns):
                measures.append("- Data encryption in transit and at rest")
            if any('authentication' in p.lower() for p in code_patterns):
                measures.append("- Secure authentication mechanisms")
        
        measures.append("- Regular security assessments and updates")
        return "\n".join(measures)