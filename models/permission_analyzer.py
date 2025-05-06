from androguard.core.bytecodes.apk import APK
import pandas as pd

class PermissionAnalyzer:
    # *** CHANGE PARAMETER HERE from apk_path to apk_object ***
    def __init__(self, apk_object):
        # *** Assign the passed APK object directly ***
        self.apk = apk_object 
        # Define dangerous permissions by category
        self.dangerous_permissions = {
            'android.permission.READ_CONTACTS',
            'android.permission.WRITE_CONTACTS',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.ACCESS_COARSE_LOCATION',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.READ_SMS',
            'android.permission.SEND_SMS',
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO'
        }
        
        # Define permission categories separately
        self.permission_categories = {
            'LOCATION': [
                'android.permission.ACCESS_FINE_LOCATION',
                'android.permission.ACCESS_COARSE_LOCATION',
                'android.permission.ACCESS_BACKGROUND_LOCATION'
            ],
            'STORAGE': [
                'android.permission.READ_EXTERNAL_STORAGE',
                'android.permission.WRITE_EXTERNAL_STORAGE',
                'android.permission.MANAGE_EXTERNAL_STORAGE'
            ],
            'CAMERA_MIC': [
                'android.permission.CAMERA',
                'android.permission.RECORD_AUDIO',
                'android.permission.MODIFY_AUDIO_SETTINGS'
            ],
            'PHONE': [
                'android.permission.READ_PHONE_STATE',
                'android.permission.CALL_PHONE',
                'android.permission.READ_CALL_LOG'
            ],
            'CONTACTS': [
                'android.permission.READ_CONTACTS',
                'android.permission.WRITE_CONTACTS',
                'android.permission.GET_ACCOUNTS'
            ]
        }
    
    def get_permissions(self):
        return self.apk.get_permissions()
    
    def get_dangerous_permissions(self):
        return [perm for perm in self.get_permissions() if perm in self.dangerous_permissions]
    
    def get_permission_categories(self):
        app_permissions = self.get_permissions()
        categories = {}
        for category, perms in self.permission_categories.items():
            matches = [p for p in app_permissions if p in perms]
            if matches:
                categories[category] = matches
        return categories
    
    def get_risk_details(self):
        categories = self.get_permission_categories()
        return {
            'category_risks': {
                cat: len(perms) / len(self.permission_categories[cat])
                for cat, perms in categories.items()
            },
            'high_risk_categories': [
                cat for cat, perms in categories.items()
                if len(perms) / len(self.permission_categories[cat]) > 0.7
            ]
        }
    
    def get_permission_risk_score(self):
        dangerous_count = len(self.get_dangerous_permissions())
        total_count = len(self.get_permissions())
        return dangerous_count / max(total_count, 1)
    
    # *** CHANGE PARAMETER HERE from permissions to self (uses self.apk) ***
    def extract_features(self):
        # Get permissions directly using self.apk
        permissions = self.get_permissions()
        
        # Get counts for each category
        categories = self.get_permission_categories() # Uses self.apk internally
        category_counts = {cat: len(perms) for cat, perms in categories.items()}
        
        # Calculate dangerous permissions
        dangerous_perms = self.get_dangerous_permissions() # Uses self.apk internally
        dangerous_count = len(dangerous_perms)
        total_count = len(permissions)
        
        # Create feature dictionary
        features = {
            'dangerous_permission_count': dangerous_count,
            'total_permission_count': total_count,
            'dangerous_permission_ratio': dangerous_count / max(total_count, 1),
            'location_permission_count': category_counts.get('LOCATION', 0),
            'storage_permission_count': category_counts.get('STORAGE', 0),
            'camera_mic_permission_count': category_counts.get('CAMERA_MIC', 0),
            'phone_permission_count': category_counts.get('PHONE', 0),
            'contacts_permission_count': category_counts.get('CONTACTS', 0)
        }
        
        return features