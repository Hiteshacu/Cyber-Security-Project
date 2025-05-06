class FeatureExtractor:
    def __init__(self):
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
    
    def extract_features(self, permissions):
        dangerous_count = len([p for p in permissions if p in self.dangerous_permissions])
        total_count = len(permissions)
        
        features = {
            'dangerous_permission_count': dangerous_count,
            'total_permission_count': total_count,
            'dangerous_permission_ratio': dangerous_count / max(total_count, 1)
        }
        
        return features