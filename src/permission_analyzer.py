from androguard.core.bytecodes.apk import APK
import pandas as pd

class PermissionAnalyzer:
    def __init__(self):
        self.dangerous_permissions = [
            'android.permission.READ_CONTACTS',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.CAMERA',
            'android.permission.READ_SMS',
            'android.permission.RECORD_AUDIO'
        ]
    
    def analyze_apk(self, apk_path):
        apk = APK(apk_path)
        permissions = apk.get_permissions()
        
        analysis_result = {
            'total_permissions': len(permissions),
            'dangerous_permissions': self._count_dangerous_permissions(permissions),
            'permission_list': permissions,
            'risk_score': self._calculate_risk_score(permissions)
        }
        
        return analysis_result
    
    def _count_dangerous_permissions(self, permissions):
        return len([p for p in permissions if p in self.dangerous_permissions])
    
    def _calculate_risk_score(self, permissions):
        base_score = len(permissions) * 0.1
        dangerous_score = self._count_dangerous_permissions(permissions) * 0.3
        return min(base_score + dangerous_score, 1.0)