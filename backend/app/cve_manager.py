import json
import csv
import requests
from datetime import datetime
from typing import Dict, List, Any, Optional
import re
import os

class CVEManager:
    def __init__(self):
        self.cve_data_path = "./data/cve_data.json"
        self.cve_cache = {}
        self.load_cve_data()
    
    def load_cve_data(self):
        """Load CVE data from local cache or create sample data"""
        if os.path.exists(self.cve_data_path):
            try:
                with open(self.cve_data_path, 'r') as f:
                    self.cve_cache = json.load(f)
            except Exception as e:
                print(f"Error loading CVE data: {e}")
                self.create_sample_cve_data()
        else:
            self.create_sample_cve_data()
    
    def create_sample_cve_data(self):
        """Create sample CVE data for common services"""
        sample_cves = {
            "ssh": [
                {
                    "cve_id": "CVE-2023-38408",
                    "service": "OpenSSH",
                    "affected_versions": ["< 9.3p2"],
                    "severity": "high",
                    "cvss_score": 7.5,
                    "description": "OpenSSH before 9.3p2 has a double-free vulnerability in ssh-add",
                    "exploit_available": False
                },
                {
                    "cve_id": "CVE-2023-25136",
                    "service": "OpenSSH",
                    "affected_versions": ["< 9.2p1"],
                    "severity": "medium",
                    "cvss_score": 6.5,
                    "description": "OpenSSH server has a memory corruption vulnerability",
                    "exploit_available": False
                }
            ],
            "http": [
                {
                    "cve_id": "CVE-2023-44487",
                    "service": "Apache HTTP Server",
                    "affected_versions": ["< 2.4.58"],
                    "severity": "high",
                    "cvss_score": 7.5,
                    "description": "HTTP/2 Rapid Reset attack vulnerability",
                    "exploit_available": True
                },
                {
                    "cve_id": "CVE-2023-27522",
                    "service": "Apache HTTP Server",
                    "affected_versions": ["2.4.53", "2.4.54", "2.4.55", "2.4.56"],
                    "severity": "critical",
                    "cvss_score": 9.8,
                    "description": "HTTP Request Smuggling vulnerability",
                    "exploit_available": True
                }
            ],
            "https": [
                {
                    "cve_id": "CVE-2023-44487",
                    "service": "Apache HTTP Server",
                    "affected_versions": ["< 2.4.58"],
                    "severity": "high",
                    "cvss_score": 7.5,
                    "description": "HTTP/2 Rapid Reset attack vulnerability",
                    "exploit_available": True
                }
            ],
            "mysql": [
                {
                    "cve_id": "CVE-2023-22084",
                    "service": "MySQL Server",
                    "affected_versions": ["8.0.34", "8.1.0"],
                    "severity": "medium",
                    "cvss_score": 4.9,
                    "description": "MySQL Server vulnerability allows low privileged attacker to compromise server",
                    "exploit_available": False
                }
            ],
            "ftp": [
                {
                    "cve_id": "CVE-2023-22809",
                    "service": "vsftpd",
                    "affected_versions": ["< 3.0.5"],
                    "severity": "high",
                    "cvss_score": 8.1,
                    "description": "vsftpd has a memory disclosure vulnerability",
                    "exploit_available": False
                }
            ]
        }
        
        self.cve_cache = sample_cves
        os.makedirs(os.path.dirname(self.cve_data_path), exist_ok=True)
        
        try:
            with open(self.cve_data_path, 'w') as f:
                json.dump(sample_cves, f, indent=2)
        except Exception as e:
            print(f"Error saving CVE data: {e}")
    
    def match_vulnerabilities(self, service: str, version: str = None) -> List[Dict[str, Any]]:
        """Match service and version against CVE database"""
        service_lower = service.lower()
        vulnerabilities = []
        
        service_mappings = {
            "ssh": ["ssh", "openssh"],
            "http": ["http", "apache", "httpd", "nginx"],
            "https": ["https", "apache", "httpd", "nginx"],
            "mysql": ["mysql"],
            "ftp": ["ftp", "vsftpd", "proftpd"]
        }
        
        matched_service = None
        for cve_service, aliases in service_mappings.items():
            if any(alias in service_lower for alias in aliases):
                matched_service = cve_service
                break
        
        if matched_service and matched_service in self.cve_cache:
            for cve in self.cve_cache[matched_service]:
                vulnerability = cve.copy()
                vulnerability["matched_service"] = service
                vulnerability["matched_version"] = version
                
                if version:
                    vulnerability["version_vulnerable"] = self.check_version_vulnerable(version, cve.get("affected_versions", []))
                else:
                    vulnerability["version_vulnerable"] = "unknown"
                
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def check_version_vulnerable(self, version: str, affected_versions: List[str]) -> str:
        """Check if a specific version is vulnerable based on affected version patterns"""
        if not version or not affected_versions:
            return "unknown"
        
        version_clean = re.sub(r'[^\d.]', '', version)
        
        for affected in affected_versions:
            if "< " in affected:
                max_version = affected.replace("< ", "").strip()
                if self.compare_versions(version_clean, max_version) < 0:
                    return "vulnerable"
            elif version_clean in affected:
                return "vulnerable"
        
        return "not_vulnerable"
    
    def compare_versions(self, v1: str, v2: str) -> int:
        """Compare two version strings. Returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2"""
        try:
            v1_parts = [int(x) for x in v1.split('.')]
            v2_parts = [int(x) for x in v2.split('.')]
            
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            
            for i in range(max_len):
                if v1_parts[i] < v2_parts[i]:
                    return -1
                elif v1_parts[i] > v2_parts[i]:
                    return 1
            
            return 0
        except:
            return 0
    
    def get_risk_assessment(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate risk assessment based on found vulnerabilities"""
        if not vulnerabilities:
            return {
                "overall_risk": "low",
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "exploit_available_count": 0
            }
        
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        exploit_count = 0
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "low")
            severity_counts[severity] += 1
            
            if vuln.get("exploit_available", False):
                exploit_count += 1
        
        if severity_counts["critical"] > 0:
            overall_risk = "critical"
        elif severity_counts["high"] > 0:
            overall_risk = "high"
        elif severity_counts["medium"] > 0:
            overall_risk = "medium"
        else:
            overall_risk = "low"
        
        return {
            "overall_risk": overall_risk,
            "critical_count": severity_counts["critical"],
            "high_count": severity_counts["high"],
            "medium_count": severity_counts["medium"],
            "low_count": severity_counts["low"],
            "exploit_available_count": exploit_count,
            "total_vulnerabilities": len(vulnerabilities)
        }

cve_manager = CVEManager()
