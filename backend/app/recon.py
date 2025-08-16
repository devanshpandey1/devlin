import asyncio
import json
import socket
import requests
from datetime import datetime
from typing import Dict, List, Any
import uuid
import re
from urllib.parse import urljoin, urlparse

class ReconEngine:
    def __init__(self):
        self.common_subdomains = [
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk", 
            "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test", 
            "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3", 
            "mail2", "new", "mysql", "old", "www1", "email", "img", "www3", "help", "shop"
        ]
        
        self.common_directories = [
            "admin", "administrator", "login", "wp-admin", "phpmyadmin", "cpanel", "webmail",
            "backup", "test", "dev", "staging", "api", "v1", "v2", "docs", "documentation",
            "config", "conf", "tmp", "temp", "uploads", "files", "images", "img", "css",
            "js", "scripts", "includes", "lib", "libs", "vendor", "assets", "static",
            "public", "private", "secure", "hidden", "secret", "old", "new", "beta"
        ]

    async def subdomain_enumeration(self, domain: str, progress_callback=None) -> Dict[str, Any]:
        """Enumerate subdomains using DNS resolution"""
        results = {
            "domain": domain,
            "subdomains": [],
            "total_checked": 0,
            "found_count": 0
        }
        
        total_subdomains = len(self.common_subdomains)
        
        for i, subdomain in enumerate(self.common_subdomains):
            full_domain = f"{subdomain}.{domain}"
            
            try:
                ip = socket.gethostbyname(full_domain)
                results["subdomains"].append({
                    "subdomain": full_domain,
                    "ip": ip,
                    "status": "resolved"
                })
                results["found_count"] += 1
            except socket.gaierror:
                pass
            
            results["total_checked"] += 1
            
            if progress_callback:
                progress = int((i + 1) / total_subdomains * 100)
                await progress_callback(progress)
            
            await asyncio.sleep(0.1)
        
        return results

    async def directory_fuzzing(self, target_url: str, progress_callback=None) -> Dict[str, Any]:
        """Fuzz directories using common directory names"""
        results = {
            "target": target_url,
            "directories": [],
            "total_checked": 0,
            "found_count": 0
        }
        
        parsed_url = urlparse(target_url)
        if not parsed_url.scheme:
            target_url = f"http://{target_url}"
        
        total_dirs = len(self.common_directories)
        
        for i, directory in enumerate(self.common_directories):
            test_url = urljoin(target_url, directory)
            
            try:
                response = requests.get(test_url, timeout=5, allow_redirects=False)
                if response.status_code in [200, 301, 302, 403]:
                    results["directories"].append({
                        "path": f"/{directory}",
                        "url": test_url,
                        "status_code": response.status_code,
                        "content_length": len(response.content)
                    })
                    results["found_count"] += 1
            except requests.RequestException:
                pass
            
            results["total_checked"] += 1
            
            if progress_callback:
                progress = int((i + 1) / total_dirs * 100)
                await progress_callback(progress)
            
            await asyncio.sleep(0.2)
        
        return results

    async def technology_detection(self, target_url: str, progress_callback=None) -> Dict[str, Any]:
        """Detect web technologies using HTTP headers and response analysis"""
        results = {
            "target": target_url,
            "technologies": [],
            "headers": {},
            "server_info": {}
        }
        
        parsed_url = urlparse(target_url)
        if not parsed_url.scheme:
            target_url = f"http://{target_url}"
        
        try:
            if progress_callback:
                await progress_callback(25)
            
            response = requests.get(target_url, timeout=10, allow_redirects=True)
            results["headers"] = dict(response.headers)
            
            if progress_callback:
                await progress_callback(50)
            
            server = response.headers.get('Server', '')
            if server:
                results["server_info"]["server"] = server
                results["technologies"].append({
                    "name": "Web Server",
                    "version": server,
                    "confidence": "high"
                })
            
            if progress_callback:
                await progress_callback(75)
            
            content = response.text.lower()
            
            tech_patterns = {
                "WordPress": r"wp-content|wp-includes|wordpress",
                "Drupal": r"drupal|sites/default",
                "Joomla": r"joomla|option=com_",
                "Apache": r"apache",
                "Nginx": r"nginx",
                "PHP": r"\.php|x-powered-by.*php",
                "ASP.NET": r"aspnet|__viewstate",
                "jQuery": r"jquery",
                "Bootstrap": r"bootstrap",
                "React": r"react|reactjs"
            }
            
            for tech, pattern in tech_patterns.items():
                if re.search(pattern, content) or re.search(pattern, str(results["headers"]).lower()):
                    results["technologies"].append({
                        "name": tech,
                        "version": "detected",
                        "confidence": "medium"
                    })
            
            if progress_callback:
                await progress_callback(100)
                
        except requests.RequestException as e:
            results["error"] = str(e)
        
        return results

recon_engine = ReconEngine()
