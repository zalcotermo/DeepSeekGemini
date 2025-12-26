#!/usr/bin/env python3
"""
Advanced OSINT Investigation Toolkit
Integrates multiple APIs for comprehensive phone number, IMEI, BSSID, and MAC address investigations
Author: ZALCO SNDK 221 @SALIF
Version: 2.0
"""

import re
import json
import requests
import phonenumbers
import ipaddress
import socket
import time
import sys
import os
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
import urllib.parse
from colorama import init, Fore, Style
import pandas as pd
import folium
from folium import plugins
import webbrowser
from geopy.geocoders import Nominatim
import concurrent.futures
import logging

# Initialize colorama for colored output
init(autoreset=True)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ============================================================================
# API KEYS CONFIGURATION
# ============================================================================

class APIConfig:
    """API Keys Configuration"""
    
    # Phone Number APIs
    NUMVERIFY_API_KEY = "d4356687121b52819a7ea470c6387d5f"
    NUMLOOKUP_API_KEY = "num_live_B6AfEveoFnwe6TIKV2oL8T6KcY10oRLsQ4HzzSvn"
    ABSTRACT_API_KEY = "bdf209a5a133453cbf82f4a0f098773d"
    VERIPHONE_API_KEY = "885174620DD34D3A80B4E57BA05036E3"
    CALLERID_API_KEY = "9973dff9-8e59-4b60-9486-147bbe313bdd"
    
    # Email & Social Media APIs
    HUNTERIO_API_KEY = "374d3258ec737081b981b693ac6590661c87c60d"
    APIFY_API_KEY = "apify_api_YBWWNp1ZhciYjkek4hYXVyvyRFPhri0StD4w"
    SERAPI_API_KEY = "eee2937a45ff20f37c91be7f73f8264ed2b4c07c7e58e6a4348ab84e249ee72b"
    SEARCHAPI_API_KEY = "xt6LQRFE6ZerCgeA97KQLYYg"
    
    # Geolocation & IP APIs
    IPQUALITYSCORE_API_KEY = "ffEazTnuE5Zw2SMmvL3OUw1yPf7UToTV"
    IPGEOLOCATION_API_KEY = "920e2b83bc99495e9bc740b0f3951dfa"
    IPAPI_API_KEY = "4113b2d32abbe2b31921776cdf8de7ab"
    OPENCAGE_API_KEY = "f8c073589bca4d09b09a50e7c600ee10"
    LOCATIONIQ_API_KEY = "pk.acfeb81fc23fd46a33d8d3e54eb4fc9b"
    IP2LOCATION_API_KEY = "36AD7EC66400FBBF8E0FFA4AAEE0F2D8"
    GEOAPIFY_API_KEY = "db320d22a49f42e7b7bd6ccd546b3e12"
    BIGDATACLOUD_API_KEY = "bdc_afb64aea91744a5cb05857e673d824f3"
    
    # Security & Threat Intelligence
    VIRUSTOTAL_API_KEY = "5182a9778e51cdd86961625c88a090023d8f4f9dd9315dfadc76f46bad1978d9"
    
    # Cellular & Network APIs
    OPENCELLID_API_KEY = "1f8f328afa8ba5"
    WIGLE_API_KEY = "2c1d0dfc144073c4fb55b633d0fcf90d"
    
    # Device & Hardware APIs
    MACVENDORS_API_KEY = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiIsImp0aSI6ImI5MmFiNjczLTNmM2QtNDY5ZC04ODFjLWM3MGM1M2FjOGJhYSJ9.eyJpc3MiOiJtYWN2ZW5kb3JzIiwiYXVkIjoibWFjdmVuZG9ycyIs"
    
    # Miscellaneous APIs
    NINJAS_API_KEY = "sUsLXVH/ik6Prq3y82s1JA==MemGS6cWyrR31Qn3"
    NEUTRINO_API_KEY = "zalco:gbGIAK6VmaXNcgZc8iBMsOPuHCIL5tsNbrD5CzTjxNvB6pEs"
    APILAYER_API_KEY = "8rzKF9g70xXyMGQEuOUuVSoZ10Fqu8PG"
    WHOISXML_API_KEY = "at_2oSrnByBCX0A5an8EeacWZyT4Bfx5"
    TWILIO_SID = "ACd3100d53564049dd0cb6a29447000522"
    TWILIO_TOKEN = "ebd67b7bb0571540ee0af523715a7842"
    LOOKIFY_API_KEY = "42c24cb1-b8b3-b198-7116-91b176a6b0e6"
    TRUECALLER_API_KEY = "Ytlb1a08ac5f80a5540beb0e0f2c62e7632af"
    APIVERSE_API_KEY = "ef3fe363-3547-4e2a-8d2b-552ec41d96de"
    LOCALEXPOXE_API_KEY = "uZz8PjGTNTMUfdz1hzdRnFqeOxgkKJeNm25UQsfo"
    ANYAPI_API_KEY = "pgmilo0sk6gdj0u8ddnie5kgta6sqitcs8dojf1jcobmse8boji3o"
    BRIGHTDATA_API_KEY = "1108e1c6-4ab8-42d7-834c-bce26fb7d5d4"

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def print_banner():
    """Print tool banner"""
    banner = f"""
{Fore.CYAN}{'='*80}
{Fore.YELLOW}╔═╗╔═╗╔═╗╦╔╗╔  ╔═╗╔═╗╔═╗╦╔╦╗╔═╗╦═╗
{Fore.YELLOW}║ ╦║╣ ║ ║║║║║  ║  ║ ║╠═╝║ ║ ║╣ ╠╦╝
{Fore.YELLOW}╚═╝╚═╝╚═╝╩╝╚╝  ╚═╝╚═╝╩  ╩ ╩ ╚═╝╩╚═
{Fore.CYAN}{'='*80}
{Fore.GREEN}Advanced OSINT Investigation Toolkit v2.0 Zalco SNDK 221
{Fore.MAGENTA}Phone | Email | IMEI | BSSID | MAC Address | Geolocation
{Fore.CYAN}{'='*80}{Style.RESET_ALL}
    """
    print(banner)

def validate_phone_number(phone_number: str) -> Optional[str]:
    """Validate and format phone number"""
    try:
        parsed = phonenumbers.parse(phone_number, None)
        if phonenumbers.is_valid_number(parsed):
            return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    except:
        pass
    
    # Try to clean and format
    clean_number = re.sub(r'[^\d+]', '', phone_number)
    if clean_number.startswith('00'):
        clean_number = '+' + clean_number[2:]
    elif clean_number.startswith('0'):
        clean_number = '+1' + clean_number[1:]  # Default to US
    
    return clean_number if len(clean_number) > 7 else None

def validate_mac_address(mac: str) -> Optional[str]:
    """Validate MAC address format"""
    mac = mac.upper().replace('-', ':').replace('.', ':')
    if re.match(r'^([0-9A-F]{2}[:]){5}([0-9A-F]{2})$', mac):
        return mac
    return None

def validate_imei(imei: str) -> bool:
    """Validate IMEI number using Luhn algorithm"""
    imei = re.sub(r'\D', '', imei)
    if len(imei) != 15:
        return False
    
    total = 0
    for i, digit in enumerate(imei):
        digit = int(digit)
        if i % 2 == 1:  # Double every second digit
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    
    return total % 10 == 0

# ============================================================================
# API HANDLERS
# ============================================================================

class APIHandler:
    """Handler for all API calls"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def make_request(self, url: str, params: Dict = None, headers: Dict = None, 
                    method: str = 'GET', timeout: int = 10) -> Optional[Dict]:
        """Make API request with error handling"""
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, params=params, headers=headers, timeout=timeout)
            else:
                response = self.session.post(url, json=params, headers=headers, timeout=timeout)
            
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {e}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {e}")
            return None

class PhoneNumberInvestigator:
    """Phone number investigation module"""
    
    def __init__(self, api_handler: APIHandler):
        self.api = api_handler
        self.config = APIConfig()
    
    def numverify_lookup(self, phone_number: str) -> Dict:
        """NumVerify API lookup"""
        url = "http://apilayer.net/api/validate"
        params = {
            'access_key': self.config.NUMVERIFY_API_KEY,
            'number': phone_number,
            'country_code': '',
            'format': 1
        }
        return self.api.make_request(url, params) or {}
    
    def numlookup_lookup(self, phone_number: str) -> Dict:
        """NumLookup API lookup"""
        url = "https://api.numlookupapi.com/v1/validate/"
        headers = {'apikey': self.config.NUMLOOKUP_API_KEY}
        params = {'number': phone_number}
        return self.api.make_request(url, params, headers) or {}
    
    def abstractapi_lookup(self, phone_number: str) -> Dict:
        """Abstract API phone validation"""
        url = f"https://phonevalidation.abstractapi.com/v1/"
        params = {
            'api_key': self.config.ABSTRACT_API_KEY,
            'phone': phone_number
        }
        return self.api.make_request(url, params) or {}
    
    def opencage_geocode(self, lat: float, lon: float) -> Dict:
        """Reverse geocoding with OpenCage"""
        url = "https://api.opencagedata.com/geocode/v1/json"
        params = {
            'key': self.config.OPENCAGE_API_KEY,
            'q': f"{lat}+{lon}",
            'pretty': 1,
            'no_annotations': 1
        }
        return self.api.make_request(url, params) or {}
    
    def twilio_lookup(self, phone_number: str) -> Dict:
        """Twilio phone number lookup"""
        url = f"https://lookups.twilio.com/v2/PhoneNumbers/{phone_number}"
        auth = (self.config.TWILIO_SID, self.config.TWILIO_TOKEN)
        
        try:
            response = requests.get(url, auth=auth, timeout=10)
            return response.json() if response.status_code == 200 else {}
        except:
            return {}
    
    def search_social_media(self, phone_number: str) -> Dict:
        """Search for social media profiles linked to phone number"""
        results = {}
        
        # Search via Apify (Facebook/Instagram)
        try:
            apify_url = "https://api.apify.com/v2/acts/username~facebook-scraper/runs"
            headers = {'Authorization': f'Bearer {self.config.APIFY_API_KEY}'}
            data = {
                'search': phone_number,
                'searchType': 'phone'
            }
            apify_result = self.api.make_request(apify_url, data, headers, 'POST')
            if apify_result:
                results['apify'] = apify_result
        except:
            pass
        
        # Search via SerpAPI
        try:
            serp_url = "https://serpapi.com/search"
            params = {
                'engine': 'google',
                'q': f'"{phone_number}" site:facebook.com OR site:twitter.com OR site:instagram.com',
                'api_key': self.config.SERAPI_API_KEY
            }
            serp_result = self.api.make_request(serp_url, params)
            if serp_result:
                results['serpapi'] = serp_result.get('organic_results', [])
        except:
            pass
        
        return results
    
    def hunterio_email_lookup(self, phone_number: str) -> Dict:
        """Hunter.io email lookup by phone"""
        url = "https://api.hunter.io/v2/email-finder"
        params = {
            'api_key': self.config.HUNTERIO_API_KEY,
            'phone': phone_number
        }
        return self.api.make_request(url, params) or {}
    
    def comprehensive_phone_investigation(self, phone_number: str) -> Dict:
        """Comprehensive phone number investigation"""
        print(f"{Fore.CYAN}[*] Starting comprehensive investigation for: {phone_number}")
        
        results = {
            'phone_number': phone_number,
            'timestamp': datetime.now().isoformat(),
            'validation': {},
            'carrier_info': {},
            'geolocation': {},
            'social_media': {},
            'email_associations': {},
            'threat_intelligence': {},
            'additional_data': {}
        }
        
        # Validate phone number
        print(f"{Fore.YELLOW}[*] Validating phone number...")
        results['validation']['numverify'] = self.numverify_lookup(phone_number)
        results['validation']['numlookup'] = self.numlookup_lookup(phone_number)
        results['validation']['abstract'] = self.abstractapi_lookup(phone_number)
        
        # Get carrier and location info
        print(f"{Fore.YELLOW}[*] Gathering carrier information...")
        valid_data = None
        for source, data in results['validation'].items():
            if data.get('valid', False):
                valid_data = data
                break
        
        if valid_data:
            results['carrier_info'] = {
                'carrier': valid_data.get('carrier', 'Unknown'),
                'country': valid_data.get('country_name', 'Unknown'),
                'country_code': valid_data.get('country_code', 'Unknown'),
                'location': valid_data.get('location', 'Unknown'),
                'line_type': valid_data.get('line_type', 'Unknown')
            }
        
        # Geolocation from IP if available
        if valid_data and valid_data.get('location'):
            print(f"{Fore.YELLOW}[*] Attempting geolocation...")
            try:
                # Use IP geolocation services
                ip_results = self.ip_geolocation(valid_data.get('location'))
                results['geolocation'] = ip_results
            except:
                pass
        
        # Social media search
        print(f"{Fore.YELLOW}[*] Searching social media platforms...")
        results['social_media'] = self.search_social_media(phone_number)
        
        # Email associations
        print(f"{Fore.YELLOW}[*] Searching for associated emails...")
        results['email_associations'] = self.hunterio_email_lookup(phone_number)
        
        # Threat intelligence
        print(f"{Fore.YELLOW}[*] Checking threat intelligence...")
        results['threat_intelligence'] = self.check_phone_reputation(phone_number)
        
        # Generate report
        self.generate_phone_report(results)
        
        return results
    
    def check_phone_reputation(self, phone_number: str) -> Dict:
        """Check phone number reputation"""
        results = {}
        
        # IPQualityScore check
        try:
            url = "https://ipqualityscore.com/api/json/phone"
            params = {
                'key': self.config.IPQUALITYSCORE_API_KEY,
                'phone': phone_number
            }
            iq_result = self.api.make_request(url, params)
            if iq_result:
                results['ipqualityscore'] = iq_result
        except:
            pass
        
        return results
    
    def generate_phone_report(self, data: Dict):
        """Generate formatted report for phone investigation"""
        print(f"\n{Fore.GREEN}{'='*80}")
        print(f"{Fore.GREEN}PHONE NUMBER INVESTIGATION REPORT")
        print(f"{Fore.GREEN}{'='*80}")
        
        phone = data.get('phone_number', 'Unknown')
        print(f"{Fore.CYAN}Target Phone: {Fore.WHITE}{phone}")
        print(f"{Fore.CYAN}Investigation Date: {Fore.WHITE}{data.get('timestamp', 'Unknown')}")
        
        # Validation Results
        print(f"\n{Fore.YELLOW}[VALIDATION RESULTS]")
        for source, result in data.get('validation', {}).items():
            if result:
                valid = result.get('valid', False)
                status = f"{Fore.GREEN}VALID" if valid else f"{Fore.RED}INVALID"
                print(f"  {source.upper()}: {status}")
                if valid:
                    print(f"    Carrier: {result.get('carrier', 'Unknown')}")
                    print(f"    Country: {result.get('country_name', 'Unknown')}")
                    print(f"    Line Type: {result.get('line_type', 'Unknown')}")
        
        # Carrier Information
        carrier_info = data.get('carrier_info', {})
        if carrier_info:
            print(f"\n{Fore.YELLOW}[CARRIER INFORMATION]")
            for key, value in carrier_info.items():
                if value:
                    print(f"  {key.replace('_', ' ').title()}: {value}")
        
        # Social Media Findings
        social_data = data.get('social_media', {})
        if social_data:
            print(f"\n{Fore.YELLOW}[SOCIAL MEDIA FINDINGS]")
            for platform, findings in social_data.items():
                if findings:
                    print(f"  {platform.upper()}: Found {len(findings) if isinstance(findings, list) else 1} result(s)")
        
        # Threat Intelligence
        threats = data.get('threat_intelligence', {})
        if threats:
            print(f"\n{Fore.YELLOW}[THREAT INTELLIGENCE]")
            for source, info in threats.items():
                if info and info.get('fraud_score'):
                    score = info.get('fraud_score', 0)
                    risk = f"{Fore.GREEN}Low Risk" if score < 30 else f"{Fore.YELLOW}Medium Risk" if score < 70 else f"{Fore.RED}High Risk"
                    print(f"  {source}: Fraud Score: {score}/100 - {risk}")
        
        print(f"\n{Fore.GREEN}{'='*80}\n")

class NetworkInvestigator:
    """Network device investigation module (BSSID, MAC, IMEI)"""
    
    def __init__(self, api_handler: APIHandler):
        self.api = api_handler
        self.config = APIConfig()
    
    def mac_address_lookup(self, mac_address: str) -> Dict:
        """MAC address vendor lookup"""
        url = f"https://api.macvendors.com/{mac_address}"
        headers = {'Authorization': f'Bearer {self.config.MACVENDORS_API_KEY}'}
        return self.api.make_request(url, headers=headers) or {}
    
    def bssid_lookup(self, bssid: str) -> Dict:
        """BSSID/WiFi access point lookup"""
        results = {}
        
        # Wigle.net BSSID search
        try:
            wigle_url = "https://api.wigle.net/api/v2/network/search"
            headers = {'Authorization': f'Basic {self.config.WIGLE_API_KEY}'}
            params = {
                'netid': bssid,
                'resultsPerPage': 10
            }
            wigle_result = self.api.make_request(wigle_url, params, headers)
            if wigle_result:
                results['wigle'] = wigle_result
        except:
            pass
        
        return results
    
    def imei_lookup(self, imei: str) -> Dict:
        """IMEI number lookup"""
        if not validate_imei(imei):
            return {'error': 'Invalid IMEI number'}
        
        results = {}
        
        # Ninjas API IMEI lookup
        try:
            url = "https://api.api-ninjas.com/v1/imei"
            headers = {'X-Api-Key': self.config.NINJAS_API_KEY}
            params = {'imei': imei}
            ninjas_result = self.api.make_request(url, params, headers)
            if ninjas_result:
                results['ninjas'] = ninjas_result
        except:
            pass
        
        # Abstract API IMEI validation
        try:
            url = "https://imei.abstractapi.com/v1/"
            params = {
                'api_key': self.config.ABSTRACT_API_KEY,
                'imei': imei
            }
            abstract_result = self.api.make_request(url, params)
            if abstract_result:
                results['abstract'] = abstract_result
        except:
            pass
        
        return results
    
    def opencellid_lookup(self, mcc: int, mnc: int, lac: int, cid: int) -> Dict:
        """Cell tower lookup using OpenCellID"""
        url = "https://opencellid.org/cell/get"
        params = {
            'key': self.config.OPENCELLID_API_KEY,
            'mcc': mcc,
            'mnc': mnc,
            'lac': lac,
            'cellid': cid,
            'format': 'json'
        }
        return self.api.make_request(url, params) or {}
    
    def ip_geolocation(self, ip_address: str) -> Dict:
        """IP address geolocation"""
        results = {}
        
        # IPGeolocation API
        try:
            url = f"https://api.ipgeolocation.io/ipgeo"
            params = {
                'apiKey': self.config.IPGEOLOCATION_API_KEY,
                'ip': ip_address
            }
            geo_result = self.api.make_request(url, params)
            if geo_result:
                results['ipgeolocation'] = geo_result
        except:
            pass
        
        # IP-API.com
        try:
            url = f"http://ip-api.com/json/{ip_address}"
            ipapi_result = self.api.make_request(url)
            if ipapi_result:
                results['ipapi'] = ipapi_result
        except:
            pass
        
        # BigDataCloud
        try:
            url = f"https://api.bigdatacloud.net/data/ip-geolocation"
            params = {
                'key': self.config.BIGDATACLOUD_API_KEY,
                'ip': ip_address
            }
            bdc_result = self.api.make_request(url, params)
            if bdc_result:
                results['bigdatacloud'] = bdc_result
        except:
            pass
        
        return results

class EmailInvestigator:
    """Email investigation module"""
    
    def __init__(self, api_handler: APIHandler):
        self.api = api_handler
        self.config = APIConfig()
    
    def hunterio_verify(self, email: str) -> Dict:
        """Hunter.io email verification"""
        url = "https://api.hunter.io/v2/email-verifier"
        params = {
            'api_key': self.config.HUNTERIO_API_KEY,
            'email': email
        }
        return self.api.make_request(url, params) or {}
    
    def email_reputation_check(self, email: str) -> Dict:
        """Check email reputation"""
        results = {}
        
        # IPQualityScore
        try:
            url = "https://ipqualityscore.com/api/json/email"
            params = {
                'key': self.config.IPQUALITYSCORE_API_KEY,
                'email': email
            }
            iq_result = self.api.make_request(url, params)
            if iq_result:
                results['ipqualityscore'] = iq_result
        except:
            pass
        
        # VirusTotal (if domain)
        domain = email.split('@')[-1]
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            headers = {'x-apikey': self.config.VIRUSTOTAL_API_KEY}
            vt_result = self.api.make_request(url, headers=headers)
            if vt_result:
                results['virustotal'] = vt_result
        except:
            pass
        
        return results
    
    def find_social_media_by_email(self, email: str) -> Dict:
        """Find social media profiles by email"""
        results = {}
        
        # Use Apify for social media search
        try:
            url = "https://api.apify.com/v2/acts/username~social-media-scraper/runs"
            headers = {'Authorization': f'Bearer {self.config.APIFY_API_KEY}'}
            data = {
                'search': email,
                'searchType': 'email'
            }
            apify_result = self.api.make_request(url, data, headers, 'POST')
            if apify_result:
                results['apify'] = apify_result
        except:
            pass
        
        # Search via SerpAPI
        try:
            url = "https://serpapi.com/search"
            params = {
                'engine': 'google',
                'q': f'"{email}" site:facebook.com OR site:twitter.com OR site:linkedin.com',
                'api_key': self.config.SERAPI_API_KEY
            }
            serp_result = self.api.make_request(url, params)
            if serp_result:
                results['serpapi'] = serp_result.get('organic_results', [])
        except:
            pass
        
        return results

class GeolocationTracker:
    """Geolocation and mapping module"""
    
    def __init__(self):
        self.config = APIConfig()
    
    def create_interactive_map(self, locations: List[Dict], output_file: str = "map.html"):
        """Create interactive map with markers"""
        if not locations:
            print(f"{Fore.RED}[!] No locations to map")
            return
        
        # Get center of all locations
        center_lat = sum(loc.get('lat', 0) for loc in locations) / len(locations)
        center_lon = sum(loc.get('lon', 0) for loc in locations) / len(locations)
        
        # Create map
        m = folium.Map(location=[center_lat, center_lon], zoom_start=10)
        
        # Add markers
        for i, loc in enumerate(locations):
            if loc.get('lat') and loc.get('lon'):
                popup_text = f"""
                <b>Location {i+1}</b><br>
                Type: {loc.get('type', 'Unknown')}<br>
                Accuracy: {loc.get('accuracy', 'N/A')}<br>
                Timestamp: {loc.get('timestamp', 'N/A')}<br>
                Source: {loc.get('source', 'Unknown')}
                """
                folium.Marker(
                    [loc['lat'], loc['lon']],
                    popup=folium.Popup(popup_text, max_width=300),
                    tooltip=f"Location {i+1}"
                ).add_to(m)
        
        # Add heatmap if multiple points
        if len(locations) > 1:
            heat_data = [[loc['lat'], loc['lon']] for loc in locations if loc.get('lat') and loc.get('lon')]
            plugins.HeatMap(heat_data).add_to(m)
        
        # Save map
        m.save(output_file)
        print(f"{Fore.GREEN}[+] Interactive map saved to: {output_file}")
        
        # Try to open in browser
        try:
            webbrowser.open(f'file://{os.path.abspath(output_file)}')
        except:
            pass

class AdvancedOSINTTool:
    """Main OSINT investigation tool"""
    
    def __init__(self):
        self.api_handler = APIHandler()
        self.phone_investigator = PhoneNumberInvestigator(self.api_handler)
        self.network_investigator = NetworkInvestigator(self.api_handler)
        self.email_investigator = EmailInvestigator(self.api_handler)
        self.geolocation_tracker = GeolocationTracker()
        
        self.results = {}
        self.investigation_history = []
    
    def run_comprehensive_investigation(self, target: str, target_type: str = 'phone'):
        """Run comprehensive investigation based on target type"""
        print(f"{Fore.CYAN}[*] Starting {target_type} investigation for: {target}")
        
        if target_type == 'phone':
            phone = validate_phone_number(target)
            if phone:
                return self.phone_investigator.comprehensive_phone_investigation(phone)
            else:
                print(f"{Fore.RED}[!] Invalid phone number")
                return {}
        
        elif target_type == 'email':
            return self.investigate_email(target)
        
        elif target_type == 'mac':
            mac = validate_mac_address(target)
            if mac:
                return self.network_investigator.mac_address_lookup(mac)
            else:
                print(f"{Fore.RED}[!] Invalid MAC address")
                return {}
        
        elif target_type == 'bssid':
            return self.network_investigator.bssid_lookup(target)
        
        elif target_type == 'imei':
            if validate_imei(target):
                return self.network_investigator.imei_lookup(target)
            else:
                print(f"{Fore.RED}[!] Invalid IMEI number")
                return {}
        
        elif target_type == 'ip':
            return self.network_investigator.ip_geolocation(target)
        
        else:
            print(f"{Fore.RED}[!] Unknown target type: {target_type}")
            return {}
    
    def investigate_email(self, email: str) -> Dict:
        """Comprehensive email investigation"""
        print(f"{Fore.CYAN}[*] Investigating email: {email}")
        
        results = {
            'email': email,
            'timestamp': datetime.now().isoformat(),
            'verification': {},
            'reputation': {},
            'social_media': {},
            'breaches': {},
            'additional_data': {}
        }
        
        # Verify email
        print(f"{Fore.YELLOW}[*] Verifying email...")
        results['verification'] = self.email_investigator.hunterio_verify(email)
        
        # Check reputation
        print(f"{Fore.YELLOW}[*] Checking reputation...")
        results['reputation'] = self.email_investigator.email_reputation_check(email)
        
        # Find social media
        print(f"{Fore.YELLOW}[*] Searching social media...")
        results['social_media'] = self.email_investigator.find_social_media_by_email(email)
        
        # Generate report
        self.generate_email_report(results)
        
        return results
    
    def generate_email_report(self, data: Dict):
        """Generate formatted email report"""
        print(f"\n{Fore.GREEN}{'='*80}")
        print(f"{Fore.GREEN}EMAIL INVESTIGATION REPORT")
        print(f"{Fore.GREEN}{'='*80}")
        
        email = data.get('email', 'Unknown')
        print(f"{Fore.CYAN}Target Email: {Fore.WHITE}{email}")
        print(f"{Fore.CYAN}Investigation Date: {Fore.WHITE}{data.get('timestamp', 'Unknown')}")
        
        # Verification Results
        verification = data.get('verification', {}).get('data', {})
        if verification:
            print(f"\n{Fore.YELLOW}[VERIFICATION RESULTS]")
            status = verification.get('status', 'unknown')
            status_color = Fore.GREEN if status == 'valid' else Fore.RED if status == 'invalid' else Fore.YELLOW
            print(f"  Status: {status_color}{status.upper()}")
            print(f"  Quality Score: {verification.get('score', 'N/A')}")
            print(f"  Deliverable: {'Yes' if verification.get('deliverable') else 'No'}")
        
        # Reputation
        reputation = data.get('reputation', {})
        if reputation:
            print(f"\n{Fore.YELLOW}[REPUTATION ANALYSIS]")
            for source, info in reputation.items():
                if info and 'fraud_score' in info:
                    score = info.get('fraud_score', 0)
                    risk = f"{Fore.GREEN}Low Risk" if score < 30 else f"{Fore.YELLOW}Medium Risk" if score < 70 else f"{Fore.RED}High Risk"
                    print(f"  {source}: Fraud Score: {score}/100 - {risk}")
        
        # Social Media
        social = data.get('social_media', {})
        if social:
            print(f"\n{Fore.YELLOW}[SOCIAL MEDIA FINDINGS]")
            total_found = 0
            for platform, findings in social.items():
                if findings:
                    count = len(findings) if isinstance(findings, list) else 1
                    total_found += count
                    print(f"  {platform}: {count} profile(s) found")
            print(f"  Total: {total_found} social media profile(s) found")
        
        print(f"\n{Fore.GREEN}{'='*80}\n")
    
    def batch_investigation(self, targets: List[str], target_type: str = 'phone'):
        """Batch investigation of multiple targets"""
        results = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_target = {
                executor.submit(self.run_comprehensive_investigation, target, target_type): target 
                for target in targets
            }
            
            for future in concurrent.futures.as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    result = future.result(timeout=30)
                    results[target] = result
                    print(f"{Fore.GREEN}[+] Completed investigation for: {target}")
                except Exception as e:
                    print(f"{Fore.RED}[!] Failed investigation for {target}: {e}")
                    results[target] = {'error': str(e)}
        
        return results
    
    def export_results(self, data: Dict, format: str = 'json', filename: str = None):
        """Export investigation results"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"osint_investigation_{timestamp}"
        
        if format.lower() == 'json':
            filename += '.json'
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            print(f"{Fore.GREEN}[+] Results exported to: {filename}")
        
        elif format.lower() == 'csv':
            # Flatten data for CSV
            flattened = []
            for key, value in data.items():
                if isinstance(value, dict):
                    flat_row = {'target': key}
                    flat_row.update(value)
                    flattened.append(flat_row)
            
            if flattened:
                filename += '.csv'
                df = pd.DataFrame(flattened)
                df.to_csv(filename, index=False, encoding='utf-8')
                print(f"{Fore.GREEN}[+] Results exported to: {filename}")
        
        elif format.lower() == 'html':
            self.generate_html_report(data, filename + '.html')
        
        else:
            print(f"{Fore.RED}[!] Unsupported export format: {format}")
    
    def generate_html_report(self, data: Dict, filename: str):
        """Generate HTML report"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>OSINT Investigation Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
                .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
                .success { color: #27ae60; }
                .warning { color: #f39c12; }
                .danger { color: #e74c3c; }
                table { width: 100%; border-collapse: collapse; }
                th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
                th { background-color: #f2f2f2; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>OSINT Investigation Report</h1>
                <p>Generated: {timestamp}</p>
            </div>
            
            <div class="section">
                <h2>Summary</h2>
                <p>Total Investigations: {count}</p>
            </div>
            
            {content}
        </body>
        </html>
        """
        
        # Create content sections
        content_sections = []
        for target, results in data.items():
            section = f"""
            <div class="section">
                <h3>Target: {target}</h3>
                <pre>{json.dumps(results, indent=2)}</pre>
            </div>
            """
            content_sections.append(section)
        
        html_content = html_template.format(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            count=len(data),
            content='\n'.join(content_sections)
        )
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"{Fore.GREEN}[+] HTML report generated: {filename}")

# ============================================================================
# MAIN INTERFACE
# ============================================================================

def main():
    """Main interface"""
    print_banner()
    
    tool = AdvancedOSINTTool()
    
    while True:
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"{Fore.YELLOW}MAIN MENU")
        print(f"{Fore.CYAN}{'='*80}")
        print(f"{Fore.GREEN}1. Phone Number Investigation")
        print(f"{Fore.GREEN}2. Email Address Investigation")
        print(f"{Fore.GREEN}3. MAC Address Lookup")
        print(f"{Fore.GREEN}4. BSSID/WiFi Investigation")
        print(f"{Fore.GREEN}5. IMEI Number Lookup")
        print(f"{Fore.GREEN}6. IP Address Geolocation")
        print(f"{Fore.GREEN}7. Batch Investigation")
        print(f"{Fore.GREEN}8. Export Results")
        print(f"{Fore.GREEN}9. Create Interactive Map")
        print(f"{Fore.GREEN}0. Exit")
        print(f"{Fore.CYAN}{'='*80}")
        
        choice = input(f"{Fore.YELLOW}[?] Select option (0-9): ").strip()
        
        if choice == '0':
            print(f"{Fore.CYAN}[*] Exiting...")
            break
        
        elif choice == '1':
            phone = input(f"{Fore.YELLOW}[?] Enter phone number (with country code): ").strip()
            if phone:
                results = tool.run_comprehensive_investigation(phone, 'phone')
                tool.results[phone] = results
        
        elif choice == '2':
            email = input(f"{Fore.YELLOW}[?] Enter email address: ").strip()
            if email:
                results = tool.run_comprehensive_investigation(email, 'email')
                tool.results[email] = results
        
        elif choice == '3':
            mac = input(f"{Fore.YELLOW}[?] Enter MAC address: ").strip()
            if mac:
                results = tool.run_comprehensive_investigation(mac, 'mac')
                tool.results[mac] = results
        
        elif choice == '4':
            bssid = input(f"{Fore.YELLOW}[?] Enter BSSID: ").strip()
            if bssid:
                results = tool.run_comprehensive_investigation(bssid, 'bssid')
                tool.results[bssid] = results
        
        elif choice == '5':
            imei = input(f"{Fore.YELLOW}[?] Enter IMEI number: ").strip()
            if imei:
                results = tool.run_comprehensive_investigation(imei, 'imei')
                tool.results[imei] = results
        
        elif choice == '6':
            ip_addr = input(f"{Fore.YELLOW}[?] Enter IP address: ").strip()
            if ip_addr:
                results = tool.run_comprehensive_investigation(ip_addr, 'ip')
                tool.results[ip_addr] = results
        
        elif choice == '7':
            target_type = input(f"{Fore.YELLOW}[?] Enter target type (phone/email/mac/bssid/imei/ip): ").strip().lower()
            targets_input = input(f"{Fore.YELLOW}[?] Enter targets (comma-separated): ").strip()
            if targets_input and target_type in ['phone', 'email', 'mac', 'bssid', 'imei', 'ip']:
                targets = [t.strip() for t in targets_input.split(',')]
                results = tool.batch_investigation(targets, target_type)
                tool.results.update(results)
        
        elif choice == '8':
            if tool.results:
                format_choice = input(f"{Fore.YELLOW}[?] Export format (json/csv/html): ").strip().lower()
                filename = input(f"{Fore.YELLOW}[?] Output filename (without extension): ").strip()
                tool.export_results(tool.results, format_choice, filename)
            else:
                print(f"{Fore.RED}[!] No results to export")
        
        elif choice == '9':
            # Create map from collected locations
            locations = []
            for target, data in tool.results.items():
                if isinstance(data, dict):
                    # Extract location data from various formats
                    geo_data = data.get('geolocation', {})
                    if geo_data:
                        for source, geo_info in geo_data.items():
                            if geo_info and 'latitude' in geo_info and 'longitude' in geo_info:
                                locations.append({
                                    'lat': float(geo_info['latitude']),
                                    'lon': float(geo_info['longitude']),
                                    'type': 'geolocation',
                                    'source': source,
                                    'target': target
                                })
            
            if locations:
                tool.geolocation_tracker.create_interactive_map(locations)
            else:
                print(f"{Fore.RED}[!] No location data available for mapping")
        
        else:
            print(f"{Fore.RED}[!] Invalid option")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[!] Unexpected error: {e}")
        logger.exception("Unexpected error occurred")
        sys.exit(1)
