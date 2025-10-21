import requests
import whois
import ssl
import socket
from urllib.parse import urlparse
import re
from datetime import datetime
import time
import warnings
warnings.filterwarnings('ignore')

class FakeWebsiteDetector:
    def __init__(self):
        self.suspicious_keywords = [
            'login', 'secure', 'verify', 'account', 'bank', 'paypal', 
            'facebook', 'google', 'amazon', 'microsoft', 'netflix',
            'official', 'security', 'update', 'confirm', 'authenticate'
        ]
        
        self.trusted_tlds = ['.com', '.org', '.net', '.edu', '.gov']
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top']
    
    def analyze_website(self, url):
        """
        Comprehensive analysis of a website to detect potential fakes
        """
        print(f"\n🔍 Analyzing: {url}")
        print("=" * 60)
        
        results = {
            'url': url,
            'risk_score': 0,
            'warnings': [],
            'details': {}
        }
        
        # 1. URL Analysis
        url_analysis = self.analyze_url(url)
        results['risk_score'] += url_analysis['risk_score']
        results['warnings'].extend(url_analysis['warnings'])
        results['details']['url_analysis'] = url_analysis
        
        # 2. SSL Certificate Check
        ssl_analysis = self.check_ssl_certificate(url)
        results['risk_score'] += ssl_analysis['risk_score']
        results['warnings'].extend(ssl_analysis['warnings'])
        results['details']['ssl_analysis'] = ssl_analysis
        
        # 3. WHOIS Lookup
        whois_analysis = self.whois_lookup(url)
        results['risk_score'] += whois_analysis['risk_score']
        results['warnings'].extend(whois_analysis['warnings'])
        results['details']['whois_analysis'] = whois_analysis
        
        # 4. Content Analysis
        content_analysis = self.analyze_website_content(url)
        results['risk_score'] += content_analysis['risk_score']
        results['warnings'].extend(content_analysis['warnings'])
        results['details']['content_analysis'] = content_analysis
        
        # 5. Domain Age Analysis
        domain_analysis = self.analyze_domain_age(url)
        results['risk_score'] += domain_analysis['risk_score']
        results['warnings'].extend(domain_analysis['warnings'])
        results['details']['domain_analysis'] = domain_analysis
        
        return results
    
    def analyze_url(self, url):
        """Analyze URL structure for suspicious patterns"""
        analysis = {'risk_score': 0, 'warnings': []}
        
        try:
            parsed = urlparse(url)
            
            # Check for IP address instead of domain
            if re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc):
                analysis['risk_score'] += 30
                analysis['warnings'].append("❌ URL uses IP address instead of domain name")
            
            # Check URL length
            if len(url) > 75:
                analysis['risk_score'] += 15
                analysis['warnings'].append("⚠️ URL is unusually long (common in phishing)")
            
            # Check for suspicious characters
            if '@' in url or '//' in url.split('://')[1]:
                analysis['risk_score'] += 25
                analysis['warnings'].append("❌ URL contains suspicious characters (@ or double //)")
            
            # Check TLD
            domain = parsed.netloc.lower()
            for tld in self.suspicious_tlds:
                if domain.endswith(tld):
                    analysis['risk_score'] += 20
                    analysis['warnings'].append(f"⚠️ Suspicious TLD detected: {tld}")
            
            # Check for brand names in subdomains
            for keyword in self.suspicious_keywords:
                if keyword in domain and not any(brand in domain for brand in ['google', 'microsoft', 'amazon']):
                    analysis['risk_score'] += 10
                    analysis['warnings'].append(f"⚠️ Brand name '{keyword}' used in domain")
            
            # Check for hyphen count
            if domain.count('-') > 3:
                analysis['risk_score'] += 15
                analysis['warnings'].append("⚠️ Too many hyphens in domain name")
                
        except Exception as e:
            analysis['warnings'].append(f"❌ URL analysis failed: {str(e)}")
        
        return analysis
    
    def check_ssl_certificate(self, url):
        """Check SSL certificate validity"""
        analysis = {'risk_score': 0, 'warnings': []}
        
        try:
            parsed = urlparse(url)
            hostname = parsed.netloc
            
            if parsed.scheme != 'https':
                analysis['risk_score'] += 40
                analysis['warnings'].append("❌ No HTTPS connection - major security risk!")
                return analysis
            
            # Create SSL context
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expire_date - datetime.now()).days
                    
                    if days_until_expiry < 30:
                        analysis['risk_score'] += 20
                        analysis['warnings'].append(f"⚠️ SSL certificate expires soon: {days_until_expiry} days")
                    
                    # Check subject
                    subject = dict(x[0] for x in cert['subject'])
                    if 'organizationName' not in subject:
                        analysis['risk_score'] += 10
                        analysis['warnings'].append("⚠️ No organization name in SSL certificate")
                        
        except ssl.SSLCertVerificationError:
            analysis['risk_score'] += 50
            analysis['warnings'].append("❌ SSL certificate verification failed!")
        except Exception as e:
            analysis['risk_score'] += 30
            analysis['warnings'].append(f"⚠️ SSL check incomplete: {str(e)}")
        
        return analysis
    
    def whois_lookup(self, url):
        """Perform WHOIS lookup for domain information"""
        analysis = {'risk_score': 0, 'warnings': []}
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            
            # Remove www prefix if present
            if domain.startswith('www.'):
                domain = domain[4:]
            
            whois_info = whois.whois(domain)
            
            # Check domain creation date
            if whois_info.creation_date:
                if isinstance(whois_info.creation_date, list):
                    creation_date = whois_info.creation_date[0]
                else:
                    creation_date = whois_info.creation_date
                
                domain_age = (datetime.now() - creation_date).days
                
                if domain_age < 30:
                    analysis['risk_score'] += 30
                    analysis['warnings'].append(f"❌ Domain is very new: {domain_age} days old")
                elif domain_age < 365:
                    analysis['risk_score'] += 15
                    analysis['warnings'].append(f"⚠️ Domain is relatively new: {domain_age} days old")
                else:
                    analysis['warnings'].append(f"✅ Domain age: {domain_age} days (trustworthy)")
            
            # Check registrar
            if whois_info.registrar:
                analysis['details'] = f"Registrar: {whois_info.registrar}"
            else:
                analysis['risk_score'] += 10
                analysis['warnings'].append("⚠️ No registrar information available")
                
        except Exception as e:
            analysis['risk_score'] += 10
            analysis['warnings'].append(f"⚠️ WHOIS lookup failed: {str(e)}")
        
        return analysis
    
    def analyze_website_content(self, url):
        """Analyze website content for suspicious patterns"""
        analysis = {'risk_score': 0, 'warnings': []}
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(url, headers=headers, timeout=15, verify=False)
            content = response.text.lower()
            
            # Check for login forms
            if 'password' in content and ('input' in content or 'form' in content):
                analysis['risk_score'] += 10
                analysis['warnings'].append("⚠️ Login/password form detected")
            
            # Check for suspicious keywords in content
            suspicious_content_keywords = [
                'verify your account', 'security alert', 'suspicious activity',
                'update your information', 'confirm your identity'
            ]
            
            for keyword in suspicious_content_keywords:
                if keyword in content:
                    analysis['risk_score'] += 15
                    analysis['warnings'].append(f"⚠️ Suspicious content: '{keyword}'")
            
            # Check for poor grammar or spelling errors (basic check)
            if 'log in' not in content and 'login' in content:
                analysis['risk_score'] += 5
                analysis['warnings'].append("⚠️ Potential spelling/grammar issues")
            
            # Check response headers
            server_header = response.headers.get('Server', '').lower()
            if 'apache' not in server_header and 'nginx' not in server_header:
                analysis['risk_score'] += 5
                analysis['warnings'].append(f"⚠️ Unusual server header: {server_header}")
                
        except requests.exceptions.RequestException as e:
            analysis['risk_score'] += 20
            analysis['warnings'].append(f"❌ Could not fetch website content: {str(e)}")
        
        return analysis
    
    def analyze_domain_age(self, url):
        """Additional domain age and reputation analysis"""
        analysis = {'risk_score': 0, 'warnings': []}
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            
            # Simple domain reputation check based on patterns
            if re.search(r'\d{3,}', domain):  # Multiple numbers in domain
                analysis['risk_score'] += 15
                analysis['warnings'].append("⚠️ Domain contains multiple numbers")
            
            # Check for domain mimicking (typosquatting)
            popular_domains = ['google', 'facebook', 'amazon', 'paypal', 'microsoft']
            for popular in popular_domains:
                if popular in domain and domain != popular + '.com':
                    analysis['risk_score'] += 25
                    analysis['warnings'].append(f"❌ Possible typosquatting: mimicking {popular}")
                    
        except Exception as e:
            analysis['warnings'].append(f"⚠️ Domain analysis incomplete: {str(e)}")
        
        return analysis
    
    def generate_report(self, results):
        """Generate comprehensive report"""
        print("\n" + "=" * 60)
        print("📊 FAKE WEBSITE DETECTION REPORT")
        print("=" * 60)
        
        risk_score = results['risk_score']
        
        print(f"🔗 URL: {results['url']}")
        print(f"🎯 RISK SCORE: {risk_score}/200")
        
        if risk_score >= 100:
            print("🚨 HIGH RISK - This website is likely FAKE!")
        elif risk_score >= 60:
            print("⚠️ MEDIUM RISK - Be cautious with this website")
        elif risk_score >= 30:
            print("🔶 LOW RISK - Some suspicious elements detected")
        else:
            print("✅ LOW RISK - Website appears legitimate")
        
        print("\n🔍 DETAILED FINDINGS:")
        print("-" * 40)
        
        for warning in results['warnings']:
            print(warning)
        
        # Show breakdown by category
        print("\n📈 RISK BREAKDOWN:")
        print("-" * 40)
        categories = ['url_analysis', 'ssl_analysis', 'whois_analysis', 'content_analysis', 'domain_analysis']
        category_names = ['URL Analysis', 'SSL Check', 'WHOIS Lookup', 'Content Analysis', 'Domain Analysis']
        
        for category, name in zip(categories, category_names):
            score = results['details'][category]['risk_score']
            print(f"{name}: {score} points")
        
        print(f"\n💡 RECOMMENDATION:")
        if risk_score >= 100:
            print("DO NOT proceed with this website. It shows strong signs of being fake.")
        elif risk_score >= 60:
            print("Be very cautious. Verify through official channels before proceeding.")
        else:
            print("Website appears relatively safe, but always practice good security habits.")

def main():
    """Main function to run the fake website detector"""
    detector = FakeWebsiteDetector()
    
    print("🕵️ FAKE WEBSITE DETECTOR")
    print("=" * 50)
    
    while True:
        print("\nOptions:")
        print("1. Check single website")
        print("2. Check multiple websites")
        print("3. Exit")
        
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == '1':
            url = input("Enter website URL: ").strip()
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            try:
                results = detector.analyze_website(url)
                detector.generate_report(results)
            except Exception as e:
                print(f"❌ Error analyzing website: {str(e)}")
        
        elif choice == '2':
            urls = input("Enter websites (comma-separated): ").strip().split(',')
            for url in urls:
                url = url.strip()
                if not url.startswith(('http://', 'https://')):
                    url = 'https://' + url
                
                try:
                    results = detector.analyze_website(url)
                    detector.generate_report(results)
                    print("\n" + "="*50)
                    time.sleep(2)  # Delay between checks
                except Exception as e:
                    print(f"❌ Error analyzing {url}: {str(e)}")
        
        elif choice == '3':
            print("👋 Goodbye! Stay safe online!")
            break
        
        else:
            print("❌ Invalid choice. Please try again.")

if __name__ == "__main__":
    # Install required packages first:
    # pip install requests python-whois
    
    main()