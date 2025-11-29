import requests
import socket
import time
import random
import json
import sys
import re
import os
import dns.resolver
import ssl
import certifi
from urllib.parse import urlparse, urljoin, quote
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from datetime import datetime
import yaml
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
import urllib3
from jinja2 import Template
import pdfkit
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# تنظیمات لاگ‌گیری
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_scanner.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)

class AdvancedSecurityScanner:
    def __init__(self, max_threads=5, delay_range=(1, 3), timeout=10):
        self.vulnerabilities = []
        self.scan_results = {}
        self.session = requests.Session()
        self.max_threads = max_threads
        self.delay_range = delay_range
        self.timeout = timeout
        self.set_random_user_agent()
        self.legal_warning_displayed = {}
        self.allowed_domains = []
        self.proxy_config = None
        self.auth_config = None
        self.driver = None
        self.performance_metrics = {}
        self.waf_detected = False

    def display_legal_warning(self, target_url):
        """نمایش هشدار قانونی برای هر URL"""
        if target_url not in self.legal_warning_displayed:
            warning = f"""
            ⚠️  هشدار قانونی و اخلاقی ⚠️

            استفاده از این اسکنر بدون مجوز کتبی از مالک سایت غیرقانونی است.

            هدف اسکن: {target_url}

            تأیید می‌کنید که مجوز دارید؟ (y/n)
            """
            print(warning)
            choice = input().strip().lower()
            if choice != 'y':
                sys.exit(0)
            self.legal_warning_displayed[target_url] = True

    def set_random_user_agent(self):
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1'
        ]
        self.session.headers.update({
            'User-Agent': random.choice(user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        })

    def set_proxy(self, proxy_url):
        self.session.proxies = {'http': proxy_url, 'https': proxy_url}
        print(f"پروکسی تنظیم شد: {proxy_url}")

    def login(self, login_url, username_field, password_field, username, password):
        login_data = {username_field: username, password_field: password}
        try:
            response = self.session.post(login_url, data=login_data, timeout=self.timeout)
            if "logout" in response.text.lower() or response.status_code == 200:
                print("✅ لاگین موفقیت‌آمیز بود")
                return True
            return False
        except Exception as e:
            print(f"❌ خطا در لاگین: {str(e)}")
            return False

    def init_selenium_driver(self):
        if self.driver is None:
            try:
                options = Options()
                options.add_argument("--headless")
                options.add_argument("--no-sandbox")
                options.add_argument("--disable-dev-shm-usage")
                options.add_argument("--disable-gpu")  # برای رفع خطاهای GPU
                options.add_argument(f"user-agent={self.session.headers['User-Agent']}")
                self.driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
                self.driver.set_page_load_timeout(30)
                return True
            except Exception as e:
                logging.error(f"خطا در Selenium: {str(e)}")
                return False

    def close_resources(self):
        if self.driver:
            self.driver.quit()
            self.driver = None
        self.session.close()

    def safe_request(self, url, method='GET', data=None, headers=None, timeout=None, allow_redirects=True):
        if timeout is None:
            timeout = self.timeout
        try:
            delay = random.uniform(*self.delay_range)
            time.sleep(delay)
            request_headers = self.session.headers.copy()
            if headers:
                request_headers.update(headers)
            if method.upper() == 'GET':
                response = self.session.get(url, headers=request_headers, timeout=timeout, verify=certifi.where(), allow_redirects=allow_redirects)
            elif method.upper() == 'POST':
                response = self.session.post(url, data=data, headers=request_headers, timeout=timeout, verify=certifi.where(), allow_redirects=allow_redirects)
            else:
                response = self.session.request(method, url, data=data, headers=request_headers, timeout=timeout, verify=certifi.where(), allow_redirects=allow_redirects)
            if response.status_code == 429:
                logging.warning(f"Too Many Requests برای {url}")
                time.sleep(10)
                return self.safe_request(url, method, data, headers, timeout, allow_redirects)
            return response
        except requests.exceptions.SSLError as e:
            logging.error(f"خطای SSL: {str(e)}")
            return None
        except requests.exceptions.Timeout:
            logging.warning(f"Timeout: {url}")
            return None
        except requests.exceptions.ConnectionError:
            logging.error(f"خطای اتصال: {url}")
            return None
        except requests.exceptions.RequestException as e:
            logging.error(f"خطای درخواست: {str(e)}")
            return None

    def is_domain_allowed(self, domain):
        return not self.allowed_domains or domain in self.allowed_domains

    def load_config(self, config_file='scanner_config.yaml'):
        if not os.path.exists(config_file):
            default_config = {
                'max_threads': 5,
                'delay_range': [1, 3],
                'timeout': 10,
                'allowed_domains': [],
                'proxy': None,
                'authentication': None
            }
            with open(config_file, 'w', encoding='utf-8') as f:
                yaml.dump(default_config, f, allow_unicode=True)
            print(f"فایل config نمونه ایجاد شد: {config_file}")
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            self.max_threads = config.get('max_threads', 5)
            self.delay_range = tuple(config.get('delay_range', [1, 3]))
            self.allowed_domains = config.get('allowed_domains', [])
            self.timeout = config.get('timeout', 10)
            if config.get('proxy'):
                self.set_proxy(config['proxy'])
            self.auth_config = config.get('authentication')
            return True
        except Exception as e:
            logging.error(f"خطا در config: {str(e)}")
            return False

    def detect_waf(self, url):
        print("🔍 بررسی WAF (فایروال وب)...")
        waf_signatures = {
            'Cloudflare': ['cf-ray', 'cloudflare'],
            'Akamai': ['akamai', 'x-akamai'],
            'Imperva': ['x-iinfo', 'incapsula'],
            'AWS WAF': ['x-amzn-waf']
        }
        response = self.safe_request(url)
        if response:
            headers = response.headers
            content = response.text.lower()
            for waf, signatures in waf_signatures.items():
                if any(sig in headers or sig in content for sig in signatures):
                    self.waf_detected = True
                    self.scan_results['waf'] = f"🔒 WAF شناسایی شد: {waf}. این می‌تونه اسکن رو محدود کنه (قدرت تأثیر: متوسط، ممکنه درخواست‌ها رو بلاک کنه)."
                    return
        self.scan_results['waf'] = "✅ هیچ WAF شناخته‌شده‌ای نیست. اسکن کامل‌تر انجام می‌شه (قدرت تأثیر: کم)."

    def explain_check(self, check_name, description, impact):
        print(f"📝 بررسی: {check_name}\nتوضیح: {description}\nتأثیر احتمالی: {impact}")

    def scan_website(self, url):
        if not url.startswith('http'):
            url = 'http://' + url
        parsed_url = urlparse(url)
        domain = parsed_url.hostname
        if not self.is_domain_allowed(domain):
            print(f"❌ دامنه {domain} مجاز نیست.")
            return None
        self.display_legal_warning(url)
        if self.auth_config:
            self.login(self.auth_config['login_url'], self.auth_config['username_field'], self.auth_config['password_field'], self.auth_config['username'], self.auth_config['password'])
        print(f"🚀 شروع اسکن برای: {url}")
        logging.info(f"شروع اسکن برای: {url}")
        self.detect_waf(url)
        self.init_selenium_driver()
        checks = [
            self.check_dns_security,
            self.check_ssl_tls,
            self.check_security_headers,
            self.check_exposed_files,
            self.check_sql_injection,
            self.check_xss,
            self.check_csrf,
            self.check_file_inclusion,
            self.check_open_ports,
            self.check_info_leakage,
            self.check_admin_pages,
            self.check_cors_misconfig,
            self.check_clickjacking,
            self.check_directory_traversal,
            self.check_http_methods,
            self.check_server_info,
            self.check_backup_files,
            self.check_ssrf,
            self.check_idor,
            self.check_performance
        ]
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_check = {executor.submit(check, url): check.__name__ for check in checks}
            for future in as_completed(future_to_check):
                try:
                    future.result()
                except Exception as e:
                    logging.error(f"خطا در {future_to_check[future]}: {str(e)}")
        self.close_resources()
        return self.generate_report(url)

    def check_dns_security(self, url):
        self.explain_check("DNS Security", "بررسی DNSSEC و رکوردهای DNS برای شناسایی ضعف‌های دامنه.", "تأثیر: کم، فقط اطلاعات عمومی جمع‌آوری می‌شه بدون آسیب به سایت.")
        parsed_url = urlparse(url)
        domain = parsed_url.hostname
        try:
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(domain, 'DNSKEY')
            self.scan_results['dnssec'] = "✅ فعال - DNSSEC پیاده‌سازی شده است"
        except:
            self.scan_results['dnssec'] = "❌ غیرفعال - DNSSEC پیاده‌سازی نشده است"
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'CNAME', 'NS']
        dns_records = {}
        for record_type in record_types:
            try:
                answers = resolver.resolve(domain, record_type)
                dns_records[record_type] = [str(r) for r in answers]
            except:
                dns_records[record_type] = "یافت نشد"
        self.scan_results['dns_records'] = dns_records

    def check_ssl_tls(self, url):
        self.explain_check("SSL/TLS", "بررسی گواهی SSL و نسخه پروتکل TLS.", "تأثیر: کم، فقط ارتباط امن رو تست می‌کنه، بدون فشار روی سرور.")
        parsed_url = urlparse(url)
        if parsed_url.scheme != 'https':
            self.scan_results['ssl_tls'] = "⚠️ سایت از HTTPS استفاده نمی‌کند"
            return
        try:
            context = ssl.create_default_context(cafile=certifi.where())
            with socket.create_connection((parsed_url.hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=parsed_url.hostname) as ssock:
                    cert = ssock.getpeercert()
                    expiry_date = ssl.cert_time_to_seconds(cert['notAfter'])
                    current_time = time.time()
                    days_until_expiry = (expiry_date - current_time) // 86400
                    ssl_version = ssock.version()
                    if days_until_expiry < 30:
                        self.scan_results['ssl_tls'] = f"⚠️ هشدار: گواهی SSL در {days_until_expiry} روز منقضی می‌شود. نسخه SSL: {ssl_version}"
                    else:
                        self.scan_results['ssl_tls'] = f"✅ امن - گواهی SSL معتبر برای {days_until_expiry} روز. نسخه SSL: {ssl_version}"
        except Exception as e:
            self.scan_results['ssl_tls'] = f"❌ مشکل در SSL/TLS: {str(e)}"

    def check_security_headers(self, url):
        self.explain_check("Security Headers", "بررسی هدرهای امنیتی مثل X-Frame-Options.", "تأثیر: بسیار کم، فقط اطلاعات هدرها رو بررسی می‌کنه.")
        response = self.safe_request(url)
        if not response:
            self.scan_results['security_headers'] = "نامشخص - بررسی با خطا مواجه شد"
            return
        headers = response.headers
        security_headers = {
            'X-Frame-Options': 'حفاظت کلیک‌جکینگ',
            'X-XSS-Protection': 'حفاظت XSS',
            'X-Content-Type-Options': 'جلوگیری MIME sniffing',
            'Strict-Transport-Security': 'اجبار HTTPS',
            'Content-Security-Policy': 'سیاست امنیت محتوا'
        }
        missing_headers = []
        existing_headers = {}
        for header, description in security_headers.items():
            if header in headers:
                existing_headers[header] = {'value': headers[header], 'description': description}
            else:
                missing_headers.append(header)
        self.scan_results['security_headers'] = {'existing': existing_headers, 'missing': missing_headers}

    def check_exposed_files(self, url):
        self.explain_check("Exposed Files", "جستجوی فایل‌های حساس مثل .env یا backup.", "تأثیر: کم، فقط درخواست GET ساده، بدون تغییر در سرور.")
        exposed_files = ['/.env', '/.git/config', '/phpinfo.php', '/backup.zip']
        found_files = []
        for file_path in exposed_files:
            file_url = url.rstrip('/') + file_path
            response = self.safe_request(file_url)
            if response and response.status_code == 200:
                found_files.append({'path': file_path, 'url': file_url, 'status_code': response.status_code})
        if found_files:
            self.vulnerabilities.append("فایل‌های در معرض خطر")
            self.scan_results['exposed_files'] = found_files
        else:
            self.scan_results['exposed_files'] = "✅ هیچ فایل خطرناکی یافت نشد"

    def check_sql_injection(self, url):
        self.explain_check("SQL Injection", "تست پیلودهای SQL با time-based (تأخیر 5 ثانیه).", "تأثیر: متوسط، می‌تونه سرور رو کند کنه، اما دیتابیس تغییر نمی‌کنه.")
        response = self.safe_request(url)
        if not response:
            self.scan_results['sql_injection'] = "نامشخص - بررسی با خطا مواجه شد"
            return
        soup = BeautifulSoup(response.text, 'html.parser')
        test_params = self.find_test_params(url, soup)
        sql_payloads = ["' OR SLEEP(5)--", "' AND 1=1--"]
        vulnerable_points = []
        for param_name, param_url in test_params:
            for payload in sql_payloads:
                test_url = param_url.replace('PARAM_VALUE', quote(payload))
                start_time = time.time()
                response = self.safe_request(test_url, timeout=15)
                response_time = time.time() - start_time
                if response and response_time > 5:
                    vulnerable_points.append({'parameter': param_name, 'url': test_url, 'payload': payload, 'method': 'GET'})
                    break
        if vulnerable_points:
            self.vulnerabilities.append("تزریق SQL")
            self.scan_results['sql_injection'] = vulnerable_points
        else:
            self.scan_results['sql_injection'] = "✅ امن - هیچ نشانه‌ای یافت نشد"

    def check_xss(self, url):
        self.explain_check("XSS", "تست پیلودهای جاوااسکریپت با alert.", "تأثیر: کم، فقط تست می‌کنه، در حالت headless تأثیری نداره.")
        self.init_selenium_driver()
        if not self.driver:
            self.scan_results['xss'] = "نامشخص - بررسی با خطا مواجه شد"
            return
        self.driver.get(url)
        soup = BeautifulSoup(self.driver.page_source, 'html.parser')
        test_params = self.find_test_params(url, soup)
        xss_payloads = ['<script>alert("XSS")</script>']
        vulnerable_points = []
        for param_name, param_url in test_params:
            for payload in xss_payloads:
                test_url = param_url.replace('PARAM_VALUE', quote(payload))
                self.driver.get(test_url)
                try:
                    WebDriverWait(self.driver, 2).until(EC.alert_is_present())
                    vulnerable_points.append({'parameter': param_name, 'url': test_url, 'payload': payload, 'method': 'GET'})
                    self.driver.switch_to.alert.dismiss()
                    break
                except:
                    pass
        if vulnerable_points:
            self.vulnerabilities.append("XSS")
            self.scan_results['xss'] = vulnerable_points
        else:
            self.scan_results['xss'] = "✅ امن - هیچ نشانه‌ای یافت نشد"

    def find_test_params(self, url, soup):
        test_params = []
        links = soup.find_all('a', href=True)
        for link in links:
            href = link['href']
            if '?' in href and '=' in href:
                full_url = urljoin(url, href)
                parsed_url = urlparse(full_url)
                query_params = parsed_url.query.split('&')
                for param in query_params:
                    if '=' in param:
                        param_name = param.split('=')[0]
                        test_url = full_url.replace(param, f"{param_name}=PARAM_VALUE")
                        test_params.append((param_name, test_url))
        return test_params

    def check_csrf(self, url):
        self.explain_check("CSRF", "بررسی وجود توکن CSRF در فرم‌ها.", "تأثیر: بسیار کم، فقط فرم‌ها رو تحلیل می‌کنه.")
        response = self.safe_request(url)
        if not response:
            self.scan_results['csrf_protection'] = "نامشخص - بررسی با خطا مواجه شد"
            return
        soup = BeautifulSoup(response.text, 'html.parser')
        csrf_protected = False
        csrf_tokens = []
        forms = soup.find_all('form')
        for form in forms:
            token_inputs = form.find_all('input', {'name': lambda x: x and 'csrf' in x.lower()})
            if token_inputs:
                csrf_protected = True
                for token in token_inputs:
                    csrf_tokens.append({'form_action': form.get('action', ''), 'input_name': token.get('name')})
        self.scan_results['csrf_protection'] = "✅ محافظت شده" if csrf_protected else "⚠️ احتمالاً آسیب‌پذیر"

    def check_file_inclusion(self, url):
        self.explain_check("File Inclusion", "تست پیلودهای دسترسی به فایل مثل /etc/passwd.", "تأثیر: کم، فقط درخواست می‌فرسته، بدون تغییر فایل.")
        response = self.safe_request(url)
        if not response:
            self.scan_results['file_inclusion'] = "نامشخص - بررسی با خطا مواجه شد"
            return
        soup = BeautifulSoup(response.text, 'html.parser')
        test_params = self.find_test_params(url, soup)
        inclusion_payloads = ['../../../../etc/passwd']
        vulnerable_points = []
        for param_name, param_url in test_params:
            for payload in inclusion_payloads:
                test_url = param_url.replace('PARAM_VALUE', quote(payload))
                response = self.safe_request(test_url)
                if response and 'root:' in response.text.lower():
                    vulnerable_points.append({'parameter': param_name, 'url': test_url, 'payload': payload})
                    break
        if vulnerable_points:
            self.vulnerabilities.append("File Inclusion")
            self.scan_results['file_inclusion'] = vulnerable_points
        else:
            self.scan_results['file_inclusion'] = "✅ امن - هیچ نشانه‌ای یافت نشد"

    def check_open_ports(self, url):
        self.explain_check("Open Ports", "اسکن پورت‌های رایج مثل 80 و 443.", "تأثیر: کم، مثل ping، بدون حمله واقعی.")
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        common_ports = [80, 443]
        open_ports = []
        for port in common_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(2)
                    result = s.connect_ex((hostname, port))
                    if result == 0:
                        open_ports.append(port)
            except:
                pass
        self.scan_results['open_ports'] = f"🔓 پورت‌های باز: {', '.join(map(str, open_ports))}" if open_ports else "✅ هیچ پورت باز غیرمعمولی"

    def check_info_leakage(self, url):
        self.explain_check("Info Leakage", "جستجوی اطلاعات حساس مثل API Key.", "تأثیر: بسیار کم، فقط متن رو تحلیل می‌کنه.")
        response = self.safe_request(url)
        if not response:
            self.scan_results['info_leakage'] = "نامشخص - بررسی با خطا مواجه شد"
            return
        content = response.text.lower()
        headers = response.headers
        sensitive_patterns = {'api_key': ['api_key', 'secret']}
        leaked_info = {}
        for category, patterns in sensitive_patterns.items():
            found_items = [p for p in patterns if p in content]
            if found_items:
                leaked_info[category] = found_items
        self.scan_results['info_leakage'] = leaked_info if leaked_info else "✅ هیچ نشتی یافت نشد"

    def check_admin_pages(self, url):
        self.explain_check("Admin Pages", "جستجوی صفحات ادمین مثل /admin.", "تأثیر: کم، فقط درخواست GET ساده.")
        admin_paths = ['/admin', '/login']
        found_admin_pages = []
        for path in admin_paths:
            admin_url = url.rstrip('/') + path
            response = self.safe_request(admin_url)
            if response and response.status_code == 200:
                found_admin_pages.append({'url': admin_url, 'status_code': response.status_code})
        self.scan_results['admin_pages'] = found_admin_pages if found_admin_pages else "✅ هیچ صفحه ادمین یافت نشد"

    def check_cors_misconfig(self, url):
        self.explain_check("CORS Misconfig", "بررسی تنظیمات CORS با هدر Origin.", "تأثیر: بسیار کم، فقط هدرها رو تست می‌کنه.")
        origin = 'https://example.com'
        headers = {'Origin': origin}
        response = self.safe_request(url, headers=headers)
        if response:
            cors_headers = response.headers.get('Access-Control-Allow-Origin', '')
            if cors_headers == '*' or origin in cors_headers:
                self.vulnerabilities.append("CORS Misconfiguration")
                self.scan_results['cors'] = "❌ آسیب‌پذیر"
            else:
                self.scan_results['cors'] = "✅ امن"

    def check_clickjacking(self, url):
        self.explain_check("Clickjacking", "بررسی هدر X-Frame-Options.", "تأثیر: بسیار کم، فقط هدر رو چک می‌کنه.")
        response = self.safe_request(url)
        if not response:
            self.scan_results['clickjacking'] = "نامشخص - بررسی با خطا مواجه شد"
            return
        if 'X-Frame-Options' not in response.headers:
            self.vulnerabilities.append("Clickjacking")
            self.scan_results['clickjacking'] = "❌ آسیب‌پذیر"
        else:
            self.scan_results['clickjacking'] = "✅ امن"

    def check_directory_traversal(self, url):
        self.explain_check("Directory Traversal", "تست دسترسی به فایل‌های سیستم.", "تأثیر: کم، فقط درخواست می‌فرسته، بدون تغییر.")
        test_params = self.find_test_params(url, BeautifulSoup(self.safe_request(url).text, 'html.parser'))
        traversal_payloads = ['../../../../etc/passwd']
        vulnerable = False
        for param_name, param_url in test_params:
            for payload in traversal_payloads:
                test_url = param_url.replace('PARAM_VALUE', quote(payload))
                response = self.safe_request(test_url)
                if response and 'root:' in response.text.lower():
                    vulnerable = True
                    break
        if vulnerable:
            self.vulnerabilities.append("Directory Traversal")
            self.scan_results['directory_traversal'] = "❌ آسیب‌پذیر"
        else:
            self.scan_results['directory_traversal'] = "✅ امن"

    def check_http_methods(self, url):
        self.explain_check("HTTP Methods", "بررسی متدهای مجاز مثل PUT.", "تأثیر: کم، فقط متد رو تست می‌کنه.")
        methods = ['GET', 'POST', 'PUT']
        allowed_methods = []
        for method in methods:
            try:
                response = self.safe_request(url, method=method)
                if response and response.status_code != 405:
                    allowed_methods.append(method)
            except:
                pass
        self.scan_results['http_methods'] = allowed_methods if allowed_methods else "✅ فقط GET/POST"

    def check_server_info(self, url):
        self.explain_check("Server Info", "جستجوی اطلاعات سرور از هدرها.", "تأثیر: بسیار کم، فقط اطلاعات رو جمع‌آوری می‌کنه.")
        response = self.safe_request(url)
        if not response:
            self.scan_results['server_info'] = "نامشخص - بررسی با خطا مواجه شد"
            return
        headers = response.headers
        server_info = {h: headers[h] for h in ['Server', 'X-Powered-By'] if h in headers}
        self.scan_results['server_info'] = server_info if server_info else "✅ هیچ اطلاعات اضافی"

    def check_backup_files(self, url):
        self.explain_check("Backup Files", "جستجوی فایل‌های بکاپ مثل .bak.", "تأثیر: کم، فقط درخواست GET ساده.")
        backup_extensions = ['.bak', '.zip']
        backup_files = []
        response = self.safe_request(url)
        if not response:
            self.scan_results['backup_files'] = "نامشخص - بررسی با خطا مواجه شد"
            return
        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.find_all('a', href=True)
        for link in links:
            for ext in backup_extensions:
                if link['href'].endswith(ext):
                    backup_url = urljoin(url, link['href'])
                    backup_response = self.safe_request(backup_url)
                    if backup_response and backup_response.status_code == 200:
                        backup_files.append({'url': backup_url, 'status_code': backup_response.status_code})
        if backup_files:
            self.vulnerabilities.append("فایل‌های بکاپ")
            self.scan_results['backup_files'] = backup_files
        else:
            self.scan_results['backup_files'] = "✅ هیچ فایل بکاپ یافت نشد"

    def check_ssrf(self, url):
        self.explain_check("SSRF", "تست دسترسی به localhost با پیلودها.", "تأثیر: کم، فقط درخواست می‌فرسته، بدون تغییر.")
        test_params = self.find_test_params(url, BeautifulSoup(self.safe_request(url).text, 'html.parser'))
        ssrf_payloads = ['http://127.0.0.1']
        vulnerable_points = []
        for param_name, param_url in test_params:
            for payload in ssrf_payloads:
                test_url = param_url.replace('PARAM_VALUE', quote(payload))
                response = self.safe_request(test_url)
                if response and 'localhost' in response.text.lower():
                    vulnerable_points.append({'parameter': param_name, 'url': test_url, 'payload': payload})
                    break
        if vulnerable_points:
            self.vulnerabilities.append("SSRF")
            self.scan_results['ssrf'] = vulnerable_points
        else:
            self.scan_results['ssrf'] = "✅ امن"

    def check_idor(self, url):
        self.explain_check("IDOR", "تست دسترسی غیرمجاز با IDهای مختلف.", "تأثیر: کم، فقط درخواست می‌فرسته، بدون تغییر.")
        test_params = self.find_test_params(url, BeautifulSoup(self.safe_request(url).text, 'html.parser'))
        vulnerable = False
        for param_name, param_url in test_params:
            if 'id=' in param_url:
                test_url1 = param_url.replace('PARAM_VALUE', '1')
                test_url2 = param_url.replace('PARAM_VALUE', '1000')
                resp1 = self.safe_request(test_url1)
                resp2 = self.safe_request(test_url2)
                if resp1 and resp2 and resp1.status_code == 200 and resp2.status_code == 200:
                    vulnerable = True
                    break
        if vulnerable:
            self.vulnerabilities.append("IDOR")
            self.scan_results['idor'] = "❌ آسیب‌پذیر"
        else:
            self.scan_results['idor'] = "✅ امن"

    def check_performance(self, url):
        self.explain_check("Performance", "اندازه‌گیری زمان پاسخ با 5 درخواست.", "تأثیر: کم، فقط 5 درخواست ساده، بدون فشار زیاد.")
        load_tests = 5
        response_times = []
        for i in range(load_tests):
            start_time = time.time()
            response = self.safe_request(url)
            if response:
                response_times.append((time.time() - start_time) * 1000)
            time.sleep(1)
        if response_times:
            self.performance_metrics = {
                'average': f"{sum(response_times) / len(response_times):.2f} ms",
                'max': f"{max(response_times):.2f} ms"
            }
            self.scan_results['performance'] = self.performance_metrics
        else:
            self.scan_results['performance'] = "نامشخص - بررسی با خطا مواجه شد"

    def generate_report(self, url):
        html_template = f"""
        <!DOCTYPE html>
        <html lang="fa">
        <head><meta charset="UTF-8"><title>گزارش اسکن</title></head>
        <body dir="rtl">
        <h1>گزارش اسکن برای {url}</h1>
        <p>تاریخ: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        {''.join(f'<p>{k}: {v}</p>' for k, v in self.scan_results.items())}
        </body></html>
        """
        filename = f"security_scan_{urlparse(url).hostname}_{time.strftime('%Y%m%d_%H%M%S')}.html"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_template)
        pdf_filename = filename.replace('.html', '.pdf')
        pdfkit.from_string(html_template, pdf_filename)
        print(f"📄 گزارش در {filename} و {pdf_filename} ذخیره شد.")

def main():
    print("🛡️ اسکنر امنیتی پیشرفته")
    print("=" * 40)
    target_url = input("لطفاً آدرس سایت را وارد کنید (مثال: example.com): ").strip()
    if not target_url:
        print("❌ آدرس سایت نمی‌تواند خالی باشد.")
        return
    scanner = AdvancedSecurityScanner()
    scanner.scan_website(target_url)

if __name__ == "__main__":
    main()