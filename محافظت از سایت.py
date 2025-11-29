#!/usr/bin/env python3
"""
🎯 Attacker Trapper System - سیستم ردیابی و مهار مهاجمان
✅ شناسایی، ردیابی، مهار و اسیر کردن مهاجمان
"""

import sqlite3
import time
import logging
import re
import os
import ipaddress
from datetime import datetime
import threading
import subprocess
import requests
from urllib.parse import urlparse
import json

class AttackerTrapper:
    def __init__(self):
        print("🎯 سیستم ردیابی و مهار مهاجمان")
        print("=" * 50)
        print("🔍 شناسایی - 📍 ردیابی - 🚫 مهار - 🔒 اسیر کردن")
        print("=" * 50)
        
        # دریافت آدرس سایت
        self.target_website = self.get_target_website()
        self.target_domain = self.extract_domain(self.target_website)
        
        # راه‌اندازی سیستم
        self.setup_logging()
        self.init_database()
        self.attack_patterns = self.load_attack_patterns()
        self.trapped_attackers = {}
        
        print(f"🎯 هدف: {self.target_website}")
        print(f"🌐 دامنه: {self.target_domain}")
        print("✅ سیستم در حال راه‌اندازی...")
        print("=" * 50)
    
    def get_target_website(self):
        """دریافت آدرس سایت از کاربر"""
        while True:
            website = input("🌐 آدرس سایت را وارد کنید: ").strip()
            
            if not website:
                print("❌ آدرس سایت نمی‌تواند خالی باشد!")
                continue
            
            if not website.startswith(('http://', 'https://')):
                website = 'https://' + website
            
            if self.validate_website(website):
                return website
            else:
                print("❌ آدرس سایت نامعتبر است!")
    
    def extract_domain(self, url):
        """استخراج دامنه از آدرس کامل"""
        try:
            parsed_url = urlparse(url)
            return parsed_url.netloc
        except:
            return url.split('//')[-1].split('/')[0]
    
    def validate_website(self, url):
        """اعتبارسنجی آدرس سایت"""
        try:
            result = urlparse(url)
            return all([result.scheme in ['http', 'https'], result.netloc])
        except:
            return False
    
    def setup_logging(self):
        """راه‌اندازی سیستم لاگ‌گیری"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('attacker_trap.log', encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def init_database(self):
        """ایجاد دیتابیس برای ذخیره اطلاعات مهاجمان"""
        self.db_path = 'attackers.db'
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''CREATE TABLE IF NOT EXISTS trapped_attackers
                    (ip TEXT PRIMARY KEY,
                     trap_id TEXT,
                     trap_time INTEGER,
                     release_time INTEGER,
                     attack_type TEXT,
                     country TEXT,
                     isp TEXT,
                     status TEXT)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS attack_logs
                    (id INTEGER PRIMARY KEY,
                     ip TEXT,
                     attack_type TEXT,
                     timestamp INTEGER,
                     request_data TEXT)''')
        
        conn.commit()
        conn.close()
    
    def load_attack_patterns(self):
        """الگوهای تشخیص حملات"""
        return {
            'sql_injection': [r"union.*select", r"select.*from", r"or.*1=1", r"';.*--"],
            'xss_attack': [r"<script>", r"javascript:", r"alert\(", r"document\.cookie"],
            'rce_attack': [r"system\(", r"exec\(", r"passthru\(", r"shell_exec\("],
            'lfi_attack': [r"\.\./", r"etc/passwd", r"proc/self", r"windows/win"],
            'brute_force': [r"login.*attempt", r"failed.*password", r"admin.*admin"]
        }
    
    def read_logs(self):
        """خواندن لاگ‌های سرور"""
        log_paths = [
            'access.log',
            'C:/xampp/apache/logs/access.log',
            'C:/wamp64/logs/access.log',
            '/var/log/apache2/access.log',
            '/var/log/nginx/access.log'
        ]
        
        for log_path in log_paths:
            if os.path.exists(log_path):
                try:
                    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                        return f.readlines()[-100:]
                except Exception as e:
                    self.logger.error(f"خطا در خواندن {log_path}: {e}")
        return []
    
    def detect_attack(self, log_line):
        """تشخیص حمله در خط لاگ"""
        patterns = [
            r'^(\S+) .* "(?:GET|POST|PUT|DELETE|HEAD) ([^"]+) HTTP',
            r'^(\S+) .* "([^"]+)" \d+ \d+'
        ]
        
        for pattern in patterns:
            match = re.match(pattern, log_line)
            if match:
                ip = match.group(1)
                url = match.group(2)
                
                for attack_type, patterns in self.attack_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, url, re.IGNORECASE):
                            return {
                                'ip': ip,
                                'type': attack_type,
                                'url': url,
                                'timestamp': int(time.time()),
                                'raw': log_line.strip()
                            }
        return None
    
    def gather_intel(self, ip):
        """جمع‌آوری اطلاعات مهاجم"""
        try:
            # اطلاعات جغرافیایی
            try:
                response = requests.get(f'http://ip-api.com/json/{ip}', timeout=3)
                if response.status_code == 200:
                    data = response.json()
                    if data['status'] == 'success':
                        return {
                            'ip': ip,
                            'country': data.get('country', 'Unknown'),
                            'city': data.get('city', 'Unknown'),
                            'isp': data.get('isp', 'Unknown'),
                            'org': data.get('org', 'Unknown'),
                            'as': data.get('as', 'Unknown')
                        }
            except:
                pass
            
            return {
                'ip': ip,
                'country': 'Unknown',
                'city': 'Unknown',
                'isp': 'Unknown ISP',
                'org': 'Unknown Organization'
            }
            
        except Exception as e:
            return {'ip': ip, 'error': str(e)}
    
    def trap_attacker(self, attack_info):
        """اسیر کردن مهاجم"""
        try:
            ip = attack_info['ip']
            
            # اگر قبلاً اسیر شده، Skip
            if ip in self.trapped_attackers:
                return False
            
            # جمع‌آوری اطلاعات
            intel = self.gather_intel(ip)
            
            # ایجاد تله
            trap_id = f"TRAP-{int(time.time())}-{ip.replace('.', '')}"
            trap_time = int(time.time())
            release_time = trap_time + 1800  # 30 دقیقه
            
            # ذخیره در دیتابیس
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            c.execute('''INSERT OR REPLACE INTO trapped_attackers
                        (ip, trap_id, trap_time, release_time, attack_type, country, isp, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                     (ip, trap_id, trap_time, release_time, attack_info['type'],
                      intel.get('country', 'Unknown'), intel.get('isp', 'Unknown'), 'trapped'))
            
            c.execute('''INSERT INTO attack_logs
                        (ip, attack_type, timestamp, request_data)
                        VALUES (?, ?, ?, ?)''',
                     (ip, attack_info['type'], trap_time, attack_info['url']))
            
            conn.commit()
            conn.close()
            
            # مسدودسازی مهاجم
            self.block_attacker(ip)
            
            # ذخیره در حافظه
            self.trapped_attackers[ip] = {
                'trap_id': trap_id,
                'trap_time': trap_time,
                'release_time': release_time,
                'intel': intel,
                'attack_info': attack_info
            }
            
            # گزارش موفقیت
            print(f"🎯 مهاجم اسیر شد! » {ip}")
            print(f"🔒 تله ID: {trap_id}")
            print(f"📍 کشور: {intel.get('country', 'Unknown')}")
            print(f"⚔️ نوع حمله: {attack_info['type']}")
            print(f"⏰ زمان حبس: 30 دقیقه")
            print("=" * 50)
            
            return True
            
        except Exception as e:
            self.logger.error(f"خطا در اسیر کردن مهاجم: {e}")
            return False
    
    def block_attacker(self, ip):
        """مسدودسازی مهاجم"""
        try:
            # برای ویندوز
            if os.name == 'nt':
                subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name=Block_{ip}', 'dir=in', 'action=block', f'remoteip={ip}'
                ], capture_output=True, timeout=10)
            
            # برای لینوکس
            else:
                subprocess.run([
                    'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'
                ], timeout=10)
            
            self.logger.info(f"IP مسدود شد: {ip}")
            return True
            
        except Exception as e:
            self.logger.warning(f"امکان مسدودسازی {ip} وجود ندارد: {e}")
            return False
    
    def release_attacker(self, ip):
        """آزاد کردن مهاجم"""
        try:
            if ip in self.trapped_attackers:
                # حذف از دیتابیس
                conn = sqlite3.connect(self.db_path)
                c = conn.cursor()
                c.execute("DELETE FROM trapped_attackers WHERE ip = ?", (ip,))
                conn.commit()
                conn.close()
                
                # حذف از حافظه
                del self.trapped_attackers[ip]
                
                self.logger.info(f"مهاجم آزاد شد: {ip}")
                return True
                
        except Exception as e:
            self.logger.error(f"خطا در آزاد کردن مهاجم: {e}")
            return False
    
    def monitor_and_trap(self):
        """مانیتورینگ و اسیر کردن مهاجمان"""
        print("🔍 در حال مانیتورینگ حملات...")
        print("🎯 آماده اسیر کردن مهاجمان...")
        print("=" * 50)
        
        trapped_count = 0
        
        try:
            while True:
                # خواندن لاگ‌ها
                log_lines = self.read_logs()
                
                for line in log_lines:
                    # تشخیص حمله
                    attack_info = self.detect_attack(line)
                    if attack_info and self.target_domain in attack_info['url']:
                        # اسیر کردن مهاجم
                        if self.trap_attacker(attack_info):
                            trapped_count += 1
                            print(f"🔢 مجموع مهاجمان اسیر شده: {trapped_count}")
                
                # بررسی آزادسازی مهاجمان
                current_time = int(time.time())
                for ip, trap_info in list(self.trapped_attackers.items()):
                    if current_time >= trap_info['release_time']:
                        self.release_attacker(ip)
                        print(f"🔓 مهاجم آزاد شد: {ip}")
                
                time.sleep(5)
                
        except KeyboardInterrupt:
            print(f"\n⏹️ توقف مانیتورینگ")
            print(f"🎯 مجموع مهاجمان اسیر شده: {trapped_count}")
    
    def run(self):
        """اجرای اصلی سیستم"""
        print("\n" + "=" * 50)
        print("🚀 سیستم ردیابی و مهار مهاجمان فعال شد")
        print("=" * 50)
        
        self.monitor_and_trap()

# اجرای سیستم
if __name__ == "__main__":
    try:
        trapper = AttackerTrapper()
        trapper.run()
    except Exception as e:
        print(f"❌ خطا: {e}")
    finally:
        print("\n🎯 سیستم خاموش شد")