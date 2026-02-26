import requests
import whois
from datetime import datetime
from colorama import Fore
import random
from playwright.sync_api import sync_playwright
from playwright_stealth import stealth_sync
import re
import socket
import ssl
import dns.resolver
from urllib.parse import urlparse
from logger import logger
from config import Config

from utils import is_safe_ip, ProxyManager

class Scanner:
    def __init__(self):
        self.proxy_manager = ProxyManager()
        self.user_agents = Config.USER_AGENTS
        self._playwright = None
        self._browser = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def _get_browser(self):
        """
        Playwright browser instance'ını lazy-load ile başlatır ve döndürür (Persistent).
        """
        if self._browser is None:
            self._playwright = sync_playwright().start()
            self._browser = self._playwright.chromium.launch(
                headless=True,
                args=['--disable-gpu', '--no-sandbox', '--disable-dev-shm-usage']
            )
        return self._browser

    def close(self):
        """
        Tarayıcıyı ve Playwright'ı kapatır.
        """
        if self._browser:
            self._browser.close()
            self._browser = None
        if self._playwright:
            self._playwright.stop()
            self._playwright = None

    def _get_random_headers(self):
        return {
            "User-Agent": random.choice(self.user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7",
        }

    def get_domain_age(self, domain):
        # Güvenlik Kontrolü: Domain ismi sadece izin verilen karakterleri içermeli
        if not re.match(r"^[a-zA-Z0-9.-]+$", domain):
            return None

        # WHOIS sunucuları (özellikle .tr gibi ccTLD'ler) bazen bağlantıyı sıfırlayabilir (WinError 10054).
        # Bu durumu aşmak için kısa beklemeli bir yeniden deneme mekanizması kullanıyoruz.
        for attempt in range(2):
            try:
                domain_info = whois.whois(domain)
                creation_date = domain_info.creation_date
                
                # Liste dönmesi durumunda ilkini al (python-whois standardı)
                if isinstance(creation_date, list): 
                    creation_date = creation_date[0]
                
                # Bazı ccTLD'ler (özellikle TRABİS sonrası .tr) farklı alan adları kullanabilir
                if not creation_date:
                    creation_date = domain_info.get('created_at') or domain_info.get('updated_date')
                    if isinstance(creation_date, list): creation_date = creation_date[0]

                if not creation_date:
                    if attempt == 0:
                        import time
                        time.sleep(1)
                        continue
                    return None

                # Zaman dilimi bilgisini temizle (datetime.now() ile karşılaştırmak için)
                if hasattr(creation_date, 'tzinfo') and creation_date.tzinfo:
                    creation_date = creation_date.replace(tzinfo=None)
                
                if not isinstance(creation_date, datetime):
                    return None

                delta = datetime.now() - creation_date
                return delta.days
            except Exception as e:
                # Bağlantı hatalarında (Socket error, Reset vb.) tekrar dene
                if attempt == 0:
                    import time
                    time.sleep(1.5)
                    continue
                return None
        return None


    def check_reputation(self, domain):
        """
        Gelişmiş yerel itibar analizi (Whitelist destekli).
        """
        # Alt domain kontrolü için (örn: mail.google.com -> google.com)
        parts = domain.split('.')
        base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain
        
        if domain in Config.DOMAIN_WHITELIST or base_domain in Config.DOMAIN_WHITELIST:
            return "Güvenilir (Whitelist)"

        score = 0
        details = []

        # Keyword Check
        for kw in Config.SUSPICIOUS_KEYWORDS:
            if kw in domain.lower():
                score += 1
                details.append(f"Şüpheli kelime: {kw}")

        # TLD Check
        for tld in Config.SUSPICIOUS_TLDS:
            if domain.lower().endswith(tld):
                score += 2
                details.append(f"Yüksek riskli TLD: {tld}")

        # Hyphen Check (Çok fazla tire kullanımı)
        if domain.count("-") > 3:
            score += 2
            details.append("Aşırı tire kullanımı")

        # Uzunluk
        if len(domain) > 60:
            score += 1
            details.append("Anormal uzunluk")

        if score == 0:
            return "Temiz (Yerel Analiz)"
        elif score < 3:
             return f"Düşük Risk (Skor: {score}) -> " + ", ".join(details)
        else:
            return f"YÜKSEK RİSK (Skor: {score}) -> " + ", ".join(details)

    def detect_js_obfuscation(self, html_content):
        """
        HTML içeriğinde JavaScript karmaşıklaştırma (obfuscation) tekniklerini tespit eder.
        """
        score = 0
        findings = []

        # 1. Hex encoding yoğunluğu
        hex_matches = len(re.findall(r'\\x[0-9a-fA-F]{2}', html_content))
        if hex_matches > 50:
            score += 2
            findings.append(f"Yüksek Hex Encoding ({hex_matches} adet)")

        # 2. Tehlikeli fonksiyonlar
        if "eval(" in html_content:
            count = html_content.count("eval(")
            score += 3
            findings.append(f"Eval() kullanımı ({count} adet)")

        if "unescape(" in html_content:
            score += 2
            findings.append("Unescape() kullanımı")

        # 3. Packer tespiti (Dean Edwards vb.)
        if re.search(r'function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*d\s*\)', html_content):
            score += 4
            findings.append("JS Packer Tespiti")
            
        # 4. Uzun tek satır satırlar (Minified/Obfuscated)
        lines = html_content.split('\n')
        for line in lines:
            if len(line) > 10000 and "base64" not in line: # Base64 resimler hariç
                score += 1
                findings.append("Aşırı uzun satır (Minified/Obfuscated Code)")
                break

        # 5. Tele-Phish & Exfiltration Tespiti (Telegram API)
        # Örn: api.telegram.org/bot<TOKEN>/sendMessage
        tg_bot_pattern = r"api\.telegram\.org/bot([0-9]{8,12}:[a-zA-Z0-9_-]{35})"
        tg_matches = re.findall(tg_bot_pattern, html_content)
        if tg_matches:
            score += 10 # Doğrudan oltalama göstergesi
            findings.append(f"Telegram Bot API Tespiti (Sızıntı Riski): {len(tg_matches)} adet")
        
        # Genel Token/Key patternleri (Telegram vb.)
        if re.search(r"bot_token|chat_id|sendMessage\?", html_content, re.IGNORECASE):
            if "telegram" in html_content.lower():
                score += 5
                findings.append("Şüpheli Telegram Veri Gönderim Parametreleri")

        return score, findings


    def scrape_site(self, url):
        # 1. SSRF Kontrolü & DNS Çözümleme
        parsed_url = urlparse(url)
        domain = parsed_url.hostname
        try:
            ip = socket.gethostbyname(domain)
            if not is_safe_ip(ip):
                logger.error(f"[!] GÜVENLİK UYARISI: Yerel ağa erişim engellendi ({domain} -> {ip})")
                return "[SCANNER_FAIL] Güvenlik: Hedef IP yerel ağda."
        except Exception as e:
            logger.error(f"[!] DNS Hatası: {e}")
            return "[SCANNER_FAIL] DNS çözümlenemedi."

        # Dual Scanning (Requests + Playwright) kaldırıldı.
        # Doğrudan Playwright kullanılarak JS desteği ve tutarlılık sağlanıyor.
        try:
            # Persistent browser kullanımı
            browser = self._get_browser()
            
            # Context oluştur (User-Agent ve Proxy için)
            proxy_config = self.proxy_manager.get_playwright_proxy()
            context = browser.new_context(
                user_agent=self.user_agents[0],
                viewport={'width': 1280, 'height': 720},
                ignore_https_errors=True, # Proxy ile bazen SSL sorunları olabilir, tarama için True yapalım
                proxy=proxy_config
            )
            
            try:
                page = context.new_page()
                
                # Playwright Stealth Uygula (Anti-Detection/Evasion)
                stealth_sync(page)

                # Sayfaya git
                page.goto(url, wait_until="domcontentloaded", timeout=30000)
                
                # Biraz bekle (JS render için)
                page.wait_for_timeout(3000)

                # JS Obfuscation Analizi Yap (Page Source)
                raw_html = page.content()
                obf_score, obf_details = self.detect_js_obfuscation(raw_html)
                
                obf_status = ""
                if obf_score > 2:
                    logger.warning(f"      [!] JS Obfuscation Tespit Edildi (Skor: {obf_score}): {', '.join(obf_details)}")
                    obf_status = f"\n[WARNING] JS Obfuscation Detected: {', '.join(obf_details)}"

                # Metin içeriğini al (Temizlenmiş)
                text = page.evaluate("""() => {
                    // Gereksiz tagleri temizle
                    const tagsToRemove = ['script', 'style', 'noscript', 'iframe', 'nav', 'footer', 'header', 'aside'];
                    tagsToRemove.forEach(tag => {
                        document.querySelectorAll(tag).forEach(el => el.remove());
                    });
                    return document.body.innerText;
                }""")
                
                # Başlığı da al
                title = page.title()
                
                # Metni temizle (fazla boşlukları at)
                clean_text = " ".join(text.split())
                return f"Title: {title}{obf_status} | Body: {clean_text[:3000]}" # 3000 karakter (limit optimize edildi)

            finally:
                context.close() # Sadece context'i kapat, browser açık kalsın

        except Exception as e:
            # Playwright hatalarını sınıflandır
            err_msg = str(e).lower()
            logger.error(f"Playwright Hatası: {err_msg}") # Log detailed error
            if "timeout" in err_msg:
                return "[SCANNER_FAIL] Bağlantı zaman aşımına uğradı (Timeout - JS Render)."
            elif "ssl" in err_msg or "certificate" in err_msg:
                return "[SCANNER_FAIL] SSL Sertifikası geçersiz veya bozuk."
            elif "err_connection_refused" in err_msg:
                return "[SCANNER_FAIL] Sunucu bağlantıyı reddetti."
            elif "err_name_not_resolved" in err_msg:
                return "[SCANNER_FAIL] DNS çözümlenemedi."
            else:
                return f"[SCANNER_FAIL] Tarama hatası: {str(e)[:100]}"

    def take_screenshot(self, url, output_path="screenshot.png"):
        """
        Sitenin ekran görüntüsünü alır.
        """
        try:
            browser = self._get_browser()
            proxy_config = self.proxy_manager.get_playwright_proxy()
            context = browser.new_context(
                viewport={'width': 1280, 'height': 720},
                proxy=proxy_config,
                ignore_https_errors=True
            )
            try:
                page = context.new_page()
                page.goto(url, wait_until="networkidle", timeout=30000)
                page.screenshot(path=output_path)
                return output_path
            finally:
                context.close()
        except Exception as e:
            logger.error(f"Ekran görüntüsü alınamadı: {e}")
            return None

    def check_ssl(self, domain):
        """
        SSL/TLS Sertifikasını analiz eder.
        """
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    issuer = dict(x[0] for x in cert['issuer'])
                    not_after = cert['notAfter']
                    not_before = cert['notBefore'] # Başlangıç tarihi
                    
                    # Tarih formatını parse et: Feb 16 12:00:00 2025 GMT
                    expire_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    start_date = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z") # Parse start date
                    
                    now = datetime.now()
                    days_left = (expire_date - now).days
                    age_days = (now - start_date).days # Sertifikanın yaşı
                    
                    issuer_org = issuer.get('organizationName', 'Bilinmiyor')
                    issuer_cn = issuer.get('commonName', 'Bilinmiyor')
                    
                    return {
                        "valid": True,
                        "issuer": f"{issuer_org} ({issuer_cn})",
                        "days_left": days_left,
                        "age_days": age_days,
                    }
        except Exception as e:
            return {"valid": False, "error": str(e)}

    def check_mx_records(self, domain):
        """
        Domainin MX kaydı olup olmadığını kontrol eder (dnspython ile platform bağımsız).
        """
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            return len(answers) > 0
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.resolver.NoNameservers):
            return False
        except Exception as e:
            logger.error(f"MX Kayıt Hatası: {str(e)}")
            return False

    def get_redirect_chain(self, url):
        """
        URL yönlendirme zincirini takip eder ve tüm URL'leri liste olarak döndürür.
        """
        chain = [url]
        try:
            proxies = self.proxy_manager.get_requests_proxies()
            # Yalnızca HTTP yönlendirmelerini hızlıca yakalamak için requests kullanıyoruz
            response = requests.get(
                url, 
                headers=self._get_random_headers(), 
                timeout=Config.URL_FETCH_TIMEOUT, 
                proxies=proxies, 
                verify=False, 
                allow_redirects=True
            )
            
            # response.history, final yönlendirmeden önceki tüm response nesnelerini içerir
            for resp in response.history:
                if resp.url not in chain:
                    chain.append(resp.url)
            
            # Final URL'i ekle
            if response.url not in chain:
                chain.append(response.url)
                
            return chain
        except Exception as e:
            logger.error(f"Yönlendirme analizi hatası: {e}")
            return chain

    def full_scan(self, url):
        import tldextract
        """
        API ve CLI için toplu analiz metodu.
        """
        results = {
            "url": url,
            "scan_time": datetime.now().isoformat(),
            "domain": None,
            "redirect_chain": [],
            "technical_details": {},
            "content_analysis": None
        }

        # 1. Yönlendirme Analizi
        try:
            results["redirect_chain"] = self.get_redirect_chain(url)
            final_url = results["redirect_chain"][-1] if results["redirect_chain"] else url
            results["final_url"] = final_url
            
            # Domain ayrıştır
            ext = tldextract.extract(final_url)
            results["domain"] = f"{ext.domain}.{ext.suffix}"
        except Exception as e:
            logger.error(f"Yönlendirme hatası: {e}")
            results["error"] = str(e)
            return results

        domain = results["domain"]

        # 2. Teknik Analizler (Domain Age, SSL, MX)
        tech_details = {}
        tech_details["domain_age_days"] = self.get_domain_age(domain)
        tech_details["reputation"] = self.check_reputation(domain)
        tech_details["ssl_info"] = self.check_ssl(domain)
        tech_details["has_mx_records"] = self.check_mx_records(domain)
        results["technical_details"] = tech_details

        # 3. İçerik Analizi (Scrape)
        # Not: take_screenshot API modunda sunucuda dosya biriktirmemesi için opsiyonel olabilir
        # Şimdilik dahil ediyoruz ancak geçici dosya yönetimi gerekebilir.
        try:
            # Scrape content
            content_summary = self.scrape_site(final_url)
            results["content_analysis"] = content_summary
            
            # Screenshot (Base64'e çevrilip dönülebilir veya path verilebilir)
            # API için path dönmek istemciye erişim vermez, base64 daha iyi olurdu ama
            # şimdilik dosya yolu dönelim, API katmanı bunu okuyup silebilir.
            screenshot_path = f"scan_{random.randint(1000,9999)}.png"
            saved_path = self.take_screenshot(final_url, screenshot_path)
            results["screenshot_path"] = saved_path
        except Exception as e:
            logger.error(f"İçerik tarama hatası: {e}")

        return results
