from urllib.parse import urlparse
from colorama import Fore, Style
import tldextract
import ipaddress
import urllib3
import warnings

# SSL ve Deprecation uyarılarını sustur
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')
warnings.filterwarnings('ignore', category=UserWarning, module='playwright_stealth')
warnings.filterwarnings('ignore', message='.*pkg_resources is deprecated.*')

from scanner import Scanner
from web_tools import WebTools
from ai_analyzer import AIAnalyzer
from logger import logger
from config import Config
import base64
import os
from datetime import datetime

def validate_and_parse_url(url):
    """
    URL'yi doğrular ve domaini kapsamlı şekilde (tldextract ile) ayrıştırır.
    IP adresi desteği eklenmiştir.
    """
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc
        if not netloc:
            return None, None
            
        # Port varsa temizle
        if ':' in netloc:
            netloc = netloc.split(':')[0]
            
        # 1. IP Adresi Kontrolü
        try:
            ipaddress.ip_address(netloc)
            return url, netloc
        except ValueError:
            pass
            
        # 2. Domain Ayrıştırma (tldextract)
        ext = tldextract.extract(url)
        if ext.suffix:
            domain = f"{ext.domain}.{ext.suffix}"
        else:
            domain = ext.domain # localhost vs.
        
        return url, domain
    except:
        return None, None

def print_banner():
    # Using logger.banner
    logger.banner(Config.BANNER_TEXT)

def main():
    # Colorama başlat
    # colorama.init(autoreset=True) # Initialized in logger
    print_banner()

    # Adım 1: Kullanıcı Girişi
    url_input = input(Fore.WHITE + "İncelenecek Web Sitesi URL'si: " + Fore.YELLOW).strip()
    
    if not url_input:
        logger.error("\n[!] Geçerli bir URL girmelisiniz.")
        return

    url, domain = validate_and_parse_url(url_input)
    if not url or not domain:
        logger.error("\n[!] URL formatı geçersiz.")
        return

    # Cache Kontrolü
    from utils import CacheManager
    cache_manager = CacheManager()
    if Config.CACHE_ENABLED:
        cached_data = cache_manager.get(url)
        if cached_data:
            logger.step(f"\n[+] Önbellekte analiz bulundu: {domain}")
            ai_res = cached_data.get("ai_analysis", {})
            logger.custom(f"      Risk Skoru: {ai_res.get('risk_score', 'N/A')}/100", Fore.CYAN)
            logger.info(f"      Karar: {ai_res.get('decision', 'Unknown')}")
            
            use_cache = input(Fore.YELLOW + "      Önbellekteki sonuç kullanılsın mı? (E/h): " + Fore.RESET).strip().lower()
            if use_cache != 'h':
                 logger.success(f"\n[OK] Analiz Tamamlandı (Cache): {ai_res.get('decision')}")
                 logger.info(f"Açıklama: {ai_res.get('explanation')}\n")
                 return

    # Scanner'ı başlat
    web_tools = WebTools()
    scanner = None

    try:
        with Scanner() as scanner:
            logger.step(f"\n[+] Analiz Başlatılıyor: {domain}")
            logger.custom("---------------------------------------------", Fore.CYAN)

            # Yönlendirme Analizi
            logger.info("[*] Yönlendirme Analizi yapılıyor...")
            redirect_chain = scanner.get_redirect_chain(url)
            
            if len(redirect_chain) > 1:
                logger.step("      -> Yönlendirme Zinciri Tespit Edildi:")
                for i, link in enumerate(redirect_chain):
                    logger.info(f"         {i+1}. {link}")
                
                # Son adresi asıl hedef olarak belirle
                final_url = redirect_chain[-1]
                final_url_parsed, final_domain = validate_and_parse_url(final_url)
                
                if final_domain: 
                    logger.warning(f"      -> Hedef Güncellendi: {final_domain}")
                    url = final_url_parsed
                    domain = final_domain
                    # Artık analiz bu domain üzerinden gidecek
            else:
                logger.info("      -> Yönlendirme yok.")

            try:
                ai_analyzer = AIAnalyzer()
            except ValueError as e:
                logger.error(f"[!] Yapılandırma Hatası: {e}")
                return

            # Adım 2: İşlem Akışı (Veri Toplama)
            logger.info("[1/3] Teknik veriler (Whois, SSL, MX & Reputasyon) taranıyor...")
            domain_age = scanner.get_domain_age(domain)
            
            age_str = f"{domain_age} gün" if domain_age is not None else "Tespit Edilemedi"
            logger.info(f"      -> Domain Yaşı: {age_str}")

            # SSL Analizi
            ssl_info = scanner.check_ssl(domain)
            if ssl_info.get("valid"):
                ssl_age = ssl_info.get("age_days", "Bilinmiyor")
                ssl_str = f"Geçerli ({ssl_info.get('issuer')}) | Yaş: {ssl_age} gün"
                if isinstance(ssl_age, int) and ssl_age < 3:
                    logger.info(f"      [!] SSL Sertifikası çok yeni ({ssl_age} gün)! (Phishing Potansiyeli)")
            else:
                ssl_str = f"Geçersiz ({ssl_info.get('error')})"
            logger.info(f"      -> SSL Durumu: {ssl_str}")

            # MX Kaydı
            mx_found = scanner.check_mx_records(domain)
            mx_str = "Mevcut" if mx_found else "YOK (Ciddi Şüphe)"
            logger.info(f"      -> MX Kaydı: {mx_str}")

            reputation = scanner.check_reputation(domain)
            logger.info(f"      -> İtibar Durumu: {reputation}")

            # Web Araması
            logger.info("[*] Web üzerinde domain hakkında bilgi toplanıyor...")
            web_search_results = web_tools.search_web(f'"{domain}" reviews scam phishing', count=5)
            
            if isinstance(web_search_results, list):
                logger.info(f"      -> {len(web_search_results)} sonuç bulundu.")
            else:
                logger.info(f"      -> Arama yapılamadı ({web_search_results})")
                web_search_results = None

            logger.info("[2/3] Site içeriği ve HTML yapısı analiz ediliyor (JS Destekli)...")
            site_content = scanner.scrape_site(url)
            
            if site_content and site_content.startswith("[SCANNER_FAIL]"):
                logger.error(f"      -> Hata: {site_content}")
                content_status = "Erişim Hatası"
            else:
                content_status = "Veri alındı" if site_content else "Veri alınamadı"
                logger.info(f"      -> İçerik Durumu: {content_status}")
                
                # Tele-Phish Özel Uyarısı
                if "Telegram Bot API" in site_content or "Sızıntı Riski" in site_content:
                    logger.critical("      [!!!] KRİTİK ANALİZ: Sitede gizli veri sızıntısı (Telegram) tespiti yapıldı!")

            # Yapay Zeka Analizi
            logger.info("[3/3] Yapay Zeka değerlendiriyor (OpenRouter)...")
            
            analysis_result = ai_analyzer.analyze_site_initial(
                age_str, 
                site_content, 
                reputation,
                ssl_info,
                mx_found,
                redirect_chain,
                web_search_results
            )

            # Hibrit Karar Mekanizması (Callback / Karar Değişimi)
            screenshot_b64 = None
            if analysis_result.get("decision") == "NEED_SCREENSHOT":
                logger.step("      -> AI görsel kanıt talep etti. Ekran görüntüsü alınıyor...")
                screenshot_path = scanner.take_screenshot(url)
                
                if screenshot_path:
                    logger.step("      -> Görsel analiz yapılıyor...")
                    
                    # Rapor için görseli belleğe al
                    with open(screenshot_path, "rb") as img_file:
                        screenshot_b64 = base64.b64encode(img_file.read()).decode('utf-8')
                        
                    analysis_result = ai_analyzer.analyze_with_screenshot(age_str, site_content, screenshot_path)
                    
                    # Analiz bittiğinde temizle
                    if os.path.exists(screenshot_path):
                        os.remove(screenshot_path)
                else:
                    logger.error("      [!] Ekran görüntüsü alınamadı, mevcut verilerle devam ediliyor.")
                    # Yeniden sormayı deneyebiliriz veya hata verebiliriz, ama şimdilik kararsız bırakalım
                    analysis_result["explanation"] += " (Görsel kanıt alınamadığı için karar netleştirilemedi.)"

            # Cache Integration (Save for future API/CLI use)
            if Config.CACHE_ENABLED:
                scan_data = {
                    "url": url,
                    "scan_time": datetime.now().isoformat(),
                    "domain": domain,
                    "redirect_chain": redirect_chain,
                    "technical_details": {
                        "domain_age_days": domain_age,
                        "reputation": reputation,
                        "ssl_info": ssl_info,
                        "has_mx_records": mx_found
                    },
                    "content_analysis": site_content
                }
                
                final_result = {
                    "scan_data": scan_data,
                    "ai_analysis": analysis_result
                }
                cache_manager.set(url, final_result)

            # Adım 3: Görsel Raporlama
            score = analysis_result.get("risk_score", 0)
            risk_level = analysis_result.get("risk_level", "BELİRSİZ")
            explanation = analysis_result.get("explanation", "Açıklama yok.")

            # Renk Kodlaması ve Kurumsal Puanlama (0-10)
            risk_level_upper = risk_level.upper()
            if risk_level_upper in ["ÇOK YÜKSEK", "CRITICAL", "VERY HIGH"]:
                verdict_color = Fore.RED + Style.BRIGHT
                verdict_text = "CRITICAL DANGER"
            elif risk_level_upper in ["YÜKSEK", "HIGH"]:
                verdict_color = Fore.MAGENTA + Style.BRIGHT
                verdict_text = "HIGH RISK"
            elif risk_level_upper in ["ORTA", "MEDIUM"]:
                verdict_color = Fore.YELLOW + Style.BRIGHT
                verdict_text = "MEDIUM RISK"
            else:
                verdict_color = Fore.GREEN + Style.BRIGHT
                verdict_text = "SAFE / LOW RISK"

            logger.banner("PHISHGUARD SECURITY ANALYSIS REPORT")
            
            logger.raw(f"VERDICT       : {verdict_color}{verdict_text}{Style.RESET_ALL}")
            logger.raw(f"RISK LEVEL    : {verdict_color}{risk_level}{Style.RESET_ALL}")
            logger.raw(f"RISK SCORE    : {verdict_color}{score}/10{Style.RESET_ALL}")
            
            logger.custom("-" * 50, Fore.CYAN)
            
            logger.step("\n[DETAILED ANALYSIS AND JUSTIFICATION]")
            logger.info(explanation)
            print("\n")

    except Exception as e:
        logger.exception(f"Beklenmeyen Hata: {e}")


if __name__ == "__main__":
    main()
