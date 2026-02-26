import os
import socket
import ipaddress
from datetime import datetime
import tiktoken
from PIL import Image
import io
import base64
import random
import shutil
from diskcache import Cache
from config import Config
from logger import logger

class ProxyManager:
    """
    Basitleştirilmiş Proxy Yöneticisi.
    Config.PROXIES_FILE dosyasından proxy listesini okur.
    """
    def __init__(self, proxy_file=None):
        self.proxy_file = proxy_file or Config.PROXIES_FILE
        self.proxies = self._load_proxies()

    def _load_proxies(self):
        if not os.path.exists(self.proxy_file):
            return []
        try:
            with open(self.proxy_file, "r", encoding="utf-8") as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error(f"Proxy dosyası okuma hatası: {e}")
            return []

    def get_random_proxy(self):
        return random.choice(self.proxies) if self.proxies else None

    def get_requests_proxies(self):
        proxy = self.get_random_proxy()
        if not proxy: return None
        url = proxy if proxy.startswith("http") else f"http://{proxy}"
        return {"http": url, "https": url}

    def get_playwright_proxy(self):
        proxy = self.get_random_proxy()
        if not proxy: return None
        
        # Basit parsing: http://user:pass@ip:port veya ip:port
        server = proxy
        username = password = None

        if "@" in proxy:
            # Şema varsa temizle
            clean_proxy = proxy.replace("http://", "").replace("https://", "")
            auth, endpoint = clean_proxy.split("@")
            server = f"http://{endpoint}"
            if ":" in auth:
                username, password = auth.split(":", 1)
        elif not proxy.startswith("http"):
            server = f"http://{proxy}"

        config = {"server": server}
        if username: 
            config.update({"username": username, "password": password})
        return config

def estimate_tokens(text, encoding_name="cl100k_base"):
    """
    OpenAI token sayımı (yaklaşık).
    """
    try:
        encoding = tiktoken.get_encoding(encoding_name)
        return len(encoding.encode(text))
    except Exception:
        # Fallback: Ortalama 4 karakter = 1 token
        return len(text) // 4

def optimize_image_for_ai(image_path, max_dimension=1024, quality=75):
    """
    Görseli sıkıştırıp base64 döndürür (Token Optimizasyonu).
    """
    try:
        with Image.open(image_path) as img:
            # Alpha kanalını kaldır (PNG -> JPG)
            if img.mode in ("RGBA", "P"):
                img = img.convert("RGB")
            
            # Yeniden boyutlandır (Thumbnail oranı korur)
            img.thumbnail((max_dimension, max_dimension))
            
            buffer = io.BytesIO()
            img.save(buffer, format="JPEG", quality=quality)
            return base64.b64encode(buffer.getvalue()).decode("utf-8")
    except Exception as e:
        print(f"Görsel optimizasyon hatası: {e}")
        # Hata durumunda orijinali dön (Safe fails)
        with open(image_path, "rb") as f:
            return base64.b64encode(f.read()).decode("utf-8")

def is_safe_ip(ip_or_domain):
    """
    SSRF Koruması: Verilen girdinin (IP veya Domain) yerel ağa işaret edip etmediğini kontrol eder.
    Eğer domain verilirse önce IP'sini çözer.
    """
    try:
        # IP olup olmadığını kontrol et
        try:
            ip_obj = ipaddress.ip_address(ip_or_domain)
        except ValueError:
            # Domain ise çözümle
            ip = socket.gethostbyname(ip_or_domain)
            ip_obj = ipaddress.ip_address(ip)

        # Yasaklı aralık kontrolü
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
            return False
        
        return True
    except Exception as e:
        return False


class CacheManager:
    """
    Basit ve etkili bir önbellek yöneticisi.
    DiskCache kütüphanesini kullanır ve config.py'den yönetilir.
    """
    _instance = None
    _cache = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(CacheManager, cls).__new__(cls)
            cls._instance._init_cache()
        return cls._instance

    def _init_cache(self):
        if not Config.CACHE_ENABLED:
            logger.info("Cache sistemi devre dışı.")
            return

        cache_dir = Config.CACHE_DIR
        # Cache dizini yoksa oluştur
        if not os.path.exists(cache_dir):
            os.makedirs(cache_dir, exist_ok=True)
            
        try:
            # Singleton benzeri cache instance
            self._cache = Cache(cache_dir)
            # logger.info(f"Cache sistemi aktif: {cache_dir}") # Çok fazla log basmaması için kapalı
        except Exception as e:
            logger.error(f"Cache başlatılamadı: {e}")
            self._cache = None

    def get(self, key):
        if not self._cache:
            return None
        return self._cache.get(key)

    def set(self, key, value, expire=None):
        if not self._cache:
            return False
        if expire is None:
            expire = Config.CACHE_TTL
        self._cache.set(key, value, expire=expire)
        return True

    def delete(self, key):
        if self._cache:
            return self._cache.delete(key)
        return False

    def clear(self):
        if self._cache:
            return self._cache.clear()
        return False

    def close(self):
        if self._cache:
            self._cache.close()

