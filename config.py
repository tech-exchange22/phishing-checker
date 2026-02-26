import os
from dotenv import load_dotenv

# Load environment variables (only for secrets like API keys)
load_dotenv()

class Config:
    # --------------------------------------------------------------------------
    # API Configuration
    # --------------------------------------------------------------------------
    OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
    if not OPENROUTER_API_KEY:
         raise ValueError("OPENROUTER_API_KEY .env dosyasında bulunamadı! Lütfen .env dosyasını kontrol edin.")
         
    OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1/chat/completions"
    
    # --------------------------------------------------------------------------
    # AI Model Configuration (Hardcoded as requested)
    # --------------------------------------------------------------------------
    AI_PRIMARY_MODEL = "openrouter/free"
    
    AI_FALLBACK_MODELS = [
        "google/gemini-2.5-flash-lite"
    ]

    # --------------------------------------------------------------------------
    # Scanner Configuration
    # --------------------------------------------------------------------------
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0"
    ]
    
    # Domain Whitelist for Reputation Check
    DOMAIN_WHITELIST = [
        "google.com", "microsoft.com", "apple.com", "amazon.com", 
        "facebook.com", "twitter.com", "instagram.com", "linkedin.com", 
        "netflix.com", "paypal.com", "github.com", "ebank.com", "yahoo.com",
        "bing.com", "duckduckgo.com", "turkiye.gov.tr", "outlook.com",
        "live.com", "icloud.com", "dropbox.com", "salesforce.com"
    ]

    SUSPICIOUS_KEYWORDS = [
        "secure", "login", "verify", "update", "signin", "bank", 
        "account", "service", "confirm", "wallet", "crypto", "billing",
        "invoice", "password", "security", "alert", "notification",
        "limited", "suspended", "action", "urgency", "bonus", "reward"
    ]

    SUSPICIOUS_TLDS = [
        ".xyz", ".top", ".club", ".info", ".zip", ".review", 
        ".country", ".stream", ".gq", ".cf", ".tk", ".ml", ".ga",
        ".app", ".icu", ".buzz", ".cam", ".monster", ".work", ".bond",
        ".fit", ".live", ".store", ".solutions", ".support"
    ]

    # --------------------------------------------------------------------------
    # Web Tools Configuration
    # --------------------------------------------------------------------------
    DDG_SEARCH_LIMIT = 5
    URL_FETCH_TIMEOUT = 10
    SUMMARY_CHAR_LIMIT = 2000
    
    # --------------------------------------------------------------------------
    # File Paths & Directories
    # --------------------------------------------------------------------------
    PROXIES_FILE = "proxies.txt"
    LOGS_DIR = "logs"
    LOG_LEVEL = "DEBUG"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    LOG_MAX_BYTES = 5 * 1024 * 1024  # 5 MB
    LOG_BACKUP_COUNT = 5

    # --------------------------------------------------------------------------
    # AI Request Configuration
    # --------------------------------------------------------------------------
    AI_REQUEST_TIMEOUT = 60
    AI_RETRY_COUNT = 2
    AI_RETRY_DELAY = 2

    # --------------------------------------------------------------------------
    # API Configuration
    # --------------------------------------------------------------------------
    API_ENABLED = True
    API_HOST = "0.0.0.0"  # Dışarıdan erişim açık (Docker vb.)
    API_PORT = 8091
    ALLOWED_IPS = ["127.0.0.1", "::1", "178.18.247.156"]  # IP Whitelist. Gerektiğinde ekleyin.

    # --------------------------------------------------------------------------
    # Cache Configuration
    # --------------------------------------------------------------------------
    CACHE_ENABLED = True
    CACHE_TYPE = "disk"  # Options: "disk", "memory"
    CACHE_DIR = "cache_data"
    CACHE_TTL = 3600  # Varsayılan önbellek süresi (saniye) - 1 saat

    BANNER_TEXT = """
PHISHGUARD AI v1.0
Yapay Zeka Destekli Oltalama Avcısı
    """.strip()
