import logging
import os
import sys
import re
from logging.handlers import RotatingFileHandler
from colorama import Fore, Style, init
from config import Config

# Initialize colorama
init(autoreset=True)

# Custom Logging Levels
SUCCESS = 25
STEP = 22
logging.addLevelName(SUCCESS, "SUCCESS")
logging.addLevelName(STEP, "ADIM")

class ColoredFormatter(logging.Formatter):
    """
    Konsol çıktısı için renkli ve sembollü formatlayıcı.
    Okunabilirliği artırmak için emoji ve renk kodları kullanır.
    """
    
    # Görsel mantık için ikonlar
    ICONS = {
        logging.DEBUG: "🐛",      # Debug -> Böcek
        logging.INFO: "ℹ️",       # Info -> Bilgi
        logging.WARNING: "⚠️",     # Warning -> Uyarı
        logging.ERROR: "❌",      # Error -> Hata
        logging.CRITICAL: "🚨",   # Critical -> Kritik
        SUCCESS: "✅",            # Success -> Onay
        STEP: "➡️",              # Step -> İlerleme
    }

    COLORS = {
        logging.DEBUG: Fore.LIGHTBLACK_EX,
        logging.INFO: Fore.WHITE,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.RED + Style.BRIGHT,
        SUCCESS: Fore.GREEN,
        STEP: Fore.CYAN,
    }

    def format(self, record):
        log_color = self.COLORS.get(record.levelno, Fore.WHITE)
        icon = self.ICONS.get(record.levelno, "")
        
        # Mesajı al
        message = record.getMessage()
        
        # Banner kontrolü (özel durum)
        if hasattr(record, 'is_banner') and record.is_banner:
            log_color = Fore.CYAN + Style.BRIGHT
            border = "=" * 60
            lines = message.split('\n')
            centered_lines = [line.strip().center(60) for line in lines if line.strip()]
            formatted_banner = f"\n{log_color}{border}\n" + "\n".join(centered_lines) + f"\n{border}{Style.RESET_ALL}\n"
            return formatted_banner

        # Saat formatı (Console için sade)
        time_str = self.formatTime(record, "%H:%M:%S")

        # Standart Format: [SAAT] [IKON] MESAJ
        # Hata durumlarında yer bilgisi ekle
        if record.levelno >= logging.ERROR:
            location = f"[{record.module}:{record.lineno}]"
            format_str = f"{Fore.LIGHTBLACK_EX}[{time_str}]{Style.RESET_ALL} {icon} {log_color}{message}{Style.RESET_ALL} {Fore.LIGHTBLACK_EX}{location}{Style.RESET_ALL}"
        elif record.levelno == logging.DEBUG:
            format_str = f"{Fore.LIGHTBLACK_EX}[{time_str}] {icon} [DEBUG] {message} [{record.module}:{record.lineno}]{Style.RESET_ALL}"
        else:
            format_str = f"{Fore.LIGHTBLACK_EX}[{time_str}]{Style.RESET_ALL} {icon} {log_color}{message}{Style.RESET_ALL}"

        return format_str

class FileFormatter(logging.Formatter):
    """
    Dosya logları için detaylı, yapılandırılmış formatlayıcı.
    Kullanıcı: 'Log sistemini çok daha detaylı ve tutarlı/mantıklı hale getir'
    Bu format, regex veya grep ile analiz edilebilir yapıdadır.
    """
    
    def format(self, record):
        # ANSI kodlarını temizle (dosyada renk kodları olmamalı)
        message = record.getMessage()
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        clean_message = ansi_escape.sub('', message)
        
        # Tutarlı Ayrıştırıcı Formatı:
        # TARIH | SEVIYE | PROCESS:THREAD | MODUL:FONKSIYON:SATIR | MESAJ
        
        process_info = f"{record.process}" 
        # Fonksiyon adı da ekleyerek detay seviyesini artırıyoruz
        location = f"{record.module}:{record.funcName}:{record.lineno}"
        
        timestamp = self.formatTime(record, "%Y-%m-%d %H:%M:%S")
        level_name = record.levelname
        
        # Hizalama ile okunabilirlik
        return f"{timestamp} | {level_name:<8} | PID:{process_info:<5} | {location:<30} | {clean_message}"

class Logger:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(Logger, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
            
        self.log_dir = Config.LOGS_DIR
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
        
        self.log_file = os.path.join(self.log_dir, "phishguard.log")
        
        # Ana logger oluştur
        self.logger = logging.getLogger("PhishGuard")
        self.logger.setLevel(logging.DEBUG) # Kök seviyesi DEBUG olsun, handler'lar filtrelesin
        self.logger.propagate = False # Root logger'a tırmanmasını engelle (duplicate önleme)

        # Varolan handler'ları temizle
        if self.logger.hasHandlers():
            self.logger.handlers.clear()

        # 1. Dosya İşleyicisi (Detaylı, Dönen Dosya)
        try:
            file_handler = RotatingFileHandler(
                self.log_file, 
                maxBytes=Config.LOG_MAX_BYTES, 
                backupCount=Config.LOG_BACKUP_COUNT, 
                encoding='utf-8'
            )
            file_handler.setLevel(logging.DEBUG) # Dosyaya HER ŞEYİ, en ince detayıyla yaz
            file_handler.setFormatter(FileFormatter())
            self.logger.addHandler(file_handler)
        except Exception as e:
            print(f"Log dosyası işleyicisi başlatılamadı: {e}")

        # 2. Konsol İşleyicisi (Kullanıcı Dostu)
        console_handler = logging.StreamHandler(sys.stdout)
        
        # Config'den seviye ayarla (Varsayılan INFO)
        # Kullanıcı sadece önemli şeyleri görsün
        config_level_name = Config.LOG_LEVEL.upper()
        console_level = getattr(logging, config_level_name, logging.INFO)
        console_handler.setLevel(console_level)
        
        console_handler.setFormatter(ColoredFormatter())
        self.logger.addHandler(console_handler)
        
        self._initialized = True

    def debug(self, message):
        """Geliştirici notları (gri)"""
        self.logger.debug(message)

    def info(self, message):
        """Genel bilgilendirme (beyaz)"""
        self.logger.info(message)

    def warning(self, message):
        """Uyarılar (sarı)"""
        self.logger.warning(message)

    def error(self, message):
        """Hatalar (kırmızı)"""
        self.logger.error(message)

    def critical(self, message):
        """Kritik hatalar (parlak kırmızı)"""
        self.logger.critical(message)
    
    def exception(self, message):
        """Exception traceback ile logla"""
        self.logger.exception(message)

    def success(self, message):
        """Başarılı işlem (yeşil)"""
        self.logger.log(SUCCESS, message)

    def step(self, message):
        """İşlem adımı (camgöbeği)"""
        self.logger.log(STEP, message)
        
    def banner(self, message):
        """Özel banner formatı"""
        self.logger.info(message, extra={'is_banner': True})

    def custom(self, message, color=None):
        """Geriye dönük uyumluluk için"""
        self.logger.info(message)

    def raw(self, message):
        """İşlenmemiş ham mesaj"""
        self.logger.info(message)

# Global Instance
logger = Logger()
