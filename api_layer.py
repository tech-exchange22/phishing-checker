from fastapi import FastAPI, Request, HTTPException, Depends
from pydantic import BaseModel
from scanner import Scanner
from ai_analyzer import AIAnalyzer
from config import Config
from utils import CacheManager
from logger import logger
import uvicorn
import os
import json

app = FastAPI(title="PhishGuard AI API", version="1.0")

# Cache yöneticisini başlat
cache_manager = CacheManager()

class AnalysisRequest(BaseModel):
    url: str

# IP Doğrulama Bağımlılığı
def verify_ip(request: Request):
    if not Config.API_ENABLED:
         raise HTTPException(status_code=503, detail="API is disabled via configuration")
         
    client_ip = request.client.host
    
    # Whitelist kontrolü
    if client_ip not in Config.ALLOWED_IPS and client_ip != "127.0.0.1" and client_ip != "::1":
        logger.warning(f"[API] Yetkisiz erişim denemesi: {client_ip}")
        raise HTTPException(status_code=403, detail="Unauthorized IP Address")
    
    return True

def get_cached_analysis(url: str):
    """URL için önbellekteki analizi döner"""
    if not Config.CACHE_ENABLED:
        return None
    return cache_manager.get(url)

@app.post("/analyze", dependencies=[Depends(verify_ip)])
def analyze_url(request: AnalysisRequest):
    url = request.url
    
    # 1. Önbellek Kontrolü
    cached_result = get_cached_analysis(url)
    if cached_result:
        logger.info(f"[API] Cache hit for: {url}")
        return {
            "url": url,
            "cached": True,
            "status": "success",
            "result": cached_result
        }

    logger.info(f"[API] New analysis request for: {url}")

    try:
        scan_results = {}
        ai_result = {}
        
        # 2. Scanner ile veri topla
        with Scanner() as scanner:
            scan_results = scanner.full_scan(url)
            
            # Hata kontrolü
            if scan_results.get("error"):
                 # Hata durumunu loglayıp 400 bad request dönebiliriz.
                 # Ancak analiz devam edebilir mi? Genelde hayır.
                 # Eğer basit bir hata ise (URL parse hatası vb.) durmalı.
                 raise HTTPException(status_code=400, detail=scan_results["error"])

            # 3. AI Analizi
            ai_analyzer = AIAnalyzer()
            
            # Verileri hazırla
            tech_details = scan_results.get("technical_details", {})
            domain_age = tech_details.get("domain_age_days")
            age_str = f"{domain_age} days" if domain_age is not None else "Unknown"
            
            # AI Initial call
            # Not: recursive search şu an için API'de varsayılan olarak kapalı olabilir
            # veya açık olabilir (uzun sürebilir)
            
            ai_result = ai_analyzer.analyze_site_initial(
                domain_age=age_str,
                site_text=scan_results.get("content_analysis", ""),
                reputation_status=tech_details.get("reputation", "Unknown"),
                ssl_info=tech_details.get("ssl_info", {}),
                mx_found=tech_details.get("has_mx_records", False),
                redirect_chain=scan_results.get("redirect_chain", []),
                recursive=True 
            )
            
            # Screenshot based analysis (IfNeeded)
            screenshot_path = scan_results.get("screenshot_path")
            
            if ai_result.get("decision") == "NEED_SCREENSHOT":
                if screenshot_path and os.path.exists(screenshot_path):
                    logger.info("[API] Performing secondary image analysis...")
                    # Update result
                    ai_result = ai_analyzer.analyze_with_screenshot(
                        domain_age=age_str,
                        site_text=scan_results.get("content_analysis", ""),
                        screenshot_path=screenshot_path
                    )
                else:
                    ai_result["explanation"] += " (Screenshot requested but not available)"

            # Clean up temporary screenshot
            if screenshot_path and os.path.exists(screenshot_path):
                try:
                    os.remove(screenshot_path)
                except:
                    pass
                scan_results["screenshot_path"] = None # Remove path from result
                
        # 4. Sonucu Cache'le
        final_result = {
            "scan_data": scan_results,
            "ai_analysis": ai_result
        }
        
        if Config.CACHE_ENABLED:
            cache_manager.set(url, final_result)

        return {
            "url": url,
            "cached": False,
            "status": "success",
            "result": final_result
        }

    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"[API] Analiz hatası: {e}")
        # Detaylı hatayı loga yaz ama kullanıcıya genel hata dön
        raise HTTPException(status_code=500, detail=f"Internal Server Analysis Error: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=Config.API_HOST, port=Config.API_PORT)
