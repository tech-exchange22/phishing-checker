import os
import json
import base64
import time
import requests
from datetime import datetime
from config import Config
from logger import logger
from prompts import SYSTEM_PROMPT, INITIAL_ANALYSIS_PROMPT, SCREENSHOT_ANALYSIS_PROMPT, RESEARCH_AGENT_PROMPT
from utils import optimize_image_for_ai, estimate_tokens
from web_tools import WebTools

class AIAnalyzer:
    def __init__(self):
        self.api_key = Config.OPENROUTER_API_KEY
        self.base_url = Config.OPENROUTER_BASE_URL
        self.web_tools = WebTools()
        
        # Ana model ve fallback modelleri yükle
        self.models = [Config.AI_PRIMARY_MODEL] + Config.AI_FALLBACK_MODELS
        
        # Listeyi temizle (None değerleri at)
        self.models = [m for m in self.models if m]
        
        if not self.models:
            raise ValueError("Herhangi bir AI model ID'si bulunamadı!")

        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "HTTP-Referer": "", 
            "X-Title": "PhishGuard",
            "Content-Type": "application/json"
        }

    def _call_with_retry(self, messages, retries=2, delay=2):
        """
        API çağrısını fallback modelleri ve retry mekanizması ile gerçekleştirir.
        """
        last_exception = None
        
        for model in self.models:
            payload = {
                "model": model,
                "messages": messages,
                "response_format": {"type": "json_object"}
            }

            for i in range(retries):
                try:
                    logger.debug(f"[AI] {model} kullanılıyor... (Deneme {i+1})")
                    response = requests.post(
                        self.base_url,
                        headers=self.headers,
                        data=json.dumps(payload),
                        timeout=Config.AI_REQUEST_TIMEOUT
                    )
                    
                    if response.status_code == 200:
                        try:
                            resp_json = response.json()
                            content = resp_json['choices'][0]['message']['content']
                            return json.loads(content)
                        except (KeyError, json.JSONDecodeError) as e:
                            logger.error(f"Yanıt parse hatası: {e}")
                            raise ValueError(f"Yanıt parse hatası: {e}")
                    
                    elif response.status_code in [429, 502, 503, 504]:
                        logger.warning(f"[AI] Geçici hata ({response.status_code}), yeniden deneniyor...")
                        if i < retries - 1:
                            time.sleep(delay * (i + 1))
                            continue
                    
                    # Diğer hatalarda veya retries bittiyse bir sonraki modele geç
                    break

                except Exception as e:
                    last_exception = e
                    logger.debug(f"[AI] Model hatası ({model}): {str(e)}")
                    if i < retries - 1:
                        time.sleep(delay * (i + 1))
                        continue
                    break
            
            logger.warning(f"[AI] {model} başarısız oldu, varsa fallback modele geçiliyor.")
        
        raise last_exception or Exception("Tüm modeller başarısız oldu.")

    def perform_deep_research(self, initial_query):
        """
        Otonom alt ajan (Sub-Agent) döngüsünü çalıştırır.
        """
        logger.step(f"Araştırma başlatılıyor: {initial_query}")
        
        history = [
            {"role": "system", "content": RESEARCH_AGENT_PROMPT},
            {"role": "user", "content": f"Investigate this: {initial_query}"}
        ]
        
        max_steps = 5
        for step in range(max_steps):
            try:
                # Agent yanıtı al
                response = self._call_with_retry(history, retries=1) # Daha az retry yeterli
                
                thought = response.get("thought", "")
                action = response.get("action", "")
                param = response.get("parameter", "")

                logger.debug(f"[Agent Step {step+1}] {action}: {param}")
                
                if action == "finish":
                    return param
                
                observation = ""
                if action == "search":
                    # search_web returns list of dicts, format it for agent
                    results = self.web_tools.search_web(param, count=3)
                    observation = json.dumps(results)
                elif action == "visit":
                    observation = self.web_tools.fetch_and_summarize(param)
                else:
                    observation = "Invalid action. Use 'search', 'visit', or 'finish'."
                
                # History güncelle
                history.append({"role": "assistant", "content": json.dumps(response)})
                history.append({"role": "user", "content": f"Observation: {observation}"})
                
            except Exception as e:
                logger.error(f"[Agent Error] {e}")
                return f"Research interrupted by error: {e}"
                
        return "Research loop timed out without final conclusion."

    def analyze_site_initial(self, domain_age, site_text, reputation_status, ssl_info, mx_found, redirect_chain, web_search_results=None, recursive=True):
        """
        İlk analizi yapar. Eğer gerekirse görsel talep eder veya alt ajan çalıştırır.
        """
        current_date = datetime.now().strftime("%d %B %Y")
        
        mx_str = "FOUND" if mx_found else "NOT FOUND (Potential phishing indicator)"
        ssl_str = f"Valid: {ssl_info.get('valid')}, Issuer: {ssl_info.get('issuer')}"
        redirect_str = " -> ".join(redirect_chain) if redirect_chain else "None"
        
        search_str = "Veri Yok"
        if web_search_results:
             search_lines = []
             for res in web_search_results:
                 title = res.get('title', 'No Title')
                 # Support both field names
                 desc = res.get('snippet') or res.get('description', '')
                 desc = desc[:200]
                 search_lines.append(f"- {title}: {desc}")
             search_str = "\n".join(search_lines)

        # Token Kontrolü (Fallback)
        # Search sonuçları ve site metni için token hesapla
        MAX_TOKENS = 12000  # Context window güvenliği için sınır
        
        full_text = f"{search_str}\n{site_text}"
        token_count = estimate_tokens(full_text)
        
        if token_count > MAX_TOKENS:
             logger.warning(f"Token limiti aşıldı ({token_count}), içerik kırpılıyor...")
             # Basit oranlama ile karakter kırpma (ortalama 4 char/token)
             # Daha kesin çözüm için chunking yapılabilir ama şimdilik hızlı çözüm:
             ratio = MAX_TOKENS / token_count
             new_len_search = int(len(search_str) * ratio)
             new_len_site = int(len(site_text) * ratio)
             
             search_str = search_str[:new_len_search] + "..."
             site_text = site_text[:new_len_site] + "..."

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT.format(current_date=current_date)},
            {"role": "user", "content": INITIAL_ANALYSIS_PROMPT.format(
                domain_age=domain_age,
                reputation_status=reputation_status,
                ssl_str=ssl_str,
                mx_str=mx_str,
                redirect_str=redirect_str,
                search_str=search_str,
                site_text=site_text
            )}
        ]

        try:
            response = self._call_with_retry(messages=messages)
            
            # Sub-Agent Trigger Logic
            if recursive and response.get("decision") == "NEED_RESEARCH":
                query = response.get("research_query")
                if not query:
                    query = "Check this domain for phishing signs"
                
                # Run the sub-agent
                report = self.perform_deep_research(query)
                
                # Add results to the context and re-run
                new_results = web_search_results or []
                new_results.append({
                    "title": "AGENTS RESEARCH REPORT",
                    "description": report,
                    "snippet": report,
                    "url": "internal:agent"
                })
                
                # Recursive call with recursive=False to prevent infinite loop
                return self.analyze_site_initial(
                    domain_age, site_text, reputation_status, ssl_info, mx_found, redirect_chain, 
                    web_search_results=new_results, recursive=False
                )
            
            return response

        except Exception as e:
            logger.exception(f"AI Analiz Hatası: {str(e)}")
            return {"risk_score": -1, "decision": "ERROR", "explanation": f"Analiz Hatası: {str(e)}"}

    def analyze_with_screenshot(self, domain_age, site_text, screenshot_path):
        """
        Ekran görüntüsü ile hibrit analiz yapar.
        """
        current_date = datetime.now().strftime("%d %B %Y")
        
        # Görseli optimize et (Token tasarrufu)
        img_data = optimize_image_for_ai(screenshot_path)

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT.format(current_date=current_date)},
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": SCREENSHOT_ANALYSIS_PROMPT.format(
                            current_date=current_date,
                            domain_age=domain_age,
                            site_text=site_text
                        )
                    },
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:image/png;base64,{img_data}"
                        }
                    }
                ]
            }
        ]

        try:
            return self._call_with_retry(
                messages=messages
            )
        except Exception as e:
            logger.exception(f"AI Görsel Analiz Hatası: {str(e)}")
            return {"risk_score": -1, "decision": "ERROR", "explanation": f"Görsel Analiz Hatası: {str(e)}"}
