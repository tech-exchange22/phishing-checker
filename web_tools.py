from bs4 import BeautifulSoup
import requests
from ddgs import DDGS
from logger import logger
from utils import ProxyManager
from config import Config
import random

class WebTools:
    def __init__(self):
        self.proxy_manager = ProxyManager()
        self.headers = {
            "User-Agent": random.choice(Config.USER_AGENTS)
        }

    def search_web(self, query, count=Config.DDG_SEARCH_LIMIT):
        """
        Searches the web using DuckDuckGo (duckduckgo-search).
        """
        try:
            proxy = self.proxy_manager.get_random_proxy()
            # Proxy formatını düzenle (duckduckgo_search string bekler: http://user:pass@ip:port)
            proxy_url = None
            if proxy:
                proxy_url = proxy if proxy.startswith("http") else f"http://{proxy}"
            
            with DDGS(proxy=proxy_url) as ddgs:
                results = list(ddgs.text(query, max_results=count))
             # Convert generator to list
            formatted_results = []
            for r in results:
                body = r.get("body", "")
                if body and len(body) > 300:
                    body = body[:300] + "..."
                
                formatted_results.append({
                    "title": r.get("title"),
                    "url": r.get("href"),
                    "snippet": body
                })
            return formatted_results
        except Exception as e:
            # logger.exception automatically logs traceback
            logger.error(f"DuckDuckGo Search Error: {str(e)}")
            return f"Search Error: {str(e)}"

    def fetch_and_summarize(self, url):
        """
        Fetches the content of a URL and returns a summary (text content).
        """
        try:
            proxies = self.proxy_manager.get_requests_proxies()
            response = requests.get(url, headers=self.headers, timeout=Config.URL_FETCH_TIMEOUT, proxies=proxies, verify=False)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Remove scripts and styles
            for script in soup(["script", "style", "nav", "footer", "header"]):
                script.extract()
                
            text = soup.get_text()
            
            # Clean up text
            lines = (line.strip() for line in text.splitlines())
            chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
            text = '\n'.join(chunk for chunk in chunks if chunk)
            
            # Limit to Config.SUMMARY_CHAR_LIMIT chars to avoid token limits
            limit = Config.SUMMARY_CHAR_LIMIT
            return text[:limit] + "..." if len(text) > limit else text
            
        except Exception as e:
            logger.error(f"URL Fetch Error ({url}): {str(e)}")
            return f"Error fetching URL: {str(e)}"