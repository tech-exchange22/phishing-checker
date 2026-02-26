# PhishGuard AI - API Dokümantasyonu

PhishGuard AI API, web sitelerini phishing (oltalama) risklerine karşı tarayan ve yapay zeka destekli analiz sunan yüksek performanslı bir arayüzdür. FastAPI üzerine inşa edilmiştir ve gerçek zamanlı analiz yetenekleri sunar.

## 1. Hızlı Başlangıç

API sunucusunu başlatmak için aşağıdaki komutu terminalde çalıştırın:

```powershell
python api_layer.py
```

Varsayılan olarak sunucu `http://0.0.0.0:8000` adresinde dinlemeye başlayacaktır.

## 2. Yapılandırma

API ayarları `config.py` dosyası üzerinden yönetilir:

- **API_ENABLED**: API'nin aktif olup olmadığını belirler.
- **API_HOST / API_PORT**: Sunucunun dinleyeceği adres ve port (Varsayılan: 0.0.0.0:8000).
- **ALLOWED_IPS**: API'ye erişim izni olan IP adreslerinin listesi (Whitelist). Güvenlik için sadece güvenilir IP'leri buraya ekleyin.

## 3. API Uç Noktaları (Endpoints)

### URL Analiz Et
**POST** `/analyze`

Web sitesini tarar, teknik verileri toplar ve yapay zeka ile risk analizi yapar.

**İstek Gövdesi (Request Body):**

```json
{
  "url": "https://example-phishing-site.com"
}
```

**Başarılı Yanıt (Success Response - 200 OK):**

```json
{
  "url": "https://example-phishing-site.com",
  "cached": false,
  "status": "success",
  "result": {
    "scan_data": {
      "technical_details": {
        "domain_age_days": 15,
        "reputation": "Suspicious",
        "ssl_info": { ... },
        "has_mx_records": true
      },
      "content_analysis": "..."
    },
    "ai_analysis": {
      "risk_score": 85,
      "decision": "PHISHING",
      "explanation": "Bu site oltalama belirtileri gösteriyor...",
      "detected_flags": ["NEW_DOMAIN", "SUSPICIOUS_CONTENT"]
    }
  }
}
```

**Hata Yanıtları:**

- **400 Bad Request**: Geçersiz URL formatı veya tarama hatası.
- **403 Forbidden**: IP adresi beyaz listede (whitelist) değil.
- **503 Service Unavailable**: API yapılandırmada devre dışı bırakılmış.

## 4. Güvenlik ve Performans

- **IP Whitelisting**: API, yetkisiz erişimi engellemek için IP tabanlı kısıtlama kullanır. Erişim için IP adresinizi `config.py` içindeki `ALLOWED_IPS` listesine eklemelisiniz.
- **Önbellekleme (Caching)**: Aynı URL için mükerrer analizleri önlemek adına sistem disk tabanlı önbellekleme kullanır. Önbellek süresi `Config.CACHE_TTL` ile ayarlanabilir.
- **Asenkron Çalışma**: Tarama ve AI analiz süreçleri paralel izlenebilir şekilde tasarlanmıştır.

## 5. Örnek Kullanım (cURL)

```bash
curl -X POST "http://localhost:8000/analyze" \
     -H "Content-Type: application/json" \
     -d '{"url": "https://www.google.com"}'
```

---
*Not: API'nin tam fonksiyonel çalışması için geçerli bir `OPENROUTER_API_KEY` değişkeninin `.env` dosyasında tanımlı olması gerekmektedir.*
