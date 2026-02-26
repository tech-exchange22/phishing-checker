🛡️ PhishGuard - Website Security Analysis Tool
PhishGuard is an AI-powered security tool that analyzes whether a website is fraudulent (phishing/scam) or legitimate.
🔍 What Does It Do?

SSL Certificate check (is it valid? how old?)
WHOIS / Domain age lookup
MX record verification
Reputation analysis
Redirect chain detection
Web search about the target domain
Takes a screenshot for visual analysis when needed
Evaluates all data using AI (OpenRouter) and gives a risk score

⚙️ Installation & Usage
Requirements

Python 3.8+
OpenRouter API key

Steps
bash# Clone the repo
git clone https://github.com/tech-exchange22/phishing-checker.git
cd phishing-checker

# Setup and run
python3 setup_and_run.py
API Key Setup
Create a .env file and add your OpenRouter API key:
OPENROUTER_API_KEY=your_api_key_here

Get your OpenRouter API key at: https://openrouter.ai

📊 Example Output
VERDICT       : CRITICAL DANGER
RISK LEVEL    : VERY HIGH
RISK SCORE    : 9/10
🐛 Bug Reports & Feedback
Found a bug or have a suggestion? Feel free to open an issue in the Issues tab.
📄 License
MIT License
