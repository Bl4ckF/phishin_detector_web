from flask import Flask, request, jsonify, render_template
import re
import requests

app = Flask(__name__)

# Configurações da API do Google Safe Browsing
API_KEY = "SUA_CHAVE_DE_API_AQUI"  # Substitua pela sua chave de API
API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# Lista de domínios maliciosos conhecidos (blacklist)
BLACKLIST = [
    "phishingsite.com",
    "maliciousdomain.net",
    "fakebanklogin.org"
]

# Palavras-chave suspeitas comuns em URLs de phishing
SUSPICIOUS_KEYWORDS = [
    "login",
    "bank",
    "secure",
    "account",
    "update",
    "verify"
]

def check_google_safe_browsing(url):
    """
    Verifica se uma URL é maliciosa usando a API do Google Safe Browsing.
    """
    payload = {
        "client": {
            "clientId": "seusistema",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "THREAT_TYPE_UNSPECIFIED"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    params = {"key": API_KEY}
    try:
        response = requests.post(API_URL, json=payload, params=params)
        if response.status_code == 200:
            data = response.json()
            if data.get("matches"):
                return True, "URL maliciosa detectada pelo Google Safe Browsing."
        return False, "URL segura conforme o Google Safe Browsing."
    except Exception as e:
        return False, f"Erro ao verificar a URL: {str(e)}"

def is_url_suspicious(url):
    """
    Verifica se uma URL é suspeita com base em regras simples e na API do Google Safe Browsing.
    """
    # Verifica se o domínio está na blacklist
    domain = re.findall(r"https?://([^/]+)", url)
    if domain and domain[0] in BLACKLIST:
        return True, "Domínio na blacklist."

    # Verifica palavras-chave suspeitas na URL
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url.lower():
            return True, f"Palavra-chave suspeita encontrada: {keyword}."

    # Verifica se a URL é muito longa (potencialmente suspeita)
    if len(url) > 100:
        return True, "URL muito longa."

    # Verifica a URL usando a API do Google Safe Browsing
    is_malicious, reason = check_google_safe_browsing(url)
    if is_malicious:
        return True, reason

    # Se nenhuma regra for violada, a URL é considerada segura
    return False, "URL parece segura."

@app.route("/")
def index():
    """Renderiza a página inicial."""
    return render_template("index.html")

@app.route("/check-url", methods=["POST"])
def check_url():
    """Verifica se a URL é suspeita."""
    data = request.get_json()  # Use get_json() para obter os dados JSON
    url = data.get("url")

    if not url:
        return jsonify({"error": "URL não fornecida."}), 400

    is_suspicious, reason = is_url_suspicious(url)
    return jsonify({"is_suspicious": is_suspicious, "reason": reason})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
