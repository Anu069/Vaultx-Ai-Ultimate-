import re
import math
import string
import requests
from flask import current_app
from datetime import datetime, timedelta

COMMON_PASSWORDS = {
    'password', '123456', 'password123', 'admin', 'letmein', 'qwerty',
    'abc123', 'monkey', '1234567890', 'master', 'dragon', 'pass', 
    'welcome', 'shadow', 'sunshine', 'princess', 'iloveyou', 'football'
}

PHISHING_INDICATORS = [
    r'paypa[l1]', r'arnazon', r'g[o0]{2}gle', r'faceb[o0]{2}k',
    r'micr[o0]s[o0]ft', r'app[l1]e', r'netf[l1][i1]x', r'[a@]maz[o0]n',
    r'verify.*account', r'confirm.*password', r'urgent.*action',
    r'suspended.*account', r'click.*here.*immediately'
]

SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.top', '.xyz', '.click', '.download'}

def calculate_password_strength(password: str) -> dict:
    if not password:
        return {'score': 0, 'label': 'No Password', 'color': '#666', 'issues': [], 'suggestions': []}
    
    score = 0
    issues = []
    suggestions = []
    
    length = len(password)
    if length < 8:
        issues.append('Too short (minimum 8 characters)')
    elif length < 12:
        score += 10
        suggestions.append('Use 12+ characters for better security')
    elif length < 16:
        score += 20
    else:
        score += 30

    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    
    if has_upper: score += 10
    else: issues.append('Add uppercase letters')
    if has_lower: score += 10
    else: issues.append('Add lowercase letters')
    if has_digit: score += 10
    else: issues.append('Add numbers')
    if has_special: score += 20
    else: suggestions.append('Add special characters (!@#$%...)')

    # Entropy
    charset = 0
    if has_upper: charset += 26
    if has_lower: charset += 26
    if has_digit: charset += 10
    if has_special: charset += 32
    
    if charset > 0:
        entropy = length * math.log2(charset)
        if entropy > 60: score += 20
        elif entropy > 40: score += 10

    # Common password check
    if password.lower() in COMMON_PASSWORDS:
        score = max(0, score - 40)
        issues.append('This is a commonly used password')

    # Repeating chars
    if re.search(r'(.)\1{2,}', password):
        score = max(0, score - 10)
        issues.append('Avoid repeating characters')

    # Sequential
    if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde)', password.lower()):
        score = max(0, score - 10)
        issues.append('Avoid sequential characters')

    score = min(100, max(0, score))
    
    if score >= 80:
        label, color = 'Very Strong', '#00ff9f'
    elif score >= 60:
        label, color = 'Strong', '#4ade80'
    elif score >= 40:
        label, color = 'Moderate', '#facc15'
    elif score >= 20:
        label, color = 'Weak', '#f97316'
    else:
        label, color = 'Very Weak', '#ef4444'

    return {
        'score': score,
        'label': label,
        'color': color,
        'issues': issues,
        'suggestions': suggestions,
        'has_upper': has_upper,
        'has_lower': has_lower,
        'has_digit': has_digit,
        'has_special': has_special,
        'length': length
    }

def detect_phishing_url(url: str) -> dict:
    if not url:
        return {'risk': 'unknown', 'score': 0, 'reasons': []}
    
    risk_score = 0
    reasons = []
    
    url_lower = url.lower()
    
    # Check for suspicious brand patterns
    for pattern in PHISHING_INDICATORS:
        if re.search(pattern, url_lower):
            risk_score += 25
            reasons.append(f'Suspicious brand imitation pattern detected')
            break
    
    # Check TLD
    for tld in SUSPICIOUS_TLDS:
        if url_lower.endswith(tld) or tld + '/' in url_lower:
            risk_score += 20
            reasons.append(f'Suspicious domain extension ({tld})')
            break
    
    # Multiple subdomains
    try:
        domain_part = url_lower.split('/')[2] if '/' in url_lower else url_lower
        subdomain_count = domain_part.count('.')
        if subdomain_count > 3:
            risk_score += 15
            reasons.append('Excessive subdomains (common phishing tactic)')
    except:
        pass
    
    # IP address URL
    if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
        risk_score += 30
        reasons.append('URL uses raw IP address instead of domain name')
    
    # URL shorteners
    shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'buff.ly']
    for s in shorteners:
        if s in url_lower:
            risk_score += 15
            reasons.append('URL shortener detected (destination unknown)')
            break
    
    # Suspicious keywords
    suspicious_kw = ['login', 'signin', 'verify', 'secure', 'update', 'confirm', 'account', 'bank']
    kw_hits = sum(1 for kw in suspicious_kw if kw in url_lower)
    if kw_hits >= 2:
        risk_score += 20
        reasons.append('Multiple suspicious keywords in URL')
    
    # HTTP (not HTTPS)
    if url_lower.startswith('http://'):
        risk_score += 15
        reasons.append('Not using HTTPS (insecure connection)')
    
    # Long URL
    if len(url) > 100:
        risk_score += 10
        reasons.append('Unusually long URL')
    
    risk_score = min(100, risk_score)
    
    if risk_score >= 70:
        risk = 'high'
    elif risk_score >= 40:
        risk = 'medium'
    elif risk_score >= 10:
        risk = 'low'
    else:
        risk = 'safe'
    
    return {
        'risk': risk,
        'score': risk_score,
        'reasons': reasons,
        'url': url
    }

def calculate_vault_health(passwords, notes, files) -> dict:
    if not passwords:
        return {
            'score': 0,
            'label': 'Empty Vault',
            'color': '#666',
            'details': {},
            'recommendations': ['Start by adding passwords to your vault']
        }
    
    active_passwords = [p for p in passwords if not p.is_deleted]
    total = len(active_passwords)
    
    if total == 0:
        return {'score': 0, 'label': 'Empty Vault', 'color': '#666', 'details': {}, 'recommendations': []}
    
    score = 100
    recommendations = []
    
    # Weak passwords
    weak = sum(1 for p in active_passwords if p.strength_score < 40)
    weak_pct = (weak / total) * 100
    score -= weak_pct * 0.5
    if weak > 0:
        recommendations.append(f'Update {weak} weak password(s) to stronger alternatives')
    
    # Reused passwords (check by encrypted value)
    encrypted_vals = [p.password_encrypted for p in active_passwords]
    unique_vals = len(set(encrypted_vals))
    reused = total - unique_vals
    if reused > 0:
        score -= min(30, reused * 5)
        recommendations.append(f'Replace {reused} reused password(s) with unique ones')
    
    # Expired passwords
    expired = sum(1 for p in active_passwords if p.is_expired())
    if expired > 0:
        score -= min(20, expired * 5)
        recommendations.append(f'Renew {expired} expired password(s)')
    
    # 2FA adoption (bonus)
    bonus = min(10, len(notes) // 5 + len(files) // 3)
    score = min(100, score + bonus)
    
    score = max(0, score)
    
    if score >= 80:
        label, color = 'Excellent', '#00ff9f'
    elif score >= 60:
        label, color = 'Good', '#4ade80'
    elif score >= 40:
        label, color = 'Fair', '#facc15'
    elif score >= 20:
        label, color = 'Poor', '#f97316'
    else:
        label, color = 'Critical', '#ef4444'
    
    return {
        'score': round(score),
        'label': label,
        'color': color,
        'details': {
            'total': total,
            'weak': weak,
            'reused': reused,
            'expired': expired,
            'strong': total - weak,
            'notes': len([n for n in notes if not n.is_deleted]),
            'files': len([f for f in files if not f.is_deleted])
        },
        'recommendations': recommendations
    }

def get_ai_security_advice(query: str, context: dict = None) -> str:
    """Get AI security advice - supports Grok (xAI) or Anthropic, with fallback."""
    
    grok_key = current_app.config.get('GROK_API_KEY', '')
    anthropic_key = current_app.config.get('ANTHROPIC_API_KEY', '')

    system_prompt = """You are VaultX AI Security Advisor, an expert cybersecurity assistant.
Provide concise, actionable security advice. Be direct and practical.
Format responses clearly. Max 250 words."""

    context_str = ''
    if context:
        context_str = f"\n\nUser vault context: {context}"

    full_query = query + context_str

    # ── Try Grok (xAI) first ──────────────────────────────
    if grok_key:
        try:
            import requests as req
            resp = req.post(
                'https://api.x.ai/v1/chat/completions',
                headers={
                    'Authorization': f'Bearer {grok_key}',
                    'Content-Type': 'application/json'
                },
                json={
                    'model': 'grok-3-mini',
                    'messages': [
                        {'role': 'system', 'content': system_prompt},
                        {'role': 'user', 'content': full_query}
                    ],
                    'max_tokens': 400
                },
                timeout=15
            )
            if resp.status_code == 200:
                data = resp.json()
                return data['choices'][0]['message']['content']
        except Exception as e:
            current_app.logger.error(f'Grok API error: {e}')

    # ── Try Anthropic second ──────────────────────────────
    if anthropic_key:
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=anthropic_key)
            message = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=400,
                system=system_prompt,
                messages=[{"role": "user", "content": full_query}]
            )
            return message.content[0].text
        except Exception as e:
            current_app.logger.error(f'Anthropic API error: {e}')

    # ── Fallback responses ────────────────────────────────
    fallback = {
        'password': """**Password Security Tips:**
• Use 16+ character passwords with mixed characters
• Never reuse passwords across different sites
• Enable 2FA on all critical accounts
• Change passwords every 90 days for sensitive accounts
• Avoid dictionary words and personal info""",

        'phishing': """**Phishing Protection:**
• Always verify sender email addresses carefully
• Never click links in unexpected emails
• Check for HTTPS before entering credentials
• When in doubt, go directly to the website manually
• Enable email filtering and anti-phishing tools""",

        'default': """**General Security Recommendations:**
• Enable two-factor authentication everywhere
• Keep all software and OS updated regularly
• Use unique passwords for every account
• Be cautious on public WiFi networks
• Regularly audit and review your digital accounts
• Back up important data securely and encrypted"""
    }

    q = query.lower()
    if 'password' in q:
        return fallback['password']
    elif 'phish' in q or 'email' in q or 'link' in q:
        return fallback['phishing']
    else:
        return fallback['default']


def analyze_login_threat(ip: str, user_agent: str, attempts: int, username: str) -> dict:
    risk_score = 0
    threats = []
    
    # Multiple failed attempts
    if attempts >= 3:
        risk_score += min(50, attempts * 10)
        threats.append(f'{attempts} failed login attempts detected')
    
    # Bot-like user agents
    bot_patterns = ['bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python-requests']
    ua_lower = user_agent.lower() if user_agent else ''
    for bot in bot_patterns:
        if bot in ua_lower:
            risk_score += 30
            threats.append('Automated/bot user-agent detected')
            break
    
    # Check for known bad patterns
    if ip and (ip.startswith('10.') or ip.startswith('192.168.')):
        pass  # Local network, less suspicious
    
    if risk_score >= 70:
        level = 'high'
    elif risk_score >= 40:
        level = 'medium'
    elif risk_score >= 10:
        level = 'low'
    else:
        level = 'none'
    
    return {
        'level': level,
        'score': min(100, risk_score),
        'threats': threats
    }
