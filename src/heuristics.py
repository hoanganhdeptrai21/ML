# -*- coding: utf-8 -*-
import re

import tldextract

from url_utils import RISKY_TLDS, is_trusted, normalize_url, registered_domain

BRAND_TOKENS = [
    'facebook', 'fb', 'instagram', 'insta', 'youtube', 'google', 'goog',
    'paypal', 'apple', 'microsoft', 'amazon', 'netflix', 'whatsapp',
    'telegram', 'tiktok', 'shopee', 'lazada', 'zalo', 'momo',
    'vietcombank', 'techcombank', 'bidv', 'agribank', 'mbbank',
    'napthe', 'dangnhap', 'icloud', 'outlook', 'office365',
]

SENSITIVE_KEYWORDS = [
    'login', 'verify', 'account', 'secure', 'bank', 'update',
    'signin', 'wallet', 'gift', 'free', 'bonus', 'promo',
]


def _brand_hits(domain):
    hits = []
    for brand in BRAND_TOKENS:
        if brand in domain and domain not in (brand, f'{brand}s'):
            hits.append(brand)
    return hits
def heuristic_risk(url, trusted_domains=None):
    normalized = normalize_url(url)
    ext = tldextract.extract('http://' + normalized)
    domain = (ext.domain or '').lower()
    full_host = registered_domain(ext)
    score = 0.0
    reasons = []
    if is_trusted(normalized, trusted_domains):
        return 2.0, ['trusted_domain']
    if re.match(r'^\d+\.\d+\.\d+\.\d+', normalized):
        score += 55
        reasons.append('ip_host')
    if '@' in normalized:
        score += 70
        reasons.append('at_symbol')

    if ext.suffix in RISKY_TLDS:
        score += 35
        reasons.append(f'risky_tld.{ext.suffix}')

    digit_ratio = len(re.findall(r'\d', domain)) / max(len(domain), 1)
    if digit_ratio >= 0.25:
        score += 25
        reasons.append('many_digits_in_domain')
    if re.search(r'\d{3,}', domain):
        score += 20
        reasons.append('long_digit_run')
    if '-' in domain:
        score += 8
        reasons.append('hyphen_in_domain')
    subdomain_depth = len([p for p in (ext.subdomain or '').split('.') if p])
    if subdomain_depth >= 2:
        score += 12 + subdomain_depth * 4
        reasons.append('deep_subdomain')
    brand_hits = _brand_hits(domain)
    if brand_hits:
        score += 45
        reasons.append(f'brand_token.{brand_hits[0]}')
        if ext.suffix in RISKY_TLDS:
            score += 35
            reasons.append('brand_on_risky_tld')
        if digit_ratio > 0:
            score += 25
            reasons.append('brand_with_digits')
    keyword_hits = sum(1 for kw in SENSITIVE_KEYWORDS if kw in normalized)
    if keyword_hits:
        score += keyword_hits * 8
        reasons.append('sensitive_keywords')
    if full_host and full_host.count('.') >= 2 and ext.suffix in RISKY_TLDS:
        score += 10
        reasons.append('multi_part_risky_host')
    return min(score, 100.0), reasons
