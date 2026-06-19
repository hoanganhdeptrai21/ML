# -*- coding: utf-8 -*-
import os
import re

import tldextract

RISKY_TLDS = {
    'win', 'top', 'xyz', 'tk', 'cc', 'icu', 'club', 'buzz', 'loan', 'work',
    'click', 'site', 'online', 'live', 'store', 'rest', 'cam', 'stream',
    'gq', 'ml', 'ga', 'cf', 'pw', 'fit', 'monster', 'sbs', 'cfd',
}

CORE_TRUSTED = {
    'youtube.com', 'google.com', 'instagram.com', 'facebook.com', 'twitter.com',
    'x.com', 'microsoft.com', 'apple.com', 'amazon.com', 'github.com',
    'wikipedia.org', 'linkedin.com', 'netflix.com', 'reddit.com', 'tiktok.com',
    'whatsapp.com', 'telegram.org', 'spotify.com', 'yahoo.com', 'bing.com',
    'cloudflare.com', 'stackoverflow.com', 'zoom.us', 'paypal.com',
    'shopee.vn', 'lazada.vn', 'zalo.me', 'momo.vn', 'vietcombank.com.vn',
}


def normalize_url(url):
    url = str(url).strip().lower()
    url = url.replace('[', '').replace(']', '')
    url = re.sub(r'^(https?://)?(www\.)?', '', url)
    return url.rstrip('/').split('/')[0].split('?')[0].split('#')[0]


def registered_domain(url_or_ext):
    if isinstance(url_or_ext, str):
        ext = tldextract.extract('http://' + normalize_url(url_or_ext))
    else:
        ext = url_or_ext
    if not ext.domain or not ext.suffix:
        return ''
    return f'{ext.domain}.{ext.suffix}'


def load_trusted_domains(legit_path=None, top_n=8000):
    trusted = set(CORE_TRUSTED)
    if legit_path and os.path.exists(legit_path):
        with open(legit_path, encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f):
                if i >= top_n:
                    break
                domain = registered_domain(line.strip())
                if domain and domain.count('.') >= 1:
                    trusted.add(domain)
    return trusted
def is_trusted(url, trusted_domains=None):
    domain = registered_domain(url)
    if not domain:
        return False
    if trusted_domains is None:
        return domain in CORE_TRUSTED
    return domain in trusted_domains

def is_noisy_benign(url):
    ext = tldextract.extract('http://' + normalize_url(url))
    if ext.suffix in RISKY_TLDS:
        return True
    domain = ext.domain or ''
    if ext.suffix in RISKY_TLDS or (ext.suffix and len(domain) <= 2):
        return True
    if re.search(r'\d{3,}', domain):
        return True
    return False
