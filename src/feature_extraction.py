# -*- coding: utf-8 -*-
import re
import math
from collections import Counter
from urllib.parse import urlparse

import tldextract

from heuristics import BRAND_TOKENS, SENSITIVE_KEYWORDS
from url_utils import RISKY_TLDS, normalize_url

SHORTENERS = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'is.gd', 'bit.do']


class FeatureExtractor:
    def __init__(self, url):
        url_str = normalize_url(url)
        if not url_str.startswith(('http://', 'https://')):
            url_str = 'http://' + url_str
        self.normalized = normalize_url(url)
        self.url_lower = url_str
        try:
            self.parsed = urlparse(url_str)
            self.ext = tldextract.extract(url_str)
        except Exception:
            self.parsed = urlparse('http://malformed-invalid-url.local')
            self.ext = tldextract.extract('http://malformed-invalid-url.local')

    def extract_all(self):
        url = self.url_lower
        parsed = self.parsed
        ext = self.ext
        domain = (ext.domain or '').lower()
        features = []
        length = float(len(url))

        features.append(len(self.normalized))
        features.append(len(parsed.netloc))
        features.append(url.count('/'))
        features.append(url.count('.'))
        features.append(len(re.findall(r'\d', url)))
        features.append(len(re.findall(r'[a-z]', url)))
        features.append(len(re.findall(r'[!@#$%^&*()_+\-=\[\]{};\':",.<>/?]', url)))

        features.append(1 if '@' in url else 0)
        features.append(1 if '//' in url[7:] else 0)
        features.append(1 if re.match(r'^\d+\.\d+\.\d+\.\d+', parsed.netloc) else 0)

        features.append(sum(1 for w in SENSITIVE_KEYWORDS if w in self.normalized))
        features.append(1 if url.startswith('https://') else 0)

        features.append(self.normalized.count('-'))
        features.append(url.count('?'))
        features.append(url.count('='))

        counts = Counter(url).values()
        entropy = -sum(c / length * math.log(c / length, 2) for c in counts) if length > 0 else 0
        features.append(entropy)
        features.append(len([x for x in parsed.path.split('/') if x]))
        features.append(len(re.findall(r'\d', url)) / length if length > 0 else 0)
        features.append(len(re.findall(r'\d', parsed.netloc)) / float(len(parsed.netloc) or 1))

        features.append(1 if any(s in url for s in SHORTENERS) else 0)

        domain_parts = [p for p in [ext.subdomain, ext.domain, ext.suffix] if p]
        features.append(len(domain_parts))
        features.append(len(ext.subdomain or ''))
        features.append(len([p for p in (ext.subdomain or '').split('.') if p]))

        tld_risk_map = {
            'win': 5.0, 'top': 5.0, 'xyz': 4.0, 'cc': 4.0, 'tk': 4.0,
            'club': 3.0, 'icu': 3.0, 'site': 3.0, 'online': 3.0, 'live': 3.0,
        }
        features.append(tld_risk_map.get(ext.suffix, 0.0))
        features.append(len(re.findall(r'[!@#$%^&*()_+\-=\[\]{};\':",.<>/?]', url)) / length if length > 0 else 0)

        digit_count = len(re.findall(r'\d', domain))
        features.append(digit_count / float(len(domain) or 1))
        features.append(len(re.findall(r'\d+', domain)))
        features.append(1 if '-' in domain else 0)
        features.append(1 if ext.suffix in RISKY_TLDS else 0)
        features.append(sum(1 for b in BRAND_TOKENS if b in domain and domain not in (b, f'{b}s')))
        features.append(
            1 if any(b in domain for b in BRAND_TOKENS) and ext.suffix in RISKY_TLDS else 0
        )
        features.append(len(domain))

        return features
