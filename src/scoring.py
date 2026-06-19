# -*- coding: utf-8 -*-
import numpy as np

from feature_extraction import FeatureExtractor
from heuristics import heuristic_risk
from url_utils import is_trusted, normalize_url

RISK_LABELS = ['phishing', 'malware', 'defacement']


def analyze_url(url, pipeline, le, trusted_domains=None):
    normalized = normalize_url(url)
    extractor = FeatureExtractor(normalized)
    features = np.array(extractor.extract_all()).reshape(1, -1)
    probs = pipeline.predict_proba(features)[0]
    label_probs = {le.classes_[i]: float(probs[i]) for i in range(len(le.classes_))}

    benign = label_probs.get('benign', 0.0)
    max_bad = max(label_probs.get(label, 0.0) for label in RISK_LABELS)
    ml_risk = max(max_bad * 100.0, (1.0 - benign) * 50.0)

    rule_risk, reasons = heuristic_risk(normalized, trusted_domains)

    if is_trusted(normalized, trusted_domains):
        final_risk = min(ml_risk, 5.0)
        verdict = 'safe'
        source = 'trusted'
    elif rule_risk >= 70:
        final_risk = max(rule_risk, ml_risk * 0.5)
        verdict = 'danger'
        source = 'heuristic'
    elif benign >= 0.82 and rule_risk < 20:
        final_risk = min(ml_risk, 10.0)
        verdict = 'safe'
        source = 'model'
    else:
        final_risk = max(ml_risk * 0.7, rule_risk * 0.75)
        if rule_risk >= 50:
            final_risk = max(final_risk, rule_risk * 0.92)
        source = 'hybrid'
        if final_risk >= 45:
            verdict = 'danger'
        elif final_risk >= 30:
            verdict = 'suspicious'
        else:
            verdict = 'safe'

    predicted_label = max(label_probs, key=label_probs.get)
    if final_risk >= 45:
        predicted_label = max(RISK_LABELS, key=lambda label: label_probs.get(label, 0.0))

    reg = extractor.ext
    registered = f'{reg.domain}.{reg.suffix}' if reg.domain and reg.suffix else normalized

    return {
        'url': url,
        'normalized': normalized,
        'registered_domain': registered,
        'risk': round(final_risk, 1),
        'verdict': verdict,
        'source': source,
        'predicted_label': predicted_label,
        'label_probs': label_probs,
        'ml_risk': round(ml_risk, 1),
        'rule_risk': round(rule_risk, 1),
        'reasons': reasons,
    }
