
import os
import joblib
import numpy as np
import pandas as pd
from collections import Counter
from joblib import Parallel, delayed
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, StandardScaler
from tqdm import tqdm
from xgboost import XGBClassifier
from feature_extraction import FeatureExtractor
from url_utils import is_noisy_benign, load_trusted_domains, normalize_url
def load_dataset(data_path, legit_path):
    df = pd.read_csv(data_path, encoding='utf-8-sig', encoding_errors='ignore').dropna(subset=['url'])
    if os.path.exists(legit_path):
        df_legit = pd.read_csv(legit_path, header=None, names=['url']).assign(type='benign')
        df = pd.concat([df, df_legit], ignore_index=True)
    df['url'] = df['url'].astype(str).str.strip()
    df['type'] = df['type'].astype(str).str.strip().str.lower()
    df = df[df['type'].isin(['benign', 'phishing', 'malware', 'defacement'])]
    noisy_mask = (df['type'] == 'benign') & df['url'].apply(is_noisy_benign)
    removed = noisy_mask.sum()
    if removed:
        print(f'🧹 Loại {removed} mẫu benign nhiễu (TLD rủi ro / domain đáng ngờ)')
    df = df[~noisy_mask].drop_duplicates(subset=['url'])
    df['url'] = df['url'].apply(normalize_url)
    df = df[df['url'].astype(bool)].drop_duplicates(subset=['url'])
    return df
def extract_features(urls):
    return np.array(
        Parallel(n_jobs=-1)(
            delayed(lambda u: FeatureExtractor(u).extract_all())(u)
            for u in tqdm(urls, desc='Trich xuat dac trung')
        )
    )
def train():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(root)

    data_path = os.path.join('data', 'urldata.csv')
    legit_path = os.path.join('data', 'legitimateurls.csv')
    model_path = os.path.join('model', 'pipeline.pkl')
    os.makedirs('model', exist_ok=True)

    df = load_dataset(data_path, legit_path)
    trusted_domains = load_trusted_domains(legit_path, top_n=8000)
    print(f'✅ Dang xu ly {len(df)} mau | trusted domains: {len(trusted_domains)}')

    X = extract_features(df['url'].tolist())
    le = LabelEncoder()
    y = le.fit_transform(df['type'])

    class_counts = Counter(y)
    total = len(y)
    weight_map = {i: total / (len(class_counts) * count) for i, count in class_counts.items()}
    sample_weights = np.array([weight_map[label] for label in y])

    X_train, X_test, y_train, y_test, weights_train, _ = train_test_split(
        X, y, sample_weights, test_size=0.2, stratify=y, random_state=42
    )
    pipeline = Pipeline([
        ('scaler', StandardScaler()),
        ('classifier', XGBClassifier(
            n_estimators=500,
            learning_rate=0.05,
            max_depth=7,
            min_child_weight=3,
            subsample=0.85,
            colsample_bytree=0.85,
            reg_lambda=1.2,
            reg_alpha=0.2,
            gamma=0.1,
            random_state=42,
            n_jobs=-1,
            eval_metric='mlogloss',
        )),
    ])
    print('🚀 Dang huan luyen model...')
    pipeline.fit(X_train, y_train, classifier__sample_weight=weights_train)
    y_pred = pipeline.predict(X_test)
    print(classification_report(y_test, y_pred, target_names=le.classes_))
    bundle = {
        'model': pipeline,
        'le': le,
        'trusted_domains': trusted_domains,
        'feature_count': X.shape[1],
    }
    joblib.dump(bundle, model_path)
    print(f'💾 Da luu model: {model_path}')
if __name__ == '__main__':
    train()
