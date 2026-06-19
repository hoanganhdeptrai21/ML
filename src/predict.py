import os
import sys
from scoring import analyze_url
VERDICT_TEXT = {
    'safe': ('AN TOAN', '\033[92m'),
    'suspicious': ('NGHI VAN', '\033[93m'),
    'danger': ('NGUY HIEM', '\033[91m'),
}

def load_pipeline():
    pipeline_path = os.path.join('model', 'pipeline.pkl')
    if not os.path.exists(pipeline_path):
        raise FileNotFoundError('Khong tim thay file model! Hay chay train.py truoc.')
    import joblib
    return joblib.load(pipeline_path)


def format_result(result):
    label, color = VERDICT_TEXT.get(result['verdict'], ('KHONG XAC DINH', '\033[0m'))
    reset = '\033[0m'
    lines = [
        '',
        '=' * 56,
        f'URL nhap       : {result["url"]}',
        f'Domain phan tich: {result["registered_domain"]}',
        f'Do nguy hiem   : {result["risk"]:.1f}%',
        f'Ket luan       : {color}{label}{reset}',
        f'Nguon danh gia : {result["source"]}',
        f'ML risk        : {result["ml_risk"]:.1f}% | Rule risk: {result["rule_risk"]:.1f}%',
    ]

    if result['reasons']:
        lines.append(f'Ly do rule     : {", ".join(result["reasons"][:4])}')

    probs = result['label_probs']
    prob_line = ' | '.join(f'{name}: {prob * 100:.1f}%' for name, prob in sorted(probs.items()))
    lines.append(f'Xac suat model : {prob_line}')
    lines.append('=' * 56)
    return '\n'.join(lines)


def run_prediction(url):
    data = load_pipeline()
    pipeline = data['model']
    le = data['le']
    trusted_domains = data.get('trusted_domains')
    result = analyze_url(url, pipeline, le, trusted_domains)
    print(format_result(result))
    return result


if __name__ == '__main__':
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except Exception:
            pass

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(root)

    print('HE THONG PHAT HIEN WEB DOC HAI (optimized)')
    while True:
        try:
            user_input = input('\nNhap URL (hoac "exit"): ').strip()
            if user_input.lower() == 'exit':
                break
            if user_input:
                run_prediction(user_input)
        except KeyboardInterrupt:
            break
        except Exception as exc:
            print(f'Loi: {exc}')
