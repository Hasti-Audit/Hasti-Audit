import re
import pandas as pd

# ==========================================
# 1. Bilingual Lexicon (English + Persian)
# ==========================================
LEXICON = {
    "en": {
        "positive": {"good", "great", "happy", "love", "amazing", "excellent"},
        "negative": {"bad", "terrible", "sad", "hate", "awful", "poor"}
    },
    "fa": {
        "positive": {"خوب", "عالی", "شاد", "دوست", "شگفت‌انگیز", "ممتاز"},
        "negative": {"بد", "افتضاح", "غمگین", "نفرت", "ضعیف", "افتضاح"}
    }
}

# ==========================================
# 2. Language Detection (Regex based)
# ==========================================
def detect_language(text):
    if re.search(r'[\u0600-\u06FF]', text):
        return "fa"
    return "en"

# ==========================================
# 3. Bilingual Sentiment Analyzer
# ==========================================
def analyze_sentiment(text):
    lang = detect_language(text)
    words = text.lower().split()
    score = 0
    for word in words:
        if word in LEXICON[lang]["positive"]:
            score += 1
        elif word in LEXICON[lang]["negative"]:
            score -= 1
    predicted_label = 1 if score > 0 else (0 if score < 0 else 0.5)
    return lang, score, predicted_label

# ==========================================
# 4. Language Fairness Check (Core Feature)
# ==========================================
def evaluate_multilingual_fairness(data):
    results = []
    for item in data:
        lang, score, pred = analyze_sentiment(item["text"])
        results.append({
            "Text": item["text"],
            "Lang": lang,
            "Score": score,
            "Expected": item["expected"],
            "Predicted": pred,
            "Correct": (pred == item["expected"])
        })
    
    df = pd.DataFrame(results)
    lang_accuracy = df.groupby("Lang")["Correct"].mean() * 100
    overall_accuracy = df["Correct"].mean() * 100
    
    print("=== MULTILINGUAL FAIRNESS REPORT ===")
    print(df.to_string(index=False))
    print("\n=== METRICS ===")
    print(f"Total Samples: {len(df)}")
    print(f"Overall Accuracy: {overall_accuracy:.2f}%")
    print("\n--- Accuracy by Language ---")
    for lang, acc in lang_accuracy.items():
        print(f"Language '{lang}': {acc:.2f}%")
    
    if len(lang_accuracy) > 1:
        gap = lang_accuracy.max() - lang_accuracy.min()
        print(f"\nLanguage Fairness Gap: {gap:.2f}%")
        if gap > 10:
            print("⚠️ WARNING: Significant fairness gap detected.")
        else:
            print("✅ Fairness gap is within acceptable limits (< 10%).")
    return df

if __name__ == "__main__":
    mock_data = [
        {"text": "I love this amazing product!", "expected": 1},
        {"text": "This movie was terrible and boring.", "expected": 0},
        {"text": "این محصول فوق‌العاده و عالی است", "expected": 1},
        {"text": "این فیلم بسیار بد و افتضاح بود", "expected": 0},
        {"text": "I am very happy today", "expected": 1},
        {"text": "امروز بسیار شاد هستم", "expected": 1}
    ]
    evaluate_multilingual_fairness(mock_data)
