# ml_service.py
from flask import Flask, request, jsonify
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib

app = Flask(__name__)

# Load once
model = joblib.load("waf_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")
THRESHOLD = 0.6  # Confidence threshold

@app.route("/predict", methods=["GET"])
def predict():
    query = request.args.get("q", "").strip().lower()
    features = vectorizer.transform([query])
    prob = model.predict_proba(features)[0][1]
    is_malicious = prob >= THRESHOLD

    return jsonify({
        "is_malicious": is_malicious,
        "confidence": prob
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
