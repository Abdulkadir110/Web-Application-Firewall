# train_model.py
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

def get_training_data():
    benign = [
        "hello", "search=test", "user=admin", "dashboard", "submit form",
        "email=example@example.com", "comment=nice post", "page=1", "sort=asc", "login=user",
        "q=flask security", "feedback=great site", "category=books", "price=20", "item=123",
        "csrf_token=abc123", "remember_me=true", "name=John", "message=thanks"
    ]

    malicious = [
        "1' OR 1=1--", "admin'--", "' OR 'x'='x", "UNION SELECT password FROM users",
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "SELECT * FROM users",
        "DROP TABLE users", "<svg onload=alert(1)>", "<body onload=alert(1)>",
        "'; DROP DATABASE test; --", "admin' or '1'='1", "' OR sleep(5)--", "'; EXEC xp_cmdshell('dir');--",
        "1' OR 'a'='a", "<iframe src='javascript:alert(1)'>", "or 1=1#", "' OR '1'='1' /*",
        "%3Cscript%3Ealert('XSS')%3C/script%3E", "1'; WAITFOR DELAY '0:0:5'--"
    ]

    payloads = benign + malicious
    labels = [0] * len(benign) + [1] * len(malicious)
    return pd.DataFrame({"payload": payloads, "label": labels})

def train_model():
    data = get_training_data()

    vectorizer = TfidfVectorizer(ngram_range=(1, 3), analyzer='char_wb', lowercase=True)
    X = vectorizer.fit_transform(data["payload"])
    y = data["label"]

    # Split and train
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # Evaluation
    y_pred = model.predict(X_test)
    print("\n[ML] Classification Report:\n")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Malicious"]))

    # Save
    joblib.dump(model, "waf_model.pkl")
    joblib.dump(vectorizer, "vectorizer.pkl")
    print("\n[ML] Model and vectorizer saved.")

if __name__ == "__main__":
    train_model()
