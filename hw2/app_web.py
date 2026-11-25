import math
import re
import streamlit as st

class PasswordEvaluator:
    COMMON_PATTERNS = [
        "password", "123456", "12345678", "123456789", "qwerty", "abcdef",
        "admin", "welcome", "iloveyou", "monkey", "dragon", "sunshine",
        "princess", "football", "shadow", "master", "michael", "superman"
    ]
    KEYBOARD_SEQUENCES = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]
    LEET_MAP = {'@': 'a', '4': 'a', '8': 'b', '3': 'e', '1': 'i', '!': 'i', '0': 'o', '$': 's', '5': 's', '7': 't'}

    @classmethod
    def decode_leetspeak(cls, text: str) -> str:
        decoded = list(text.lower())
        for i, char in enumerate(decoded):
            if char in cls.LEET_MAP:
                decoded[i] = cls.LEET_MAP[char]
        return "".join(decoded)

    @classmethod
    def evaluate(cls, password: str) -> dict:
        if not password:
            return {
                "score": 0, "category": "Very Weak", "entropy_bits": 0.0,
                "time_to_crack": "Instantaneous", "suggestions": ["Enter a password to evaluate."]
            }

        length = len(password)
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_symbol = bool(re.search(r'[^a-zA-Z0-9]', password))

        pool_size = (26 if has_lower else 0) + (26 if has_upper else 0) + (10 if has_digit else 0) + (32 if has_symbol else 0)
        raw_entropy = length * math.log2(pool_size) if pool_size > 0 else 0

        penalties = 0.0
        suggestions = []

        if len(re.findall(r'(.)\1+', password)) > 0:
            penalties += 8.0
            suggestions.append("Avoid repeated character patterns (e.g., 'aaa').")

        lower_pass = password.lower()
        for seq in cls.KEYBOARD_SEQUENCES:
            for i in range(len(seq) - 2):
                if seq[i:i+3] in lower_pass:
                    penalties += 12.0
                    suggestions.append(f"Avoid sequential keyboard walks (e.g., '{seq[i:i+3]}').")
                    break

        decoded_pass = cls.decode_leetspeak(password)
        for word in cls.COMMON_PATTERNS:
            if word in lower_pass or word in decoded_pass:
                penalties += 25.0
                suggestions.append(f"Contains dictionary word or leetspeak variant ('{word}').")
                break

        if length < 8:
            penalties += 35.0
            suggestions.append("Password is critically short. Aim for at least 12-16 characters.")

        effective_entropy = max(0.0, raw_entropy - penalties)
        score = min(100, int((effective_entropy / 80.0) * 100))

        if score < 25: category = "Very Weak"
        elif score < 50: category = "Weak"
        elif score < 70: category = "Fair"
        elif score < 88: category = "Strong"
        else: category = "Very Strong"

        guesses = 2 ** effective_entropy
        seconds = guesses / 1e11
        
        if seconds < 1: time_str = "Instantaneous (< 1 second)"
        elif seconds < 3600: time_str = f"{int(seconds // 60)} minutes"
        elif seconds < 86400: time_str = f"{int(seconds // 3600)} hours"
        elif seconds < 31536000 * 100: time_str = f"{int(seconds // 31536000)} years"
        else: time_str = "Billions of years"

        return {
            "score": score, "category": category,
            "entropy_bits": round(effective_entropy, 1),
            "time_to_crack": time_str,
            "suggestions": suggestions or ["Strong password structure! Excellent resilience."]
        }

# Streamlit Page Setup
st.set_page_config(page_title="Password Security Analyzer", layout="centered")
st.title("Password Security Analyzer")

password = st.text_input("Enter Password:", type="password")
eval_data = PasswordEvaluator.evaluate(password)

# Visual Bar & Score
st.progress(eval_data["score"] / 100)
st.markdown(f"### Category: **{eval_data['category']}** ({eval_data['score']} / 100)")

# Metrics
col1, col2 = st.columns(2)
col1.metric("Effective Entropy", f"{eval_data['entropy_bits']} bits")
col2.metric("Est. Offline Crack Time", eval_data["time_to_crack"])

# Actionable Feedback
st.markdown("### Improvement Suggestions")
for sug in eval_data["suggestions"]:
    st.write(f"- {sug}")