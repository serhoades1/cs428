#!/usr/bin/env python3
"""
Dynamic Password Strength Indicator Application
Framework: Python 3 with Tkinter (GUI)
Author: Computer Science & Cybersecurity Student

Features:
- Real-time password analysis on every keypress
- Realistic threat-model scoring based on entropy, patterns, dictionary matching, and leetspeak decoding
- Visual dynamic strength meter with multi-stage color feedback
- Time-to-crack estimations across offline fast GPU attacks
- Targeted improvement feedback
"""

import math
import re
import string
import tkinter as tk
from tkinter import ttk

# =============================================================================
# SCORING & THREAT-MODEL ENGINE
# =============================================================================

class PasswordEvaluator:
    # Common weak passphrases and top dictionary bases
    COMMON_PATTERNS = [
        "password", "123456", "12345678", "123456789", "qwerty", "abcdef",
        "admin", "welcome", "iloveyou", "monkey", "dragon", "sunshine",
        "princess", "football", "shadow", "master", "michael", "superman"
    ]

    KEYBOARD_SEQUENCES = [
        "qwertyuiop", "asdfghjkl", "zxcvbnm",
        "1234567890", "0987654321", "abcdefghijklmnopqrstuvwxyz"
    ]

    LEET_MAP = {
        '@': 'a', '4': 'a', '8': 'b', '(': 'c', '3': 'e',
        '3': 'e', '1': 'i', '!': 'i', '|': 'i', '0': 'o',
        '$': 's', '5': 's', '7': 't', '+': 't'
    }

    @classmethod
    def decode_leetspeak(cls, text: str) -> str:
        """Translates common leetspeak substitutions back to standard English letters."""
        decoded = list(text.lower())
        for i, char in enumerate(decoded):
            if char in cls.LEET_MAP:
                decoded[i] = cls.LEET_MAP[char]
        return "".join(decoded)

    @classmethod
    def evaluate(cls, password: str) -> dict:
        if not password:
            return {
                "score": 0,
                "category": "Very Weak",
                "color": "#e74c3c",
                "entropy_bits": 0.0,
                "time_to_crack": "Instant",
                "suggestions": ["Enter a password to begin evaluation."],
                "checks": {
                    "length_8": False,
                    "length_12": False,
                    "uppercase": False,
                    "lowercase": False,
                    "numbers": False,
                    "symbols": False,
                    "no_repeats": True,
                    "no_dictionary": True
                }
            }

        length = len(password)
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_symbol = bool(re.search(r'[^a-zA-Z0-9]', password))

        # 1. Base Character Pool Size (R)
        pool_size = 0
        if has_lower:
            pool_size += 26
        if has_upper:
            pool_size += 26
        if has_digit:
            pool_size += 10
        if has_symbol:
            pool_size += 32  # Standard printable ASCII punctuation

        # 2. Raw Information Entropy (Bits) = L * log2(R)
        raw_entropy = length * math.log2(pool_size) if pool_size > 0 else 0

        # 3. Apply Penalties based on Real-World Security Flaws
        penalties = 0.0
        suggestions = []

        # Penalty A: Repeated characters / Runs (e.g., "aaaaa" or "11111")
        consecutive_repeats = len(re.findall(r'(.)\1+', password))
        if consecutive_repeats > 0:
            penalties += consecutive_repeats * 8.0
            suggestions.append("Avoid repeated consecutive characters (e.g., 'aaa').")

        # Penalty B: Sequential keyboard walks (e.g., "qwerty", "12345", "abcd")
        lower_pass = password.lower()
        for seq in cls.KEYBOARD_SEQUENCES:
            for i in range(len(seq) - 2):
                sub = seq[i:i+3]
                if sub in lower_pass:
                    penalties += 12.0
                    suggestions.append(f"Avoid sequential patterns like '{sub}'.")
                    break

        # Penalty C: Dictionary words & Leetspeak obfuscation
        decoded_pass = cls.decode_leetspeak(password)
        found_dict_word = False
        for word in cls.COMMON_PATTERNS:
            if word in lower_pass or word in decoded_pass:
                found_dict_word = True
                penalties += 25.0
                suggestions.append(f"Contains common word/pattern or leetspeak variant ('{word}').")
                break

        # Penalty D: Short password penalty (exponential risk)
        if length < 8:
            penalties += 30.0
            suggestions.append("Password is critically short. Aim for at least 12-16 characters.")
        elif length < 12:
            suggestions.append("Increase length to 12+ characters for exponential security gains.")

        # Compute Effective Entropy
        effective_entropy = max(0.0, raw_entropy - penalties)

        # 4. Convert Effective Entropy to 0-100 Score
        # 0 bits = 0 score, 80+ bits = 100 score (80 bits is robust against modern offline brute force)
        score = min(100, int((effective_entropy / 80.0) * 100))

        # Categorization Mapping
        if score < 25:
            category = "Very Weak"
            color = "#e74c3c"  # Red
        elif score < 50:
            category = "Weak"
            color = "#e67e22"  # Orange
        elif score < 70:
            category = "Fair"
            color = "#f1c40f"  # Yellow
        elif score < 88:
            category = "Strong"
            color = "#2ecc71"  # Light Green
        else:
            category = "Very Strong"
            color = "#27ae60"  # Dark Green

        # 5. Time-to-Crack Calculation
        # Assuming an offline adversary with a high-end GPU array testing 100 Billion (10^11) guesses/sec
        guesses = 2 ** effective_entropy
        guesses_per_sec = 1e11
        seconds = guesses / guesses_per_sec
        time_str = cls.format_time(seconds)

        # Basic Check Criteria
        checks = {
            "length_8": length >= 8,
            "length_12": length >= 12,
            "uppercase": has_upper,
            "lowercase": has_lower,
            "numbers": has_digit,
            "symbols": has_symbol,
            "no_repeats": consecutive_repeats == 0,
            "no_dictionary": not found_dict_word
        }

        if not suggestions:
            suggestions.append("Excellent password structure! Highly resilient to automated attacks.")

        return {
            "score": score,
            "category": category,
            "color": color,
            "entropy_bits": round(effective_entropy, 1),
            "time_to_crack": time_str,
            "suggestions": suggestions,
            "checks": checks
        }

    @staticmethod
    def format_time(seconds: float) -> str:
        if seconds < 1:
            return "Instantaneous (< 1 second)"
        elif seconds < 60:
            return f"{int(seconds)} seconds"
        elif seconds < 3600:
            return f"{int(seconds // 60)} minutes"
        elif seconds < 86400:
            return f"{int(seconds // 3600)} hours"
        elif seconds < 31536000:
            return f"{int(seconds // 86400)} days"
        elif seconds < 31536000 * 100:
            return f"{int(seconds // 31536000)} years"
        elif seconds < 31536000 * 1e6:
            return f"{int(seconds // (31536000 * 1000))} thousand years"
        else:
            return "Billions of years"


# =============================================================================
# REAL-TIME TKINTER GUI INTERFACE
# =============================================================================

class DynamicPasswordApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Dynamic Password Security Analyzer")
        self.root.geometry("620x700")
        self.root.resizable(False, False)
        self.root.configure(bg="#f5f6fa")

        self.show_password = tk.BooleanVar(value=False)

        self._build_ui()

    def _build_ui(self):
        # Header Title
        header_frame = tk.Frame(self.root, bg="#2c3e50", py=15)
        header_frame.pack(fill="x")

        title_lbl = tk.Label(
            header_frame, text="Password Security & Strength Analyzer",
            font=("Helvetica", 16, "bold"), fg="#ecf0f1", bg="#2c3e50"
        )
        title_lbl.pack()

        subtitle_lbl = tk.Label(
            header_frame, text="Real-Time Threat Model Evaluation & Entropy Analysis",
            font=("Helvetica", 10), fg="#bdc3c7", bg="#2c3e50"
        )
        subtitle_lbl.pack()

        # Main Container
        main = tk.Frame(self.root, bg="#f5f6fa", px=20, py=15)
        main.pack(fill="both", expand=True)

        # Password Input Area
        input_lbl = tk.Label(main, text="Enter Password:", font=("Helvetica", 11, "bold"), bg="#f5f6fa")
        input_lbl.pack(anchor="w", pady=(0, 5))

        input_frame = tk.Frame(main, bg="#f5f6fa")
        input_frame.pack(fill="x", pady=(0, 10))

        self.entry = tk.Entry(
            input_frame, font=("Consolas", 14), show="*",
            relief="solid", bd=1
        )
        self.entry.pack(side="left", fill="x", expand=True, ipady=6, px=(0, 10))
        self.entry.bind("<KeyRelease>", self.on_password_change)

        toggle_btn = tk.Checkbutton(
            input_frame, text="Show", variable=self.show_password,
            command=self.toggle_mask, font=("Helvetica", 10), bg="#f5f6fa"
        )
        toggle_btn.pack(side="right")

        # Dynamic Strength Meter Canvas
        meter_label_frame = tk.Frame(main, bg="#f5f6fa")
        meter_label_frame.pack(fill="x", pady=(5, 2))

        tk.Label(meter_label_frame, text="Strength Score:", font=("Helvetica", 10, "bold"), bg="#f5f6fa").pack(side="left")
        self.score_text = tk.Label(meter_label_frame, text="0 / 100", font=("Helvetica", 10, "bold"), bg="#f5f6fa")
        self.score_text.pack(side="right")

        self.meter_canvas = tk.Canvas(main, height=20, bg="#dcdde1", highlightthickness=0)
        self.meter_canvas.pack(fill="x", pady=(0, 10))
        self.meter_bar = self.meter_canvas.create_rectangle(0, 0, 0, 20, fill="#e74c3c", width=0)

        # Classification Banner
        self.status_banner = tk.Label(
            main, text="Category: Very Weak", font=("Helvetica", 12, "bold"),
            fg="#ffffff", bg="#e74c3c", py=6
        )
        self.status_banner.pack(fill="x", pady=(0, 15))

        # Metrics Grid (Entropy & Crack Time)
        metrics_frame = tk.Frame(main, bg="#ffffff", bd=1, relief="solid", py=10, px=10)
        metrics_frame.pack(fill="x", pady=(0, 15))

        tk.Label(metrics_frame, text="Effective Entropy:", font=("Helvetica", 10, "bold"), bg="#ffffff").grid(row=0, column=0, sticky="w", py=2)
        self.entropy_val = tk.Label(metrics_frame, text="0.0 bits", font=("Helvetica", 10), bg="#ffffff")
        self.entropy_val.grid(row=0, column=1, sticky="w", px=(10, 0))

        tk.Label(metrics_frame, text="Est. Offline Crack Time:", font=("Helvetica", 10, "bold"), bg="#ffffff").grid(row=1, column=0, sticky="w", py=2)
        self.crack_val = tk.Label(metrics_frame, text="Instantaneous", font=("Helvetica", 10, "bold"), fg="#c0392b", bg="#ffffff")
        self.crack_val.grid(row=1, column=1, sticky="w", px=(10, 0))

        # Rule Check Indicators
        checks_frame = tk.LabelFrame(main, text=" Security Criteria ", font=("Helvetica", 10, "bold"), bg="#f5f6fa", px=10, py=10)
        checks_frame.pack(fill="x", pady=(0, 15))

        self.check_labels = {}
        criteria = [
            ("length_12", "At least 12 characters"),
            ("uppercase", "Contains Uppercase (A-Z)"),
            ("lowercase", "Contains Lowercase (a-z)"),
            ("numbers", "Contains Numbers (0-9)"),
            ("symbols", "Contains Symbols (!@#$)"),
            ("no_dictionary", "No Common Dictionary Words / Leetspeak")
        ]

        for i, (key, label_text) in enumerate(criteria):
            row = i // 2
            col = i % 2
            lbl = tk.Label(checks_frame, text=f"✖ {label_text}", font=("Helvetica", 9), fg="#7f8c8d", bg="#f5f6fa")
            lbl.grid(row=row, column=col, sticky="w", px=10, py=2)
            self.check_labels[key] = lbl

        # Actionable Suggestions Area
        sug_frame = tk.LabelFrame(main, text=" Improvement Suggestions ", font=("Helvetica", 10, "bold"), bg="#f5f6fa", px=10, py=10)
        sug_frame.pack(fill="both", expand=True)

        self.sug_listbox = tk.Listbox(
            sug_frame, font=("Helvetica", 9), bd=0, bg="#f5f6fa",
            highlightthickness=0, selectbackground="#f5f6fa"
        )
        self.sug_listbox.pack(fill="both", expand=True)

        # Trigger initial evaluation
        self.on_password_change(None)

    def toggle_mask(self):
        if self.show_password.get():
            self.entry.config(show="")
        else:
            self.entry.config(show="*")

    def on_password_change(self, event):
        password = self.entry.get()
        eval_data = PasswordEvaluator.evaluate(password)

        # Update Score and Meter Bar
        score = eval_data["score"]
        self.score_text.config(text=f"{score} / 100")
        
        canvas_width = self.meter_canvas.winfo_width()
        if canvas_width <= 1:
            canvas_width = 570  # Fallback initial width
        
        target_width = int((score / 100.0) * canvas_width)
        self.meter_canvas.coords(self.meter_bar, 0, 0, target_width, 20)
        self.meter_canvas.itemconfig(self.meter_bar, fill=eval_data["color"])

        # Update Banner
        self.status_banner.config(
            text=f"Strength Category: {eval_data['category'].upper()}",
            bg=eval_data["color"]
        )

        # Update Metrics
        self.entropy_val.config(text=f"{eval_data['entropy_bits']} bits")
        self.crack_val.config(text=eval_data["time_to_crack"])

        # Update Check Indicators
        for key, lbl in self.check_labels.items():
            if eval_data["checks"].get(key, False):
                lbl.config(text=f"✔ {lbl.cget('text')[2:]}", fg="#27ae60")
            else:
                lbl.config(text=f"✖ {lbl.cget('text')[2:]}", fg="#c0392b")

        # Update Suggestions
        self.sug_listbox.delete(0, tk.END)
        for sug in eval_data["suggestions"]:
            self.sug_listbox.insert(tk.END, f"• {sug}")


if __name__ == "__main__":
    root = tk.Tk()
    app = DynamicPasswordApp(root)
    root.mainloop()