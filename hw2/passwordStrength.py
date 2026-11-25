#!/usr/bin/env python3

# CS 428: Computer Security - Project 2
# Dynamic Password Strength Indicator Tool

import math
import re
import tkinter as tk
from tkinter import ttk

# Threat-Model Scoring Engine

class PasswordEvaluator:
    # Common password bases, wordlist entries, and frequent default patterns
    COMMON_PATTERNS = [
        "password", "123456", "12345678", "123456789", "qwerty", "abcdef",
        "admin", "welcome", "iloveyou", "monkey", "dragon", "sunshine",
        "princess", "football", "shadow", "master", "michael", "superman",
        "letmein", "trustno1", "baseball", "hacker", "login", "pass123",
        "keyboard", "administrator", "system", "changeit", "secret"
    ]

    KEYBOARD_SEQUENCES = [
        "qwertyuiop", "asdfghjkl", "zxcvbnm",
        "1234567890", "0987654321", "abcdefghijklmnopqrstuvwxyz"
    ]

    # Rule-based de-obfuscation mapping (simulates Hashcat/John the Ripper rules)
    LEET_MAP = {
        '@': 'a', '4': 'a', '8': 'b', '(': 'c', '3': 'e',
        '1': 'i', '!': 'i', '|': 'i', '0': 'o', '$': 's',
        '5': 's', '7': 't', '+': 't', '2': 'z'
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
                "time_to_crack": "Instantaneous",
                "suggestions": ["Type a password to begin real-time evaluation."],
                "checks": {
                    "length_12": False,
                    "uppercase": False,
                    "lowercase": False,
                    "numbers": False,
                    "symbols": False,
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
        if has_lower: pool_size += 26
        if has_upper: pool_size += 26
        if has_digit: pool_size += 10
        if has_symbol: pool_size += 32

        # 2. Raw Information Entropy (H_raw) = L * log2(R)
        raw_entropy = length * math.log2(pool_size) if pool_size > 0 else 0

        # 3. Apply Penalties based on Attacker Exploitation Vectors
        penalties = 0.0
        suggestions = []

        # Penalty A: Repeated consecutive characters (e.g., "aaaa" or "1111")
        consecutive_repeats = len(re.findall(r'(.)\1+', password))
        if consecutive_repeats > 0:
            penalties += consecutive_repeats * 8.0
            suggestions.append("Avoid repeated character patterns (e.g., 'aaa').")

        # Penalty B: Sequential keyboard walks (e.g., "qwerty", "12345", "abcd")
        lower_pass = password.lower()
        for seq in cls.KEYBOARD_SEQUENCES:
            for i in range(len(seq) - 2):
                sub = seq[i:i+3]
                if sub in lower_pass:
                    penalties += 12.0
                    suggestions.append(f"Avoid sequential keyboard walk '{sub}'.")
                    break

        # Penalty C: Dictionary word & Leetspeak obfuscation matching
        decoded_pass = cls.decode_leetspeak(password)
        found_dict_word = False
        for word in cls.COMMON_PATTERNS:
            if word in lower_pass or word in decoded_pass:
                found_dict_word = True
                penalties += 25.0
                suggestions.append(f"Contains common word/pattern or leetspeak variant ('{word}').")
                break

        # Penalty D: Recent Year Appends (e.g., "Password2024")
        if re.search(r'(19\d\d|20[0-2]\d)$', password):
            penalties += 10.0
            suggestions.append("Avoid ending with predictable years (e.g., '2024').")

        # Penalty E: Password Length Thresholds
        if length < 8:
            penalties += 35.0
            suggestions.append("Critically short: Aim for at least 12–16 characters.")
        elif length < 12:
            suggestions.append("Increase length to 12+ characters for exponential security.")

        # Calculate Effective Entropy (H_eff)
        effective_entropy = max(0.0, raw_entropy - penalties)

        # 4. Convert Effective Entropy to 0-100 Score
        # 80 bits of effective entropy represents a highly secure defense against offline GPU cracking
        score = min(100, int((effective_entropy / 80.0) * 100))

        # 5. Category Mapping
        if score < 25:
            category, color = "Very Weak", "#e74c3c"
        elif score < 50:
            category, color = "Weak", "#e67e22"
        elif score < 70:
            category, color = "Fair", "#f1c40f"
        elif score < 88:
            category, color = "Strong", "#2ecc71"
        else:
            category, color = "Very Strong", "#27ae60"

        # 6. Time-to-Crack Calculation
        # Assuming an offline adversary with a fast GPU array testing 100 Billion (10^11) guesses/sec
        guesses = 2 ** effective_entropy
        seconds = guesses / 1e11
        time_str = cls.format_crack_time(seconds)

        checks = {
            "length_12": length >= 12,
            "uppercase": has_upper,
            "lowercase": has_lower,
            "numbers": has_digit,
            "symbols": has_symbol,
            "no_dictionary": not found_dict_word
        }

        if not suggestions:
            suggestions.append("Excellent password structure! Highly resilient against offline attacks.")

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
    def format_crack_time(seconds: float) -> str:
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


# Tkinter Desktop Interface

class DynamicPasswordApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Dynamic Password Security Analyzer")
        self.root.geometry("620x720")
        self.root.resizable(False, False)
        self.root.configure(bg="#f5f6fa")

        # Reactive variables for continuous real-time tracking
        self.password_var = tk.StringVar()
        self.show_password = tk.BooleanVar(value=False)

        # Attach variable trace for instantaneous update on every keypress/paste/deletion
        self.password_var.trace_add("write", self.on_password_change)

        self._build_ui()
        self.on_password_change()

    def _build_ui(self):
        # Header Banner
        header = tk.Frame(self.root, bg="#2c3e50", pady=15)
        header.pack(fill="x")

        tk.Label(
            header, text="Password Security & Strength Analyzer",
            font=("Helvetica", 15, "bold"), fg="#ecf0f1", bg="#2c3e50"
        ).pack()

        tk.Label(
            header, text="CS 428 Computer Security | Threat-Model Entropy Analysis",
            font=("Helvetica", 9), fg="#bdc3c7", bg="#2c3e50"
        ).pack()

        # Main Layout
        main = tk.Frame(self.root, bg="#f5f6fa", padx=20, pady=15)
        main.pack(fill="both", expand=True)

        # Password Input Field
        tk.Label(main, text="Enter Password:", font=("Helvetica", 10, "bold"), bg="#f5f6fa").pack(anchor="w", pady=(0, 4))

        input_frame = tk.Frame(main, bg="#f5f6fa")
        input_frame.pack(fill="x", pady=(0, 10))

        self.entry = tk.Entry(
            input_frame, textvariable=self.password_var, font=("Consolas", 13),
            show="*", relief="solid", bd=1
        )
        self.entry.pack(side="left", fill="x", expand=True, ipady=5, padx=(0, 10))

        tk.Checkbutton(
            input_frame, text="Show", variable=self.show_password,
            command=self.toggle_mask, font=("Helvetica", 9), bg="#f5f6fa"
        ).pack(side="right")

        # Dynamic Visual Progress Meter
        meter_header = tk.Frame(main, bg="#f5f6fa")
        meter_header.pack(fill="x")
        tk.Label(meter_header, text="Strength Score:", font=("Helvetica", 10, "bold"), bg="#f5f6fa").pack(side="left")
        self.score_lbl = tk.Label(meter_header, text="0 / 100", font=("Helvetica", 10, "bold"), bg="#f5f6fa")
        self.score_lbl.pack(side="right")

        self.meter_canvas = tk.Canvas(main, height=18, bg="#dcdde1", highlightthickness=0)
        self.meter_canvas.pack(fill="x", pady=(4, 10))
        self.meter_bar = self.meter_canvas.create_rectangle(0, 0, 0, 18, fill="#e74c3c", width=0)

        # Classification Status Banner
        self.status_banner = tk.Label(
            main, text="Category: Very Weak", font=("Helvetica", 11, "bold"),
            fg="#ffffff", bg="#e74c3c", pady=5
        )
        self.status_banner.pack(fill="x", pady=(0, 12))

        # Security Metrics Panel
        metrics_frame = tk.Frame(main, bg="#ffffff", bd=1, relief="solid", padx=10, pady=8)
        metrics_frame.pack(fill="x", pady=(0, 12))

        tk.Label(metrics_frame, text="Effective Entropy:", font=("Helvetica", 9, "bold"), bg="#ffffff").grid(row=0, column=0, sticky="w")
        self.entropy_val = tk.Label(metrics_frame, text="0.0 bits", font=("Helvetica", 9), bg="#ffffff")
        self.entropy_val.grid(row=0, column=1, sticky="w", padx=(10, 0))

        tk.Label(metrics_frame, text="Est. Offline Crack Time:", font=("Helvetica", 9, "bold"), bg="#ffffff").grid(row=1, column=0, sticky="w", pady=(4, 0))
        self.crack_val = tk.Label(metrics_frame, text="Instantaneous", font=("Helvetica", 9, "bold"), fg="#c0392b", bg="#ffffff")
        self.crack_val.grid(row=1, column=1, sticky="w", padx=(10, 0), pady=(4, 0))

        # Criteria Checklist
        checks_frame = tk.LabelFrame(main, text=" Security Criteria ", font=("Helvetica", 9, "bold"), bg="#f5f6fa", padx=8, pady=6)
        checks_frame.pack(fill="x", pady=(0, 12))

        self.check_labels = {}
        criteria = [
            ("length_12", "At least 12 characters"),
            ("uppercase", "Contains Uppercase (A-Z)"),
            ("lowercase", "Contains Lowercase (a-z)"),
            ("numbers", "Contains Numbers (0-9)"),
            ("symbols", "Contains Symbols (!@#$)"),
            ("no_dictionary", "No Common Word / Leetspeak")
        ]

        for i, (key, label_text) in enumerate(criteria):
            lbl = tk.Label(checks_frame, text=f"✖ {label_text}", font=("Helvetica", 8), fg="#7f8c8d", bg="#f5f6fa")
            lbl.grid(row=i // 2, column=i % 2, sticky="w", padx=8, pady=2)
            self.check_labels[key] = lbl

        # Actionable Suggestions Box
        sug_frame = tk.LabelFrame(main, text=" Improvement Suggestions ", font=("Helvetica", 9, "bold"), bg="#f5f6fa", padx=8, pady=6)
        sug_frame.pack(fill="both", expand=True)

        self.sug_listbox = tk.Listbox(sug_frame, font=("Helvetica", 9), bd=0, bg="#f5f6fa", highlightthickness=0)
        self.sug_listbox.pack(fill="both", expand=True)

    def toggle_mask(self):
        self.entry.config(show="" if self.show_password.get() else "*")

    def on_password_change(self, *args):
        password = self.password_var.get()
        eval_data = PasswordEvaluator.evaluate(password)

        score = eval_data["score"]
        self.score_lbl.config(text=f"{score} / 100")

        # Redraw Dynamic Meter Geometry
        canvas_width = self.meter_canvas.winfo_width()
        if canvas_width <= 1:
            canvas_width = 570
        target_width = int((score / 100.0) * canvas_width)
        self.meter_canvas.coords(self.meter_bar, 0, 0, target_width, 18)
        self.meter_canvas.itemconfig(self.meter_bar, fill=eval_data["color"])

        # Update Classification Banner
        self.status_banner.config(
            text=f"Strength Category: {eval_data['category'].upper()}",
            bg=eval_data["color"]
        )

        # Update Entropy and Crack Time Metrics
        self.entropy_val.config(text=f"{eval_data['entropy_bits']} bits")
        self.crack_val.config(text=eval_data["time_to_crack"])

        # Update Criteria Checklist Flags
        for key, lbl in self.check_labels.items():
            if eval_data["checks"].get(key, False):
                lbl.config(text=f"✔ {lbl.cget('text')[2:]}", fg="#27ae60")
            else:
                lbl.config(text=f"✖ {lbl.cget('text')[2:]}", fg="#c0392b")

        # Update Suggestions Listbox
        self.sug_listbox.delete(0, tk.END)
        for sug in eval_data["suggestions"]:
            self.sug_listbox.insert(tk.END, f"• {sug}")


if __name__ == "__main__":
    root = tk.Tk()
    app = DynamicPasswordApp(root)
    root.mainloop()