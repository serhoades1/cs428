"""
app.py - Flask backend. Serves the TypeScript frontend and exposes two JSON
endpoints that the frontend calls to generate passwords and passphrases.

Run:  python app.py   then open  http://127.0.0.1:5000
"""
import os
from flask import Flask, request, jsonify, send_from_directory
import generator
import vault

BASE = os.path.dirname(__file__)
app = Flask(__name__, static_folder="static", static_url_path="")

with open(os.path.join(BASE, "words.txt")) as f:
    WORDLIST = [w.strip() for w in f if w.strip()]

VAULT = vault.Vault(os.path.join(BASE, "vault.json"))


@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/api/generate", methods=["POST"])
def api_generate():
    d = request.get_json(force=True)
    try:
        pw, entropy, pool = generator.generate_password(
            d.get("length", 16),
            bool(d.get("upper", True)),
            bool(d.get("lower", True)),
            bool(d.get("digits", True)),
            bool(d.get("symbols", True)),
            bool(d.get("avoidAmbiguous", False)),
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({
        "password": pw,
        "entropy": round(entropy, 1),
        "poolSize": pool,
        "strength": generator.strength_label(entropy),
    })


@app.route("/api/passphrase", methods=["POST"])
def api_passphrase():
    d = request.get_json(force=True)
    phrase, entropy = generator.generate_passphrase(
        d.get("words", 4),
        d.get("separator", "-"),
        bool(d.get("capitalize", True)),
        bool(d.get("addNumber", False)),
        WORDLIST,
    )
    return jsonify({
        "password": phrase,
        "entropy": round(entropy, 1),
        "strength": generator.strength_label(entropy),
        "wordlistSize": len(WORDLIST),
    })


@app.route("/api/vault/save", methods=["POST"])
def api_vault_save():
    d = request.get_json(force=True)
    master = d.get("master", "")
    label = (d.get("label", "") or "").strip()
    password = d.get("password", "")
    if not master or not label or not password:
        return jsonify({"error": "Master password, a label, and a password are all required."}), 400
    try:
        count = VAULT.add(master, label, password)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"ok": True, "count": count})


@app.route("/api/vault/unlock", methods=["POST"])
def api_vault_unlock():
    d = request.get_json(force=True)
    master = d.get("master", "")
    if not master:
        return jsonify({"error": "Enter your master password."}), 400
    if not VAULT.exists():
        return jsonify({"entries": [], "empty": True})
    try:
        entries = VAULT.unlock_and_list(master)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"entries": entries})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
