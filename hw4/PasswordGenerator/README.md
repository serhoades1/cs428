# Password Generator (NordPass replica) - CS 428/528 Project 4

Tye Morris and Stephen Rhoades

A secure password / passphrase generator and encrypted vault modeled on NordPass. The
Python backend does all generation with a cryptographically secure RNG (`secrets`); the
TypeScript frontend collects options and shows the result with a live strength meter.
Generated passwords can be saved to a vault that is encrypted at rest (PBKDF2 + AES)
behind a master password.

## Run it
```
pip install -r requirements.txt
python app.py
```
Then open http://127.0.0.1:5000 in a browser.

## Verify the randomness
```
python verify_randomness.py
```
Prints the randomness source, a chi-square uniformity test, and an unpredictability check.

## Files
- `app.py` - Flask backend; serves the page and the generate, passphrase, and vault endpoints.
- `generator.py` - core generation logic (secrets, character pool, secure shuffle, entropy).
- `vault.py` - secure storage (PBKDF2-HMAC-SHA256 key derivation + AES/Fernet encryption).
- `src/app.ts` - TypeScript frontend source (compiled to `static/app.js`).
- `static/index.html`, `static/app.js` - the user interface.
- `words.txt` - 618-word list for passphrase mode.
- `verify_randomness.py` - team randomness verification.

## Vault
Saved passwords are stored in `vault.json`, encrypted with a key derived from your
master password. The master password is never stored; without it the file cannot be
read. (`vault.json` is created on first save.)

## Rebuild the frontend (optional)
```
tsc src/app.ts --outDir static --target ES2017 --lib ES2017,DOM --strict
```
