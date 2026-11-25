"""
generator.py - core password / passphrase generation.

All randomness comes from Python's `secrets` module, which is a cryptographically
secure PRNG backed by the operating system's CSPRNG (os.urandom). We never use the
ordinary `random` module, because that one is a predictable Mersenne Twister and is
not safe for secrets.
"""
import secrets
import math

UPPER   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
LOWER   = "abcdefghijklmnopqrstuvwxyz"
DIGITS  = "0123456789"
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"

# Characters that look alike and are easy to confuse when typing a password.
AMBIGUOUS = set("Il1O0o")


def _secure_shuffle(items):
    """Fisher-Yates shuffle driven by secrets (NOT random.shuffle, which is insecure)."""
    for i in range(len(items) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        items[i], items[j] = items[j], items[i]


def generate_password(length, use_upper, use_lower, use_digits, use_symbols,
                      avoid_ambiguous=False):
    """Return (password, entropy_bits, pool_size)."""
    classes = []
    if use_upper:  classes.append(UPPER)
    if use_lower:  classes.append(LOWER)
    if use_digits: classes.append(DIGITS)
    if use_symbols: classes.append(SYMBOLS)
    if not classes:
        raise ValueError("Select at least one character type.")

    if avoid_ambiguous:
        classes = [''.join(c for c in cls if c not in AMBIGUOUS) for cls in classes]
        classes = [cls for cls in classes if cls]

    pool = ''.join(classes)
    # make sure the password is at least long enough to hold one of each type
    length = max(int(length), len(classes))

    # guarantee at least one character from every selected type (NordPass does this)
    chars = [secrets.choice(cls) for cls in classes]
    # fill the rest from the whole pool
    while len(chars) < length:
        chars.append(secrets.choice(pool))
    # shuffle so the guaranteed characters are not stuck at the front
    _secure_shuffle(chars)

    password = ''.join(chars)
    entropy = length * math.log2(len(pool))        # bits of entropy for this keyspace
    return password, entropy, len(pool)


def generate_passphrase(num_words, separator, capitalize, add_number, wordlist):
    """Bonus mode: a random-word passphrase. Return (phrase, entropy_bits)."""
    num_words = max(1, int(num_words))
    words = [secrets.choice(wordlist) for _ in range(num_words)]
    if capitalize:
        words = [w.capitalize() for w in words]
    phrase = separator.join(words)

    entropy = num_words * math.log2(len(wordlist))
    if add_number:
        n = secrets.randbelow(100)                 # 0-99
        phrase = phrase + separator + f"{n:02d}"
        entropy += math.log2(100)
    return phrase, entropy


def strength_label(entropy_bits):
    """Map entropy to NordPass's three-level rating."""
    if entropy_bits < 40:
        return "Weak"
    if entropy_bits < 75:
        return "Medium"
    return "Strong"
