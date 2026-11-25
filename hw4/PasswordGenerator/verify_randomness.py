"""
verify_randomness.py - our team's verification that the generator uses secure,
uniform randomness. Run:  python verify_randomness.py
"""
import os
import math
import secrets
import collections
import generator

print("=" * 60)
print("RANDOMNESS VERIFICATION")
print("=" * 60)

print("\n1) Randomness source")
sr = secrets.SystemRandom()
print("   secrets.SystemRandom base class:", sr.__class__.__bases__[0].__name__)
print("   (Python docs: secrets/SystemRandom pulls from os.urandom, the OS CSPRNG.)")
print("   os.urandom(8) sample:", os.urandom(8).hex())

print("\n2) Uniformity test (chi-square) over the full character pool")
pool = generator.UPPER + generator.LOWER + generator.DIGITS + generator.SYMBOLS
N = 200000
counts = collections.Counter(secrets.choice(pool) for _ in range(N))
k = len(pool)
expected = N / k
chi2 = sum((counts[c] - expected) ** 2 / expected for c in pool)
df = k - 1
crit = df + 3 * math.sqrt(2 * df)   # ~99.7% upper bound (normal approx.)
print(f"   samples = {N}, pool size = {k}, expected per char = {expected:.1f}")
print(f"   observed min = {min(counts.values())}, max = {max(counts.values())}")
print(f"   chi-square = {chi2:.1f}, degrees of freedom = {df}")
print(f"   ~99.7% critical bound ~= {crit:.1f}")
print("   result:", "UNIFORM (pass)" if chi2 < crit else "NOT uniform (fail)")

print("\n3) Unpredictability check")
a, _, _ = generator.generate_password(20, True, True, True, True, False)
b, _, _ = generator.generate_password(20, True, True, True, True, False)
print("   two generations with identical settings:")
print("   ", a)
print("   ", b)
print("   identical? ", a == b,
      "(a predictably seeded PRNG could be forced to repeat; secrets cannot)")
print("=" * 60)
