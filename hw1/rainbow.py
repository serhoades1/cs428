#!/usr/bin/env python3
# rainbow.py - our rainbow table for CS 428/528 Project 1
# Tye Morris & Stephen Rhoades
#
# We assume passwords are 4 chars, lowercase letters + digits (36 chars),
# hashed with MD5. That's 36^4 = 1,679,616 possible passwords.
#
# A chain works by hashing a password, reducing the hash back into a password,
# hashing that, and so on. We only save the first and last password of each
# chain. Each column uses a different reduction so chains don't merge as much
# (that's the "rainbow" part vs the older Hellman tables). One table only gets
# us ~60% coverage because of merges, so we build 4 tables with different
# reductions and combine them, which is what RainbowCrack/ophcrack do too.
#
# Commands:
#   python rainbow.py gen                build the 4 tables
#   python rainbow.py crack              crack 50 random in-space passwords
#   python rainbow.py experiment         try passwords outside our space
#   python rainbow.py demo <password>    crack one password (for the demo)
#
# You can override the size with env vars T (chain length), M (chains/table),
# NUM_TABLES if you want to experiment.

import hashlib
import random
import time
import sys
import os

# our password space
CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789"   # 36 chars
BASE = len(CHARSET)
LENGTH = 4
KEYSPACE = BASE ** LENGTH                            # 1,679,616

# table settings (t = chain length, m = chains per table)
CHAIN_LEN = int(os.environ.get("T", "400"))
NUM_CHAINS = int(os.environ.get("M", "6000"))
NUM_TABLES = int(os.environ.get("NUM_TABLES", "4"))
SEED = 428                          # fixed so we get the same tables every time

TABLE_PREFIX = "rainbow_table"      # files end up as rainbow_table_0.txt etc
HASH_FN = "md5"
MIX = 0x9E3779B1                    # just a big odd number to make each table's reduction different


def index_to_password(idx: int) -> str:
    # turn a number into a 4-char password (basically base-36)
    chars = []
    for _ in range(LENGTH):
        idx, r = divmod(idx, BASE)
        chars.append(CHARSET[r])
    return "".join(reversed(chars))


def md5_hex(password: str) -> str:
    # normal md5 hex string, we use this for printing
    return hashlib.md5(password.encode("ascii")).hexdigest()


def md5_int(password: str) -> int:
    # md5 as an int straight from the raw bytes - faster than parsing the hex,
    # which matters a lot since we call this millions of times
    return int.from_bytes(hashlib.md5(password.encode("ascii")).digest(), "big")


def reduce_fn(hash_int: int, column: int, table_id: int) -> str:
    # the reduction function: take a hash and turn it back into a password.
    # we add the column so every column reduces differently (rainbow), and add
    # table_id * MIX so each of the 4 tables reduces differently too
    idx = (hash_int + column + table_id * MIX) % KEYSPACE
    return index_to_password(idx)


def build_one_table(table_id: int, rng: random.Random):
    # pick m random starting passwords, run each one out to a full chain,
    # and remember (endpoint -> startpoint)
    start_indices = rng.sample(range(KEYSPACE), NUM_CHAINS)
    table = {}
    merges = 0
    for sidx in start_indices:
        pw = index_to_password(sidx)
        start_pw = pw
        for col in range(CHAIN_LEN):
            pw = reduce_fn(md5_int(pw), col, table_id)
        # if two chains end on the same password they've merged, so we only
        # keep the first one and count the rest as wasted
        if pw in table:
            merges += 1
        else:
            table[pw] = start_pw
    fname = f"{TABLE_PREFIX}_{table_id}.txt"
    with open(fname, "w") as f:
        f.write(f"# table_id={table_id} charset={CHARSET} length={LENGTH} "
                f"hash={HASH_FN} t={CHAIN_LEN} m={NUM_CHAINS} seed={SEED}\n")
        f.write("# endpoint startpoint\n")
        for end in sorted(table):
            f.write(f"{end} {table[end]}\n")
    return table, merges, os.path.getsize(fname)


def generate_tables():
    print("=" * 64)
    print("RAINBOW TABLE GENERATION")
    print("=" * 64)
    print(f"Charset          : {CHARSET}  ({BASE} symbols)")
    print(f"Password length  : {LENGTH}")
    print(f"Keyspace (36^4)  : {KEYSPACE:,}")
    print(f"Hash function    : {HASH_FN.upper()}")
    print(f"Chain length (t) : {CHAIN_LEN}")
    print(f"Chains/table (m) : {NUM_CHAINS}")
    print(f"Tables           : {NUM_TABLES}")
    print(f"Total matrix     : {NUM_TABLES*NUM_CHAINS*CHAIN_LEN:,}  "
          f"({NUM_TABLES*NUM_CHAINS*CHAIN_LEN/KEYSPACE:.2f} x keyspace)")
    print("-" * 64)

    rng = random.Random(SEED)
    t0 = time.time()
    total_stored, total_merges, total_bytes = 0, 0, 0
    for k in range(NUM_TABLES):
        table, merges, size = build_one_table(k, rng)
        total_stored += len(table)
        total_merges += merges
        total_bytes += size
        print(f"  table {k}: stored {len(table):>5} chains, "
              f"{merges:>5} merges ({merges/NUM_CHAINS*100:4.1f}%), {size/1024:5.1f} KB")

    gen_time = time.time() - t0
    ops = NUM_TABLES * NUM_CHAINS * CHAIN_LEN
    print("-" * 64)
    print(f"Chains stored    : {total_stored:,} of {NUM_TABLES*NUM_CHAINS:,} attempted")
    print(f"Total merges     : {total_merges:,} "
          f"({total_merges/(NUM_TABLES*NUM_CHAINS)*100:.1f}%)")
    print(f"Generation time  : {gen_time:.2f} s")
    print(f"MD5 operations   : {ops:,}")
    print(f"Total table size : {total_bytes:,} bytes ({total_bytes/1024:.1f} KB)")
    print(f"Naive full dict  : ~{KEYSPACE*(LENGTH+33):,} bytes "
          f"(storing every pw+hash) -> tables use "
          f"{total_bytes/(KEYSPACE*(LENGTH+33))*100:.2f}% of that")
    print("=" * 64)


def load_tables():
    tables = []
    k = 0
    while os.path.exists(f"{TABLE_PREFIX}_{k}.txt"):
        t = {}
        with open(f"{TABLE_PREFIX}_{k}.txt") as f:
            for line in f:
                if line.startswith("#"):
                    continue
                end, start = line.split()
                t[end] = start
        tables.append(t)
        k += 1
    if not tables:
        print(f"[!] No {TABLE_PREFIX}_*.txt found - run 'python rainbow.py gen' first.")
        sys.exit(1)
    return tables


def crack_in_table(target_int, table, table_id):
    # try to find the password for this hash using one table.
    # start at the last column and work backwards. for each column we guess the
    # password might be in, we finish the chain from there and see if we land on
    # an endpoint we stored.
    for start_col in range(CHAIN_LEN - 1, -1, -1):
        pw = reduce_fn(target_int, start_col, table_id)
        for col in range(start_col + 1, CHAIN_LEN):
            pw = reduce_fn(md5_int(pw), col, table_id)
        if pw in table:
            # we found a matching endpoint, so rebuild that chain from its saved
            # start until the md5 actually matches (could be a false alarm)
            candidate = table[pw]
            for col in range(CHAIN_LEN):
                hc = md5_int(candidate)
                if hc == target_int:
                    return candidate
                candidate = reduce_fn(hc, col, table_id)
    return None


def crack_hash(target_hash_hex, tables):
    # try each table in turn until one of them cracks it
    target_int = int(target_hash_hex, 16)
    for table_id, table in enumerate(tables):
        found = crack_in_table(target_int, table, table_id)
        if found is not None:
            return found
    return None


def run_crack_batch(passwords, tables, label):
    print("=" * 64)
    print(f"CRACKING BATCH: {label}  ({len(passwords)} passwords)")
    print("=" * 64)
    hits = 0
    total_time = 0.0
    for pw in passwords:
        h = md5_hex(pw)
        t0 = time.time()
        found = crack_hash(h, tables)
        dt = time.time() - t0
        total_time += dt
        ok = (found == pw)
        hits += 1 if ok else 0
        status = "CRACKED" if ok else " miss  "
        print(f"  {pw:<6} md5={h}  [{status}] "
              f"recovered={found!s:<8} {dt*1000:6.0f} ms")
    print("-" * 64)
    rate = hits / len(passwords) * 100
    print(f"Recovered        : {hits}/{len(passwords)}  ({rate:.1f}%)")
    print(f"Total crack time : {total_time:.2f} s")
    print(f"Avg per password : {total_time/len(passwords)*1000:.0f} ms")
    print("=" * 64)
    return hits, len(passwords), total_time


def cmd_crack():
    tables = load_tables()
    rng = random.Random(2024)   # independent of the table seed -> unbiased sample
    sample = [index_to_password(rng.randrange(KEYSPACE)) for _ in range(50)]
    run_crack_batch(sample, tables, "in-space random passwords (len=4, a-z0-9)")


def cmd_experiment():
    tables = load_tables()
    print("\n### Experiment: passwords that VIOLATE the assumed space ###\n")
    too_long = ["hello", "secret", "pass12", "abc123"]      # length 5-6
    bad_chars = ["Pass", "ab!2", "A1b2", "r@ot"]            # uppercase / special
    run_crack_batch(too_long, tables, "OUT-OF-SPACE: too long (len 5-6)")
    run_crack_batch(bad_chars, tables, "OUT-OF-SPACE: uppercase / special chars")
    print("\nNote: these hashes have no preimage inside our 36^4 keyspace, so no")
    print("reduction can ever land on them -> the table structurally cannot crack them.\n")


def cmd_demo(pw):
    tables = load_tables()
    h = md5_hex(pw)
    print(f"Password : {pw}")
    print(f"MD5      : {h}")
    t0 = time.time()
    found = crack_hash(h, tables)
    dt = time.time() - t0
    print(f"Recovered: {found}   ({'OK' if found==pw else 'FAILED'}, {dt*1000:.0f} ms)")

def batch_crack_file(file_path):
    """
    Reads a text file containing MD5 hashes (one per line)
    and attempts to crack each using the loaded rainbow tables.
    """
    if not os.path.exists(file_path):
        print(f"[-] Error: File '{file_path}' not found.")
        return

    # Load rainbow tables into memory once
    print("[+] Loading rainbow tables...")
    tables = load_tables()  # Uses existing table-loading logic in rainbow.py
    if not tables:
        print("[-] No rainbow tables found. Please run 'python rainbow.py gen' first.")
        return

    # Read hashes from input file
    with open(file_path, "r") as f:
        hashes = [line.strip().lower() for line in f if line.strip()]

    print(f"[+] Loaded {len(hashes)} hashes from '{file_path}'. Starting batch crack...\n")
    
    results = {}
    cracked_count = 0

    for idx, target_hash in enumerate(hashes, 1):
        # Validate MD5 format (36 hex characters)
        if len(target_hash) != 32:
            print(f"[{idx}/{len(hashes)}] {target_hash} -> [INVALID MD5 FORMAT]")
            continue

        # Attempt to crack the individual hash
        password = crack_hash(target_hash, tables)  # Uses existing cracking logic
        
        if password:
            results[target_hash] = password
            cracked_count += 1
            print(f"[{idx}/{len(hashes)}] {target_hash} -> CRACKED: '{password}'")
        else:
            results[target_hash] = None
            print(f"[{idx}/{len(hashes)}] {target_hash} -> NOT FOUND")

    # Summary Output
    print("\n" + "=" * 40)
    print(f"BATCH PROCESS COMPLETE")
    print(f"Total Hashes Processed: {len(hashes)}")
    print(f"Successfully Cracked:   {cracked_count} ({cracked_count / len(hashes) * 100:.1f}%)")
    print("=" * 40)

    # Optional: Save results to output file
    output_path = "cracked_results.txt"
    with open(output_path, "w") as out_f:
        for h, pwd in results.items():
            out_f.write(f"{h}:{pwd if pwd else 'NOT_FOUND'}\n")
    print(f"[+] Results saved to '{output_path}'")

def batch_hash_and_crack_file(file_path):
    """
    Reads a text file containing plaintexts/passwords (one per line),
    converts each to an MD5 hash, and attempts to recover it using rainbow tables.
    """
    if not os.path.exists(file_path):
        print(f"[-] Error: File '{file_path}' not found.")
        return

    # Load rainbow tables into memory once
    print("[+] Loading rainbow tables...")
    tables = load_tables()  # Uses existing table-loading logic in rainbow.py
    if not tables:
        print("[-] No rainbow tables found. Please run 'python rainbow.py gen' first.")
        return

    # Read plaintext passwords from the input file
    with open(file_path, "r", encoding="utf-8") as f:
        passwords = [line.strip() for line in f if line.strip()]

    print(f"[+] Loaded {len(passwords)} passwords from '{file_path}'. Converting to MD5 & cracking...\n")
    
    results = {}
    cracked_count = 0

    for idx, original_password in enumerate(passwords, 1):
        # 1. Convert plaintext password to its MD5 hash
        md5_hash = hashlib.md5(original_password.encode("utf-8")).hexdigest()

        # 2. Attempt to crack the generated MD5 hash using rainbow tables
        recovered_password = crack_hash(md5_hash, tables)  # Uses existing cracking logic[cite: 2]

        # 3. Log results
        if recovered_password:
            results[original_password] = (md5_hash, recovered_password)
            cracked_count += 1
            print(f"[{idx}/{len(passwords)}] Target: '{original_password}' | MD5: {md5_hash} -> CRACKED: '{recovered_password}'")
        else:
            results[original_password] = (md5_hash, None)
            print(f"[{idx}/{len(passwords)}] Target: '{original_password}' | MD5: {md5_hash} -> NOT FOUND")

    # Summary Statistics
    print("\n" + "=" * 50)
    print("BATCH PROCESS COMPLETE")
    print(f"Total Passwords Processed: {len(passwords)}")
    print(f"Successfully Recovered:    {cracked_count} ({cracked_count / len(passwords) * 100:.1f}%)")
    print("=" * 40)

    # Export results to file
    output_path = "batch_crack_results.txt"
    with open(output_path, "w", encoding="utf-8") as out_f:
        out_f.write("Original_Password | MD5_Hash | Recovered_Password\n")
        out_f.write("-" * 60 + "\n")
        for orig_pwd, (h, rec_pwd) in results.items():
            status = rec_pwd if rec_pwd else "NOT_FOUND"
            out_f.write(f"{orig_pwd} | {h} | {status}\n")
            
    print(f"[+] Detailed report saved to '{output_path}'")


# ------------------------------------------------------------------
if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "gen"
    if cmd == "gen":
        generate_tables()
    elif cmd == "crack":
        cmd_crack()
    elif cmd == "experiment":
        cmd_experiment()
    elif cmd == "demo":
        cmd_demo(sys.argv[2])
    elif cmd == "file":
        batch_crack_file(sys.argv[2])
    elif cmd == "passwords":
        batch_hash_and_crack_file(sys.argv[2])
    else:
        print(__doc__)
