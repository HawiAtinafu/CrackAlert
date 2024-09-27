# scripts/preprocess_rockyou.py

import hashlib
import os
from tqdm import tqdm

def hash_password(password, algorithm='sha256'):
    if algorithm == 'sha256':
        return hashlib.sha256(password.encode('utf-8')).hexdigest()
    else:
        raise ValueError("Unsupported hashing algorithm.")

def preprocess_rockyou(input_file, output_file, algorithm='sha256'):
    if not os.path.exists(input_file):
        print(f"Error: {input_file} does not exist.")
        return
    
    print(f"Hashing RockYou passwords using {algorithm.upper()}")
    
    with open(input_file, 'r', encoding='latin-1') as infile, \
         open(output_file, 'w', encoding='utf-8') as outfile:
        for line in tqdm(infile, desc="Hashing"):
            password = line.strip()
            if password:
                hashed = hash_password(password, algorithm)
                outfile.write(f"{hashed}\n")
    
    print(f"Hashed passwords saved to {output_file}")

if __name__ == "__main__":
    input_path = '../data/rockyou.txt'
    output_path = '../data/rockyou_sha256.txt'
    preprocess_rockyou(input_path, output_path)
