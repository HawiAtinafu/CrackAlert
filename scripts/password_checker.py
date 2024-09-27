# scripts/password_checker.py

import hashlib
import os
import sys
import csv
from tqdm import tqdm
import itertools
import string
import time

DATA_DIR = '../data'
ROCKYOU_HASHES_FILE = os.path.join(DATA_DIR, 'rockyou_sha256.txt')
USER_CREDENTIALS_FILE = os.path.join(DATA_DIR, 'user_credentials.csv')
ADMIN_ALERTS_FILE = os.path.join(DATA_DIR, 'admin_alerts.log')

def hash_password(password, algorithm='sha256'):
    if algorithm == 'sha256':
        return hashlib.sha256(password.encode('utf-8')).hexdigest()
    else:
        raise ValueError("Unsupported hashing algorithm.")

def load_rockyou_hashes(file_path):
    if not os.path.exists(file_path):
        print(f"Error: {file_path} does not exist. Please preprocess RockYou dataset first.")
        sys.exit(1)
    
    print("Loading RockYou hashed passwords into memory...")
    rockyou_hashes = set()
    with open(file_path, 'r', encoding='utf-8') as file:
        for line in tqdm(file, desc="Loading Hashes"):
            hash_val = line.strip()
            if hash_val:
                rockyou_hashes.add(hash_val)
    print(f"Loaded {len(rockyou_hashes)} hashed passwords from RockYou dataset.")
    return rockyou_hashes

def calculate_entropy(password):
    import math
    import re

    pool = 0
    if re.search(r'[a-z]', password):
        pool += 26
    if re.search(r'[A-Z]', password):
        pool += 26
    if re.search(r'\d', password):
        pool += 10
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        pool += 32
    if re.search(r'[^a-zA-Z0-9!@#$%^&*(),.?":{}|<>]', password):
        pool += 32  # Assuming additional special characters
    entropy = len(password) * math.log2(pool) if pool else 0
    return entropy

def check_password_strength(password):
    entropy = calculate_entropy(password)
    if entropy < 28:
        return 'Weak', entropy
    elif 28 <= entropy < 36:
        return 'Medium', entropy
    else:
        return 'Strong', entropy

def dictionary_attack(hashed_password, rockyou_hashes):
    return hashed_password in rockyou_hashes

def alert_admin(username, password_attempt):
    with open(ADMIN_ALERTS_FILE, 'a', encoding='utf-8') as alert_file:
        alert_file.write(f"Weak password attempt by user '{username}': {password_attempt}\n")
    print("Admin has been alerted about the weak password attempt.")

def provide_recommendations(strength, is_weak):
    if strength == 'Weak':
        print("Recommendation: Use a longer password with a mix of uppercase, lowercase, numbers, and special characters.")
    elif strength == 'Medium':
        print("Recommendation: Consider adding more unique characters, including uppercase letters, numbers, and special symbols.")
    else:
        print("Your password is strong.")
    
    if is_weak:
        print("Recommendation: Choose a different password that is not commonly used.")

def brute_force_attack(hashed_password, salt, max_length=4, algorithm='sha256'):
    chars = string.ascii_letters + string.digits + string.punctuation
    for length in range(1, max_length + 1):
        print(f"Trying passwords of length {length}...")
        for guess in tqdm(itertools.product(chars, repeat=length), desc=f"Trying length {length}"):
            guess_password = ''.join(guess)
            # Hash the guess with the same algorithm and salt
            hasher = hashlib.sha256()
            hasher.update(bytes.fromhex(salt) + guess_password.encode('utf-8'))
            hashed_guess = hasher.hexdigest()
            if hashed_guess == hashed_password:
                return guess_password
    return None

def simulate_brute_force():
    password = input("Enter a password to hash for brute-force simulation: ").strip()
    if not password:
        print("Password cannot be empty.")
        return
    
    # Hash the password with a new salt
    salt = os.urandom(16).hex()
    hasher = hashlib.sha256()
    hasher.update(bytes.fromhex(salt) + password.encode('utf-8'))
    hashed_password = hasher.hexdigest()
    
    print("Starting brute-force attack simulation...")
    start_time = time.time()
    cracked_password = brute_force_attack(hashed_password, salt, max_length=4)
    end_time = time.time()
    if cracked_password:
        print(f"Password cracked! The password is: {cracked_password}")
    else:
        print("Password could not be cracked within the given parameters.")
    print(f"Time taken: {end_time - start_time:.2f} seconds")

def check_password_flow(rockyou_hashes):
    password = input("Enter the password to check: ").strip()
    
    if not password:
        print("Password cannot be empty.")
        return
    
    # Perform dictionary attack first
    hashed_input = hash_password(password)
    is_weak = dictionary_attack(hashed_input, rockyou_hashes)

    # If password is found in the RockYou dataset, classify it as weak
    if is_weak:
        print("Alert: This password is found in the RockYou dataset and is considered weak.")
        strength = 'Weak'  
    else:
        # Check password strength based on entropy
        strength, entropy = check_password_strength(password)
        print(f"Password Entropy: {entropy:.2f} bits")
        print(f"Password Strength: {strength}")
    
    # Provide recommendations
    provide_recommendations(strength, is_weak)

    if is_weak:
        alert_admin("username_placeholder", password) 


def main_menu(rockyou_hashes):
    while True:
        print("\n=== Custom Password Strength Checker ===")
        print("1. Check Password Strength")
        print("2. Simulate Brute-Force Attack")
        print("3. Exit")
        choice = input("Select an option (1/2/3): ").strip()
        
        if choice == '1':
            check_password_flow(rockyou_hashes)
        elif choice == '2':
            simulate_brute_force()
        elif choice == '3':
            print("Exiting the tool. Goodbye!")
            break
        else:
            print("Invalid option. Please choose 1, 2, or 3.")

if __name__ == "__main__":
    rockyou_hashes = load_rockyou_hashes(ROCKYOU_HASHES_FILE)
    main_menu(rockyou_hashes)
