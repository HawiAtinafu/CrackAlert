## CrackAlert

CrackAlert is a password strength checker and cracking simulation tool that helps identify weak passwords using dictionary attacks (RockYou dataset) and brute force methods.

## Requirements

Make sure you have the following installed:
- **Python 3.7 or higher**
- Run: pip install -r requirements.txt

## Setup

1. **Clone the Repository**:  
   Clone this repository to your local machine.

2. **Add RockYou Dataset**:  
   Due to `.gitignore` rules, the RockYou dataset is not included. Please download the **`rockyou.txt`** file and place it in the `/data` directory.

3. **Create Empty File**:  
   Also, create an empty file named **`rockyou_sha256.txt`** in the `/data` directory. This will store the hashed version of RockYou passwords.

4. **Preprocess the RockYou Dataset**:  
   Before running the tool, navigate to the `/data` directory and run the `preprocess.py` script to hash the RockYou passwords.
   This will generate the hashed password list in the `rockyou_sha256.txt` file.

## How to Use

1. **Check Password Strength**:  
   Run the `password_checker.py` script to check the strength of a password or simulate a brute force attack.
