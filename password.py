from flask import Flask, render_template, request, jsonify, redirect, url_for
import random
import string
import hashlib
import os

app = Flask(__name__)

def generate_password(length=12, use_lowercase=True, use_uppercase=True, use_digits=True, use_special=True):
    char_sets = []
    if use_lowercase:
        char_sets.append(string.ascii_lowercase)
    if use_uppercase:
        char_sets.append(string.ascii_uppercase)
    if use_digits:
        char_sets.append(string.digits)
    if use_special:
        char_sets.append(string.punctuation)

    if not char_sets:
        raise ValueError("At least one character type must be selected")

    all_chars = ''.join(char_sets)

    password = [random.choice(char_set) for char_set in char_sets]

    password += [random.choice(all_chars) for _ in range(length - len(password))]

    random.shuffle(password)

    return ''.join(password)

def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return key, salt

def verify_password(stored_password, stored_salt, password_attempt):
    key, _ = hash_password(password_attempt, stored_salt)
    return key == stored_password

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password, salt = hash_password(password)
        return render_template('index.html', hashed_password=hashed_password.hex(), salt=salt, username=username)
    return render_template('index.html')

@app.route('/generate', methods=['GET', 'POST'])
def generate():
    if request.method == 'POST':
        length = int(request.form['length'])
        use_lowercase = 'use_lowercase' in request.form
        use_uppercase = 'use_uppercase' in request.form
        use_digits = 'use_digits' in request.form
        use_special = 'use_special' in request.form
        
        password = generate_password(length, use_lowercase, use_uppercase, use_digits, use_special)
        return redirect(url_for('login', generated_password=password))
    return render_template('generate.html')

@app.route('/check', methods=['POST'])
def check():
    password = request.form['password']
    is_secure = len(password) >= 8
    return jsonify({'is_secure': is_secure})

if __name__ == '__main__':
    app.run(debug=True)
