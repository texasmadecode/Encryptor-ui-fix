from flask import Flask, render_template, request
import threading
import os
from cryptography.fernet import Fernet
from Crypto.PublicKey import RSA

app = Flask(__name__)

class Encrypto:
    def __init__(self):
        self.password = None
        self.Key = None
        print("################################### WELCOME TO THE ENCRYPTOR BY AINC ########################################")
        print("\t\t\t\t\tThis is your own mobile vault")

    def Evaluator(self):
        if self.password is None:
            return "No password provided for evaluation."
        strength = "Weak"
        if len(self.password) >= 8 and any(c.isdigit() for c in self.password) and any(c.isupper() for c in self.password):
            strength = "Strong"
        elif len(self.password) >= 6:
            strength = "Medium"
        return f"Password strength: {strength}"

    def encrypt(self):
        key = Fernet.generate_key()
        cipher_suite = Fernet(key)
        file_path = "user_data.txt"
        if os.path.exists(file_path):
            with open(file_path, "rb") as file:
                file_data = file.read()
            encrypted_data = cipher_suite.encrypt(file_data)
            with open("encrypted_user_data.txt", "wb") as enc_file:
                enc_file.write(encrypted_data)
            with open("secret.key", "wb") as key_file:
                key_file.write(key)
            print("File encrypted successfully. Secret key saved to 'secret.key'.")

    def decrypt(self):
        if not self.Key:
            return "No key provided for decryption."
        if not os.path.exists("encrypted_user_data.txt"):
            return "Encrypted file not found."
        try:
            cipher_suite = Fernet(self.Key)
            with open("encrypted_user_data.txt", "rb") as enc_file:
                encrypted_data = enc_file.read()
            decrypted_data = cipher_suite.decrypt(encrypted_data)
            with open("decrypted_user_data.txt", "wb") as dec_file:
                dec_file.write(decrypted_data)
            return "File decrypted successfully."
        except Exception as e:
            return f"Decryption failed: {e}"

    def RSA_gen(self):
        key = RSA.generate(2048)
        private_key = key.export_key()
        with open("private.pem", "wb") as priv_file:
            priv_file.write(private_key)
        public_key = key.publickey().export_key()
        with open("public.pem", "wb") as pub_file:
            pub_file.write(public_key)
        return "RSA key pair generated successfully."

# Flask routes for the Web UI
@app.route('/')
def home():
    return render_template('index.html', result=None)

@app.route('/evaluate', methods=['POST'])
def evaluate():
    password = request.form['password']
    encrypto = Encrypto()
    encrypto.password = password
    result = encrypto.Evaluator()
    return render_template('index.html', result=result)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    encrypto = Encrypto()
    encrypto.encrypt()
    return "File encrypted successfully!"

@app.route('/decrypt', methods=['POST'])
def decrypt():
    key = request.form['key']
    encrypto = Encrypto()
    encrypto.Key = key.encode()  # Ensure the key is in bytes
    result = encrypto.decrypt()
    return result

@app.route('/generate_key', methods=['POST'])
def generate_key():
    encrypto = Encrypto()
    result = encrypto.RSA_gen()
    return result

# Launch the Flask app in a separate thread
def launch_web_ui():
    app.run(debug=False, use_reloader=False)

if __name__ == "__main__":
    choice = input("Do you want to open the Web UI? (y/n): ").strip().lower()
    if choice in ('y', 'yes'):
        threading.Thread(target=launch_web_ui).start()
        print("Web UI is running. Open http://127.0.0.1:5000 in your browser.")
    else:
        e = Encrypto()
        print("\nGreat Job! Now that we have our setup successfully initialized, what would you like to do?")
        while True:
            choice = input(
                "\n1) Evaluate password strength.\n2) Encrypt your Username and Password File.\n3) Decrypt an existing file (Secret key needed).\n4) Generate a new RSA key pair.\n5) Quit for now.\n(Enter your choices as 1-5):\n")
            if choice == "1":
                password = input("Enter the password to evaluate: ")
                e.password = password
                print(e.Evaluator())
            elif choice == "2":
                e.encrypt()
            elif choice == "3":
                key = input("Enter the secret key: ")
                e.Key = key.encode()
                print(e.decrypt())
            elif choice == "4":
                print(e.RSA_gen())
            elif choice == "5":
                print("\nThank you for using the Encryptor by AINC! Hope to see you soon!")
                exit(1)
            else:
                print("Wrong input, please enter again!")

            print("\nThank you for using the Encryptor by AINC! Hope to see you soon!")
            exit(1)
        else:
            print("Wrong input, please enter again!")
