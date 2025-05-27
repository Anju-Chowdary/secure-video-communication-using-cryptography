from flask import Flask, request, render_template, redirect, session, url_for
from pymongo import MongoClient
from encryption.hill_cipher import hill_encrypt
from encryption.rsa_aes_utils import generate_rsa_keys
from encryption.password_crypto import hash_password, verify_password
from encryption.video_crypto_layers import encrypt_frame_enhanced as encrypt_frame_custom
from encryption.video_decrypt_layers import decrypt_frame_enhanced as decrypt_frame_custom
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from werkzeug.utils import secure_filename
from bson.binary import Binary
from bson import ObjectId
from PIL import Image
from io import BytesIO
import os, cv2, numpy as np
from datetime import datetime, UTC
import time
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from argon2 import PasswordHasher
from io import BytesIO
from flask import send_file
from flask import send_file, flash


app = Flask(__name__)
app.secret_key = "supersecretkey"

client = MongoClient("mongodb://localhost:27017/")
db = client["video_comm"]
users_col = db["users"]
requests_col = db["video_requests"]
video_col = db["video_responses"]

TEMP_VIDEO_FOLDER = "responses"
DECRYPTED_FOLDER = "decrypted_frames"
os.makedirs(TEMP_VIDEO_FOLDER, exist_ok=True)
os.makedirs(DECRYPTED_FOLDER, exist_ok=True)
ph = PasswordHasher()
@app.route('/')
def home():
    return render_template('home.html')

# --- MODIFY SIGNUP ROUTE ---
# --- Create PasswordHasher instance (top-level) ---
ph = PasswordHasher()
# --- MODIFY SIGNUP ROUTE ---
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if users_col.find_one({"username": username}):
            return "Username already exists", 409

        private_key, public_key = generate_rsa_keys()
        public_key_str = public_key.decode('utf-8')
        hashed = hash_password(password)
        hill_encrypted_pub_key = hill_encrypt(public_key_str, username)
        vault_password_hash = ph.hash(password)

        ecdsa_private = ec.generate_private_key(ec.SECP256R1())
        ecdsa_public = ecdsa_private.public_key()

        ecdsa_priv_pem = ecdsa_private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )

        ecdsa_pub_pem = ecdsa_public.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        users_col.insert_one({
            "username": username,
            "password_hash": hashed['hash'],
            "password_salt": hashed['salt'],
            "public_key": public_key_str,
            "private_key": private_key.decode('utf-8'),
            "hill_encrypted_public_key": hill_encrypted_pub_key,
            "vault_password_hash": vault_password_hash,
            "ecdsa_public_key": ecdsa_pub_pem
        })

        session['username'] = username

        pem_stream = BytesIO(ecdsa_priv_pem)
        return send_file(
            pem_stream,
            as_attachment=True,
            download_name=f"{username}_vault_private.pem",
            mimetype='application/x-pem-file'
        )

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = users_col.find_one({"username": username})
        if not user or not verify_password(user['password_hash'], user['password_salt'], password):
            return "Invalid username or password", 401

        session['username'] = username
        return redirect(url_for('dashboard'))

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect('/')

    current_user = session['username']
    user_list = [u['username'] for u in users_col.find({"username": {"$ne": current_user}})]
    incoming_requests = list(requests_col.find({"to": current_user, "status": "pending"}))
    sent_requests = list(requests_col.find({"from": current_user}))

    # Do NOT pass completed videos directly to dashboard
    return render_template("dashboard.html", user=current_user, users=user_list,
                           requests=incoming_requests, sent_requests=sent_requests, videos=[])
#--------------------------#
@app.route('/request-video', methods=['POST'])
def request_video():
    if 'username' not in session:
        return redirect('/')

    from_user = session['username']
    to_user = request.form['to_user']

    print(f"📩 Attempting to request video: from={from_user} to={to_user}")

    try:
        existing = requests_col.find_one({"from": from_user, "to": to_user, "status": {"$in": ["pending", "responding", "completed"]}})
        if not existing:
            result = requests_col.insert_one({
                "from": from_user,
                "to": to_user,
                "status": "pending",
                "timestamp": datetime.now(UTC)
            })
            print("✅ Request stored in DB with ID:", result.inserted_id)
        else:
            print("⚠️ Request already exists with status:", existing.get("status"))
    except Exception as e:
        print("❌ MongoDB insert failed for request:", e)

    return redirect(url_for('dashboard'))
#-------------------#
@app.route('/respond/<from_user>', methods=['POST'])
def respond_to_request(from_user):
    if 'username' not in session:
        return redirect('/')

    to_user = session['username']
    try:
        result = requests_col.update_one(
            {"from": from_user, "to": to_user, "status": "pending"},
            {"$set": {"status": "responding", "respond_time": datetime.now(UTC)}}
        )
        print("🛠 Responding to request. Matched count:", result.matched_count)
    except Exception as e:
        print("❌ Failed to update request status to responding:", e)
    return redirect(url_for('video_response_page', requester=from_user))


@app.route('/respond-video/<requester>')
def video_response_page(requester):
    return render_template('respond_video.html', requester=requester)

@app.route('/submit-response', methods=['POST'])
def submit_response():
    if 'username' not in session:
        return redirect('/')

    to_user = session['username']
    from_user = request.form['requester']
    temp_path = os.path.join(TEMP_VIDEO_FOLDER, f"temp_{from_user}_to_{to_user}.webm")
    cap = None

    try:
        video_file = request.files.get('video')
        if not video_file:
            raise Exception("No video uploaded")
        video_file.save(temp_path)

        receiver = users_col.find_one({"username": from_user})
        if not receiver:
            raise Exception("Receiver not found")

        public_key = serialization.load_pem_public_key(receiver['public_key'].encode())
        symmetric_key = from_user + to_user + "1234"

        cap = cv2.VideoCapture(temp_path)
        if not cap.isOpened():
            raise Exception("Could not open video")

        frames_data = []
        WIDTH, HEIGHT = 128, 128

        while True:
            ret, frame = cap.read()
            if not ret:
                break
            frame = cv2.resize(frame, (WIDTH, HEIGHT))
            _, img_bytes = cv2.imencode('.jpg', frame)
            encrypted_frame = encrypt_frame_custom(img_bytes.tobytes(), symmetric_key)
            frames_data.append(encrypted_frame)

        encrypted_key = public_key.encrypt(
            symmetric_key.encode(), 
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        video_doc = {
            "from": to_user,
            "to": from_user,
            "status": "completed",
            "frame_count": len(frames_data),
            "encrypted_key": Binary(encrypted_key),
            "timestamp": datetime.now(UTC)
        }
        video_id = video_col.insert_one(video_doc).inserted_id

        for idx, frame in enumerate(frames_data):
            db["video_frames"].insert_one({
                "video_id": video_id,
                "index": idx,
                "frame_data": frame
            })

        requests_col.update_one(
            {"from": from_user, "to": to_user},
            {"$set": {"status": "completed", "completed_time": datetime.now(UTC)}}
        )

        db["video_logs"].insert_one({
            "video_id": video_id,
            "from": to_user,
            "to": from_user,
            "log": f"Encrypted video submitted by {to_user} to {from_user}",
            "timestamp": datetime.now(UTC)
        })

        flash("✅ Video securely uploaded. The recipient can only decrypt it via their Vault.")
        return redirect(url_for('dashboard'))

    except Exception as e:
        print("❌ Error in /submit-response:", e)
        return "Failed to upload video", 500

    finally:
        if cap:
            cap.release()
            cv2.destroyAllWindows()
        time.sleep(0.5)
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except PermissionError:
                print(f"❌ Could not delete file: {temp_path}")


# --- END of vault + submit-response block ---


@app.route('/view-video/<video_id>')
def view_video(video_id):
    if 'username' not in session:
        return redirect('/')

    current_user = session['username']
    video_doc = video_col.find_one({"_id": ObjectId(video_id)})

    if not video_doc or video_doc['to'] != current_user:
        return "Unauthorized or video not found", 403

    user = users_col.find_one({"username": current_user})
    try:
        private_key = serialization.load_pem_private_key(user['private_key'].encode(), password=None)
        symmetric_key = private_key.decrypt(
            video_doc['encrypted_key'], 
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        ).decode()
    except Exception as e:
        print("❌ Decryption failed:", e)
        return "Decryption failed", 403

    WIDTH, HEIGHT = 128, 128
    filename = f"decrypted_{video_id}.mp4"
    out_path = os.path.join("static", "decrypted", filename)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    out = cv2.VideoWriter(out_path, cv2.VideoWriter_fourcc(*'mp4v'), 25.0, (WIDTH, HEIGHT))

    frame_docs = list(db["video_frames"].find({"video_id": ObjectId(video_id)}).sort("index", 1))

    for frame_doc in frame_docs:
        decrypted_bytes = decrypt_frame_custom(frame_doc['frame_data'], symmetric_key)
        img_array = np.array(Image.open(BytesIO(decrypted_bytes)).convert("RGB"))
        frame = cv2.resize(img_array, (WIDTH, HEIGHT))
        out.write(frame)

    out.release()
    return render_template("view_decrypted.html", filename=filename)


# --- NEW ROUTE: /my-vault ---
@app.route('/my-vault', methods=['GET', 'POST'])
def my_vault():
    if 'username' not in session:
        return redirect('/login')

    username = session['username']
    user = users_col.find_one({"username": username})

    if request.method == 'POST':
        nonce = session.get('vault_nonce')
        key_file = request.files.get('keyFile')
        if not key_file:
            return "Missing key file", 400

        try:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None)
            signature = private_key.sign(nonce.encode(), ec.ECDSA(hashes.SHA256()))
            public_key = serialization.load_pem_public_key(user['ecdsa_public_key'].encode())
            public_key.verify(signature, nonce.encode(), ec.ECDSA(hashes.SHA256()))
        except Exception:
            return "Invalid signature", 403

        videos = list(video_col.find({"to": username, "status": "completed"}))
        return render_template("my_vault.html", videos=videos)

    nonce = base64.b64encode(os.urandom(16)).decode()
    session['vault_nonce'] = nonce
    return render_template("vault_login.html", nonce=nonce)



if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
