from groq import Groq
from dotenv import load_dotenv
import os

load_dotenv()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

from flask import Flask, render_template, request, redirect, url_for, session, g, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'database.db')

app = Flask(__name__)
app.secret_key = 'replace_this_with_a_random_secret_in_production'

# --- Database helpers ---

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    cur = db.cursor()
    # users table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT
        )
    ''')
    # doubts table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS doubts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            user_id INTEGER,
            created_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    # replies table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS replies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            doubt_id INTEGER,
            user_id INTEGER,
            content TEXT NOT NULL,
            created_at TEXT,
            FOREIGN KEY(doubt_id) REFERENCES doubts(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    db.commit()

# initialize DB at start
with app.app_context():
    init_db()

# --- Auth helpers ---

def current_user():
    if 'user_id' in session:
        db = get_db()
        cur = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
        return cur.fetchone()
    return None

# --- Routes ---
@app.route('/')
def index():
    db = get_db()
    cur = db.execute('''
        SELECT d.*, u.username 
        FROM doubts d 
        LEFT JOIN users u ON d.user_id = u.id 
        ORDER BY d.created_at DESC
    ''')
    doubts = cur.fetchall()
    return render_template('index.html', doubts=doubts, user=current_user())
@app.route('/ai_suggest/<int:doubt_id>')
def ai_suggest(doubt_id):
    db = get_db()
    cur = db.execute('SELECT * FROM doubts WHERE id = ?', (doubt_id,))
    doubt = cur.fetchone()

    if not doubt:
        flash('Doubt not found')
        return redirect(url_for('index'))

    prompt = f"""
    A student has asked the following doubt:

    Title: {doubt['title']}
    Description: {doubt['description']}

    Provide a very clear, short explanation suitable for a student.
    """

    try:
      response = client.chat.completions.create(
    model="llama-3.3-70b-versatile",   # updated working model
    messages=[{"role": "user", "content": prompt}]
)

      ai_answer = response.choices[0].message.content

    except Exception as e:
        ai_answer = f"AI could not generate an answer (Groq error: {str(e)})"

    return render_template(
        "ai_answer.html",
        doubt=doubt,
        ai_answer=ai_answer,
        user=current_user()
    )




@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        if not username or not password:
            flash('Please provide both username and password')
            return redirect(url_for('signup'))
        db = get_db()
        try:
            db.execute('INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)',
                       (username, generate_password_hash(password), datetime.utcnow().isoformat()))
            db.commit()
            flash('Account created. Please log in.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already taken. Choose another.')
            return redirect(url_for('signup'))

    return render_template('signup.html', user=current_user())


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        db = get_db()
        cur = db.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cur.fetchone()
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            flash('Logged in successfully')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password')
            return redirect(url_for('login'))

    return render_template('login.html', user=current_user())


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out')
    return redirect(url_for('index'))


@app.route('/post', methods=['GET', 'POST'])
def post_doubt():
    user = current_user()
    if not user:
        flash('You must be logged in to post a doubt')
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title'].strip()
        description = request.form['description'].strip()
        if not title or not description:
            flash('Title and description are required')
            return redirect(url_for('post_doubt'))
        db = get_db()
        db.execute('INSERT INTO doubts (title, description, user_id, created_at) VALUES (?, ?, ?, ?)',
                   (title, description, user['id'], datetime.utcnow().isoformat()))
        db.commit()
        flash('Doubt posted')
        return redirect(url_for('index'))

    return render_template('post_doubt.html', user=user)


@app.route('/doubt/<int:doubt_id>', methods=['GET'])
def view_doubt(doubt_id):
    db = get_db()
    cur = db.execute('SELECT d.*, u.username FROM doubts d LEFT JOIN users u ON d.user_id = u.id WHERE d.id = ?', (doubt_id,))
    doubt = cur.fetchone()
    if not doubt:
        flash('Doubt not found')
        return redirect(url_for('index'))
    cur = db.execute('SELECT r.*, u.username FROM replies r LEFT JOIN users u ON r.user_id = u.id WHERE r.doubt_id = ? ORDER BY r.created_at ASC', (doubt_id,))
    replies = cur.fetchall()
    return render_template('view_doubt.html', doubt=doubt, replies=replies, user=current_user())


@app.route('/reply/<int:doubt_id>', methods=['POST'])
def reply(doubt_id):
    user = current_user()
    if not user:
        flash('You must be logged in to reply')
        return redirect(url_for('login'))
    content = request.form['content'].strip()
    if not content:
        flash('Reply cannot be empty')
        return redirect(url_for('view_doubt', doubt_id=doubt_id))
    db = get_db()
    db.execute('INSERT INTO replies (doubt_id, user_id, content, created_at) VALUES (?, ?, ?, ?)',
               (doubt_id, user['id'], content, datetime.utcnow().isoformat()))
    db.commit()
    flash('Reply posted')
    return redirect(url_for('view_doubt', doubt_id=doubt_id))


# ----- Edit / Delete Doubts -----

@app.route('/doubt/<int:doubt_id>/edit', methods=['GET', 'POST'])
def edit_doubt(doubt_id):
    user = current_user()
    if not user:
        flash('Login required')
        return redirect(url_for('login'))
    db = get_db()
    cur = db.execute('SELECT * FROM doubts WHERE id = ?', (doubt_id,))
    doubt = cur.fetchone()
    if not doubt:
        flash('Doubt not found')
        return redirect(url_for('index'))
    if doubt['user_id'] != user['id']:
        flash('You are not authorized to edit this doubt')
        return redirect(url_for('view_doubt', doubt_id=doubt_id))

    if request.method == 'POST':
        title = request.form['title'].strip()
        description = request.form['description'].strip()
        if not title or not description:
            flash('Title and description required')
            return redirect(url_for('edit_doubt', doubt_id=doubt_id))
        db.execute('UPDATE doubts SET title = ?, description = ? WHERE id = ?', (title, description, doubt_id))
        db.commit()
        flash('Doubt updated')
        return redirect(url_for('view_doubt', doubt_id=doubt_id))

    return render_template('edit_doubt.html', doubt=doubt, user=user)


@app.route('/doubt/<int:doubt_id>/delete', methods=['POST'])
def delete_doubt(doubt_id):
    user = current_user()
    if not user:
        flash('Login required')
        return redirect(url_for('login'))
    db = get_db()
    cur = db.execute('SELECT * FROM doubts WHERE id = ?', (doubt_id,))
    doubt = cur.fetchone()
    if not doubt:
        flash('Doubt not found')
        return redirect(url_for('index'))
    if doubt['user_id'] != user['id']:
        flash('You are not authorized to delete this doubt')
        return redirect(url_for('view_doubt', doubt_id=doubt_id))
    # delete replies for this doubt first (clean)
    db.execute('DELETE FROM replies WHERE doubt_id = ?', (doubt_id,))
    db.execute('DELETE FROM doubts WHERE id = ?', (doubt_id,))
    db.commit()
    flash('Doubt deleted')
    return redirect(url_for('index'))


# ----- Edit / Delete Replies -----

@app.route('/reply/<int:reply_id>/edit', methods=['GET', 'POST'])
def edit_reply(reply_id):
    user = current_user()
    if not user:
        flash('Login required')
        return redirect(url_for('login'))
    db = get_db()
    cur = db.execute('SELECT * FROM replies WHERE id = ?', (reply_id,))
    reply_row = cur.fetchone()
    if not reply_row:
        flash('Reply not found')
        return redirect(url_for('index'))
    if reply_row['user_id'] != user['id']:
        flash('You are not authorized to edit this reply')
        return redirect(url_for('view_doubt', doubt_id=reply_row['doubt_id']))

    if request.method == 'POST':
        content = request.form['content'].strip()
        if not content:
            flash('Reply cannot be empty')
            return redirect(url_for('edit_reply', reply_id=reply_id))
        db.execute('UPDATE replies SET content = ? WHERE id = ?', (content, reply_id))
        db.commit()
        flash('Reply updated')
        return redirect(url_for('view_doubt', doubt_id=reply_row['doubt_id']))

    return render_template('edit_reply.html', reply=reply_row, user=user)


@app.route('/reply/<int:reply_id>/delete', methods=['POST'])
def delete_reply(reply_id):
    user = current_user()
    if not user:
        flash('Login required')
        return redirect(url_for('login'))
    db = get_db()
    cur = db.execute('SELECT * FROM replies WHERE id = ?', (reply_id,))
    reply_row = cur.fetchone()
    if not reply_row:
        flash('Reply not found')
        return redirect(url_for('index'))
    if reply_row['user_id'] != user['id']:
        flash('You are not authorized to delete this reply')
        return redirect(url_for('view_doubt', doubt_id=reply_row['doubt_id']))
    db.execute('DELETE FROM replies WHERE id = ?', (reply_id,))
    db.commit()
    flash('Reply deleted')
    return redirect(url_for('view_doubt', doubt_id=reply_row['doubt_id']))


# ----- User profile -----
@app.route('/user/<username>')
def profile(username):
    db = get_db()
    cur = db.execute('SELECT * FROM users WHERE username = ?', (username,))
    user_row = cur.fetchone()
    if not user_row:
        flash('User not found')
        return redirect(url_for('index'))
    cur = db.execute('SELECT * FROM doubts WHERE user_id = ? ORDER BY created_at DESC', (user_row['id'],))
    user_doubts = cur.fetchall()
    return render_template('profile.html', profile_user=user_row, doubts=user_doubts, user=current_user())



if __name__ == '__main__':
    app.run(debug=True)
