from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import hashlib

app = Flask(__name__)
app.secret_key = 'ef1b7f45ed011a3fbe6790873b6bed1283be3c42d5ddb7633acd9cff8d287031'


class VulnerableTodo:
    def __init__(self):
        self.conn = sqlite3.connect('vulnerable_todo.db', check_same_thread=False)
        self.c = self.conn.cursor()
        self.create_tables()

    def create_tables(self):
        self.c.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY,
                            username TEXT NOT NULL UNIQUE,
                            password TEXT NOT NULL
                          );''')

        self.c.execute('''CREATE TABLE IF NOT EXISTS notes (
                            id INTEGER PRIMARY KEY,
                            user_id INTEGER NOT NULL,
                            content TEXT NOT NULL,
                            is_deleted INTEGER DEFAULT 0,
                            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY(user_id) REFERENCES users(id)
                          );''')

        self.c.execute('''CREATE TABLE IF NOT EXISTS posts (
                            id INTEGER PRIMARY KEY,
                            user_id INTEGER NOT NULL,
                            title TEXT NOT NULL,
                            content TEXT NOT NULL,
                            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                            is_deleted INTEGER DEFAULT 0,
                            visible INTEGER DEFAULT 1,
                            FOREIGN KEY(user_id) REFERENCES users(id)
                          );''')

        self.conn.commit()

    def register_user(self, username, password):
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        query = f"INSERT INTO users (username, password) VALUES ('{username}', '{hashed_password}')"
        try:
            self.c.execute(query)
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def login_user(self, username, password):
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        query = f"SELECT id FROM users WHERE username='{username}' AND password='{hashed_password}'"
        self.c.execute(query)
        user = self.c.fetchone()
        return user[0] if user else None

    def add_note(self, user_id, content):
        query = f"INSERT INTO notes (user_id, content) VALUES ({user_id}, '{content}')"
        self.c.execute(query)
        self.conn.commit()

    def get_user_notes(self, user_id):
        query = f"SELECT id, content FROM notes WHERE user_id={user_id} AND is_deleted=0"
        self.c.execute(query)
        return self.c.fetchall()

    def add_post(self, user_id, title, content):
        query = f"INSERT INTO posts (user_id, title, content) VALUES ({user_id}, '{title}', '{content}')"
        self.c.execute(query)
        self.conn.commit()

    def get_all_posts(self, user_input):
        query = f"SELECT id, title, content, created_at FROM posts WHERE visible = 1 AND {user_input} ORDER BY created_at DESC"
        try:
            posts = self.c.execute(query).fetchall()
        except Exception as e:
            print(f"SQL query execution error: {e}")
            posts = []
        return posts


    def set_post_visibility(self, post_id, visible):
        query = f"UPDATE posts SET visible = {visible} WHERE id = {post_id}"
        self.c.execute(query)
        self.conn.commit()

    def delete_post(self, post_id):
        self.c.execute('UPDATE posts SET is_deleted = 1 WHERE id = ?', (post_id,))
        self.conn.commit()

    def delete_note(self, note_id):
        self.c.execute('UPDATE notes SET is_deleted = 1 WHERE id = ?', (note_id,))
        self.conn.commit()


db = VulnerableTodo()


@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if db.register_user(username, password):
            return redirect(url_for('login'))
        else:
            return "Username already exists, please choose another one."
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_id = db.login_user(username, password)
        if user_id is not None:
            session['user_id'] = user_id
            session['is_admin'] = (username == 'admin')
            return redirect(url_for('dashboard'))
        else:
            return "Invalid credentials. Please try again."
    return render_template('login.html')


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    if request.method == 'POST':
        content = request.form['content']
        db.add_note(user_id, content)

    notes = db.get_user_notes(user_id)
    return render_template('dashboard.html', notes=notes)


@app.route('/posts', methods=['GET', 'POST'])
def posts():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    user_input = request.args.get('user_input', '1')

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        db.add_post(user_id, title, content)

    all_posts = db.get_all_posts(user_input)

    return render_template('post.html', posts=all_posts)

@app.route('/admin/posts', methods=['GET', 'POST'])
def admin_posts():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))

    if request.method == 'POST':
        post_id = request.form['post_id']
        visibility = request.form['visibility']
        db.set_post_visibility(post_id, int(visibility))
        return redirect(url_for('admin_posts'))

    all_posts = db.c.execute('''SELECT posts.id, users.username, posts.title, posts.content, posts.created_at, posts.visible
                                 FROM posts
                                 JOIN users ON posts.user_id = users.id
                                 ORDER BY posts.created_at DESC''').fetchall()
    return render_template('admin_posts.html', posts=all_posts)

@app.route('/delete_post/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    if 'user_id' not in session:
        return "Unauthorized", 403

    user_id = session['user_id']
    db.c.execute('SELECT user_id FROM posts WHERE id=?', (post_id,))
    post_owner = db.c.fetchone()

    if post_owner is None:
        return "Post not found", 404

    if post_owner[0] != user_id and not session.get('is_admin'):
        return "Unauthorized", 403

    db.delete_post(post_id)
    return redirect(url_for('posts'))


@app.route('/delete_note/<int:note_id>', methods=['POST'])
def delete_note(note_id):
    if 'user_id' not in session:
        return "Unauthorized", 403

    user_id = session['user_id']
    db.c.execute('SELECT user_id FROM notes WHERE id=?', (note_id,))
    note_owner = db.c.fetchone()

    if note_owner is None:
        return "Note not found", 404

    if note_owner[0] != user_id:
        return "Unauthorized", 403

    db.delete_note(note_id)
    return redirect(url_for('dashboard'))


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(port=5000)