import os
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3

app = Flask(__name__)
app.secret_key = 'clave_secreta_super_segura_para_el_sistema'

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# --- CONFIGURACIÓN DE LA BASE DE DATOS ---
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Tabla de Usuarios
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')
    
    # Tabla de Tareas (Cada usuario puede tener múltiples tareas/archivos)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT NOT NULL,
            description TEXT,
            filename TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')
    
    # Crear un Administrador por defecto si no existe
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        hashed_pw = generate_password_hash('admin123')
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                       ('admin', hashed_pw, 'admin'))
    
    conn.commit()
    conn.close()

# --- RUTAS DE ACCESO Y LOGIN ---

@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("SELECT id, password, role FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            session['username'] = username
            session['role'] = user[2]
            
            if user[2] == 'admin':
                return redirect(url_for('admin_panel'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            error = "Usuario o contraseña incorrectos."
            
    return render_template('login.html', error=error)

# --- PANEL DE ADMINISTRACIÓN ---

@app.route('/admin', methods=['GET', 'POST'])
def admin_panel():
    if 'role' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
        
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        # 1. Crear nuevo usuario
        if action == 'create_user':
            new_user = request.form['username']
            new_pass = generate_password_hash(request.form['password'])
            try:
                cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                               (new_user, new_pass, 'user'))
                conn.commit()
            except sqlite3.IntegrityError:
                pass # El usuario ya existe
                
        # 2. Borrar usuario
        elif action == 'delete_user':
            user_id_to_delete = request.form['user_id']
            cursor.execute("DELETE FROM users WHERE id = ?", (user_id_to_delete,))
            cursor.execute("DELETE FROM tasks WHERE user_id = ?", (user_id_to_delete,))
            conn.commit()

        # 3. Subir trabajo/archivo a un usuario específico
        elif action == 'assign_task':
            user_id = request.form['user_id']
            title = request.form['title']
            description = request.form['description']
            
            file = request.files['file']
            filename = None
            if file and file.filename != '':
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                
            cursor.execute("INSERT INTO tasks (user_id, title, description, filename) VALUES (?, ?, ?, ?)",
                           (user_id, title, description, filename))
            conn.commit()

    # Consultar datos para mostrar en la vista de admin
    cursor.execute("SELECT id, username FROM users WHERE role = 'user'")
    users = cursor.fetchall()
    
    cursor.execute("""
        SELECT tasks.id, users.username, tasks.title, tasks.description, tasks.filename 
        FROM tasks JOIN users ON tasks.user_id = users.id
    """)
    tasks = cursor.fetchall()
    
    conn.close()
    return render_template('admin_panel.html', users=users, tasks=tasks)

# --- PANEL PRIVADO DEL USUARIO ---

@app.route('/dashboard')
def user_dashboard():
    if 'role' not in session or session['role'] != 'user':
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Traer solo las tareas que pertenecen a este usuario exacto
    cursor.execute("SELECT title, description, filename FROM tasks WHERE user_id = ?", (user_id,))
    my_tasks = cursor.fetchall()
    conn.close()
    
    return render_template('user_dashboard.html', tasks=my_tasks)

# --- DESCARGA DE ARCHIVOS ---

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# --- CERRAR SESIÓN ---

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)