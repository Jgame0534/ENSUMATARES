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
    
    # Tabla de Tareas
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
    
    # Crear Administrador Maestro si no existe
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        hashed_pw = generate_password_hash('admin123')
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                       ('admin', hashed_pw, 'admin'))
    
    conn.commit()
    conn.close()

# Iniciar base de datos al arrancar
init_db()

# --- 1. RUTA PRINCIPAL (LO PRIMERO QUE VE CUALQUIERA) ---
@app.route('/', methods=['GET', 'POST'])
def login():
    # Si la persona ya inició sesión previamente, la enviamos a su pantalla correspondiente
    if 'role' in session:
        if session['role'] == 'admin':
            return redirect(url_for('admin_panel'))
        else:
            return redirect(url_for('user_dashboard'))

    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("SELECT id, password, role FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        
        # Verificar contraseña
        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            session['username'] = username
            session['role'] = user[2]
            
            # Redirección según rol
            if user[2] == 'admin':
                return redirect(url_for('admin_panel'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            error = "Usuario o contraseña incorrectos."
            
    return render_template('login.html', error=error)

# --- 2. PANEL PRIVADO DEL ADMINISTRADOR ---
@app.route('/admin', methods=['GET', 'POST'])
def admin_panel():
    # BLOQUEO DE SEGURIDAD: Si no es admin, no entra aquí bajo ninguna circunstancia
    if 'role' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
        
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        # Crear Usuario
        if action == 'create_user':
            new_user = request.form['username']
            new_pass = generate_password_hash(request.form['password'])
            try:
                cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                               (new_user, new_pass, 'user'))
                conn.commit()
            except sqlite3.IntegrityError:
                pass
                
        # Eliminar Usuario
        elif action == 'delete_user':
            user_id_to_delete = request.form['user_id']
            cursor.execute("DELETE FROM users WHERE id = ?", (user_id_to_delete,))
            cursor.execute("DELETE FROM tasks WHERE user_id = ?", (user_id_to_delete,))
            conn.commit()

        # Asignar Trabajo / Archivo
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

    cursor.execute("SELECT id, username FROM users WHERE role = 'user'")
    users = cursor.fetchall()
    
    cursor.execute("""
        SELECT tasks.id, users.username, tasks.title, tasks.description, tasks.filename 
        FROM tasks JOIN users ON tasks.user_id = users.id
    """)
    tasks = cursor.fetchall()
    
    conn.close()
    return render_template('admin_panel.html', users=users, tasks=tasks)

# --- 3. PANEL PRIVADO DEL USUARIO / ESTUDIANTE ---
@app.route('/dashboard')
def user_dashboard():
    # BLOQUEO DE SEGURIDAD: Si no ha iniciado sesión, lo manda al login
    if 'role' not in session or session['role'] != 'user':
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Consultar SOLO los trabajos asignados a ESTE usuario
    cursor.execute("SELECT title, description, filename FROM tasks WHERE user_id = ?", (user_id,))
    my_tasks = cursor.fetchall()
    conn.close()
    
    return render_template('user_dashboard.html', tasks=my_tasks)

# --- 4. DESCARGA DE ARCHIVOS ---
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    if 'role' not in session:
        return redirect(url_for('login'))
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# --- 5. CERRAR SESIÓN ---
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)