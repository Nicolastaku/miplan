import os
import secrets
from datetime import timedelta
from functools import wraps

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from werkzeug.security import check_password_hash
from supabase import create_client, Client
from dotenv import load_dotenv

load_dotenv()

# ============================================================
# CONFIG
# ============================================================
ADMIN_USER = os.environ.get('ADMIN_USER', 'yo')
ADMIN_PASSWORD_HASH = os.environ.get('ADMIN_PASSWORD_HASH', '')
ADMIN_PASSWORD_PLAIN = os.environ.get('ADMIN_PASSWORD', 'cambiar123')

SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_urlsafe(32)

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=90)

# ============================================================
# SUPABASE
# ============================================================
SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY')

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("Faltan SUPABASE_URL o SUPABASE_KEY")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ============================================================
# AUTH
# ============================================================
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('auth'):
            if request.path.startswith('/api/'):
                return jsonify({'error': 'No autorizado'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

def _check_password(password):
    if ADMIN_PASSWORD_HASH:
        try:
            return check_password_hash(ADMIN_PASSWORD_HASH, password)
        except Exception:
            return False
    return password == ADMIN_PASSWORD_PLAIN

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        user = request.form.get('user', '').strip()
        pw = request.form.get('password', '')
        if user == ADMIN_USER and _check_password(pw):
            session.permanent = True
            session['auth'] = True
            return redirect(url_for('index'))
        error = 'Usuario o contraseña incorrectos'
    return '''<!DOCTYPE html>
<html lang="es"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Login · Mi Plan</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, sans-serif; background: #0a0a0a; color: #d8d0c4;
         min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
  .box { background: #141210; border: 1px solid #2e2721; border-radius: 12px;
         padding: 32px; width: 100%; max-width: 380px;
         box-shadow: 0 20px 60px rgba(0,0,0,0.7); }
  h1 { font-size: 20px; font-weight: 700; margin-bottom: 6px; letter-spacing: 0.02em; }
  h1::before { content: '❖ '; color: #7a8b6a; }
  .sub { color: #8a7f70; font-size: 13px; margin-bottom: 24px; }
  label { font-size: 11px; color: #8a7f70; font-weight: 600; text-transform: uppercase;
          letter-spacing: 0.08em; display: block; margin-bottom: 6px; }
  input { width: 100%; padding: 11px 14px; background: #0a0a0a; color: #d8d0c4;
          border: 1px solid #2e2721; border-radius: 8px; font-size: 14px;
          margin-bottom: 16px; font-family: inherit; }
  input:focus { outline: none; border-color: #7a8b6a; }
  button { width: 100%; padding: 12px; background: #4a5540; color: #d8d0c4;
           border: 1px solid #5a6550; border-radius: 8px; font-size: 14px; font-weight: 600;
           font-family: inherit; cursor: pointer; transition: background 0.15s; }
  button:hover { background: #5a6550; }
  .err { color: #a04a3a; font-size: 13px; margin-bottom: 14px; padding: 10px;
         background: rgba(160,74,58,0.1); border-radius: 6px; text-align: center;
         border: 1px solid rgba(160,74,58,0.3); }
</style></head>
<body><div class="box">
  <h1>Mi Plan</h1>
  <div class="sub">Inicia sesión para continuar</div>
  ''' + (f'<div class="err">{error}</div>' if error else '') + '''
  <form method="post">
    <label>Usuario</label>
    <input type="text" name="user" autocomplete="username" required autofocus>
    <label>Contraseña</label>
    <input type="password" name="password" autocomplete="current-password" required>
    <button type="submit">Entrar</button>
  </form>
</div></body></html>'''

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

# ============================================================
# API · DÍAS
# ============================================================
@app.route('/api/days', methods=['GET'])
@login_required
def get_days():
    try:
        response = supabase.table('days').select('date, data').execute()
        result = {}
        for row in response.data:
            result[row['date']] = row['data']
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/days/<date>', methods=['PUT'])
@login_required
def put_day(date):
    payload = request.get_json() or {}
    try:
        supabase.table('days').upsert({'date': date, 'data': payload}).execute()
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================
# API · MERCADO
# ============================================================
@app.route('/api/mercado', methods=['GET'])
@login_required
def get_mercado():
    try:
        response = supabase.table('mercado').select('*').order('position').order('id').execute()
        return jsonify(response.data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/mercado', methods=['POST'])
@login_required
def add_mercado():
    data = request.get_json() or {}
    item = (data.get('item') or '').strip()
    custom = 1 if data.get('custom') else 0
    if not item:
        return jsonify({'error': 'Item vacío'}), 400
    try:
        max_resp = supabase.table('mercado').select('position').order('position', desc=True).limit(1).execute()
        pos = (max_resp.data[0]['position'] + 1) if max_resp.data else 1
        response = supabase.table('mercado').insert({
            'item': item, 'custom': custom, 'checked': 0, 'position': pos
        }).execute()
        return jsonify(response.data[0])
    except Exception as e:
        if 'duplicate' in str(e).lower() or 'unique' in str(e).lower():
            return jsonify({'error': 'Ya existe'}), 400
        return jsonify({'error': str(e)}), 500

@app.route('/api/mercado/<int:mid>', methods=['PUT'])
@login_required
def update_mercado(mid):
    data = request.get_json() or {}
    try:
        update_data = {}
        if 'checked' in data:
            update_data['checked'] = 1 if data['checked'] else 0
        if not update_data:
            return jsonify({'error': 'Nada que actualizar'}), 400
        supabase.table('mercado').update(update_data).eq('id', mid).execute()
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/mercado/<int:mid>', methods=['DELETE'])
@login_required
def delete_mercado(mid):
    try:
        supabase.table('mercado').delete().eq('id', mid).execute()
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/mercado/reset', methods=['POST'])
@login_required
def reset_mercado():
    try:
        supabase.table('mercado').update({'checked': 0}).neq('id', 0).execute()
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================
# API · NOTAS
# ============================================================
@app.route('/api/notas', methods=['GET'])
@login_required
def get_notas():
    try:
        response = supabase.table('notas').select('content').eq('id', 1).execute()
        content = response.data[0]['content'] if response.data else ''
        return jsonify({'content': content})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/notas', methods=['PUT'])
@login_required
def put_notas():
    data = request.get_json() or {}
    try:
        supabase.table('notas').update({'content': data.get('content', '')}).eq('id', 1).execute()
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================
# API · SETTINGS
# ============================================================
@app.route('/api/settings', methods=['GET'])
@login_required
def get_settings():
    try:
        response = supabase.table('settings').select('key, value').execute()
        return jsonify({row['key']: row['value'] for row in response.data})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/settings', methods=['PUT'])
@login_required
def put_settings():
    data = request.get_json() or {}
    try:
        for k, v in data.items():
            supabase.table('settings').upsert({'key': k, 'value': str(v)}).execute()
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================
# API · TAREAS
# ============================================================
@app.route('/api/tareas', methods=['GET'])
@login_required
def get_tareas():
    try:
        response = supabase.table('tareas').select('*').order('section').order('position').order('id').execute()
        return jsonify(response.data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tareas', methods=['POST'])
@login_required
def add_tarea():
    data = request.get_json() or {}
    section = (data.get('section') or '').strip()
    text = (data.get('text') or '').strip()
    time_hint = (data.get('time_hint') or '').strip()
    if not section or not text:
        return jsonify({'error': 'Falta sección o texto'}), 400
    if section not in ('manana', 'trabajo', 'tarde', 'noche'):
        return jsonify({'error': 'Sección inválida'}), 400
    try:
        max_resp = supabase.table('tareas').select('position').eq('section', section).order('position', desc=True).limit(1).execute()
        pos = (max_resp.data[0]['position'] + 1) if max_resp.data else 1
        response = supabase.table('tareas').insert({
            'section': section,
            'text': text,
            'time_hint': time_hint,
            'position': pos
        }).execute()
        return jsonify(response.data[0])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tareas/<int:tid>', methods=['PUT'])
@login_required
def update_tarea(tid):
    data = request.get_json() or {}
    try:
        upd = {}
        if 'text' in data:
            upd['text'] = (data['text'] or '').strip()
        if 'time_hint' in data:
            upd['time_hint'] = (data['time_hint'] or '').strip()
        if 'section' in data:
            sec = data['section']
            if sec not in ('manana', 'trabajo', 'tarde', 'noche'):
                return jsonify({'error': 'Sección inválida'}), 400
            upd['section'] = sec
        if not upd:
            return jsonify({'error': 'Nada que actualizar'}), 400
        supabase.table('tareas').update(upd).eq('id', tid).execute()
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tareas/<int:tid>', methods=['DELETE'])
@login_required
def delete_tarea(tid):
    try:
        supabase.table('tareas').delete().eq('id', tid).execute()
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================
# HEALTH
# ============================================================
@app.route('/api/health')
def health():
    try:
        supabase.table('days').select('date').limit(1).execute()
        return jsonify({'ok': True, 'db': 'connected'})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)