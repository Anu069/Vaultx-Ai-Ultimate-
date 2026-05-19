from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, send_file, current_app
from flask_login import login_required, current_user
from app import db
from app.models import PasswordEntry, SecureNote, SecureFile
from app.services.encryption import encrypt_data, decrypt_data, encrypt_file, decrypt_file
from app.services.ai_security import calculate_password_strength
from app.services.password_gen import generate_password, generate_passphrase
from app.services.audit import log_action
from datetime import datetime, timedelta
import os, io, json, secrets, zipfile

vault_bp = Blueprint('vault', __name__)

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'zip', 'csv'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ─── PASSWORD VAULT ───────────────────────────────────────────────────────────

@vault_bp.route('/passwords')
@login_required
def passwords():
    category = request.args.get('category', '')
    search = request.args.get('search', '')
    show_favourites = request.args.get('favourites') == '1'
    
    query = PasswordEntry.query.filter_by(user_id=current_user.id, is_deleted=False)
    
    if category:
        query = query.filter_by(category=category)
    if show_favourites:
        query = query.filter_by(is_favourite=True)
    if search:
        query = query.filter(PasswordEntry.title.ilike(f'%{search}%'))
    
    entries = query.order_by(PasswordEntry.is_favourite.desc(), PasswordEntry.updated_at.desc()).all()
    
    categories = db.session.query(PasswordEntry.category).filter_by(
        user_id=current_user.id, is_deleted=False
    ).distinct().all()
    categories = [c[0] for c in categories if c[0]]
    
    # Decrypt for display (only show masked)
    for e in entries:
        e._decrypted = decrypt_data(e.password_encrypted)
    
    return render_template('vault/passwords.html', 
        entries=entries, categories=categories,
        current_category=category, search=search, show_favourites=show_favourites)

@vault_bp.route('/passwords/add', methods=['GET', 'POST'])
@login_required
def add_password():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        url = request.form.get('url', '').strip()
        notes = request.form.get('notes', '').strip()
        category = request.form.get('category', 'General').strip()
        tags = request.form.get('tags', '').strip()
        expires_days = request.form.get('expires_days', '')
        
        if not title or not password:
            flash('Title and password are required.', 'error')
            return redirect(url_for('vault.add_password'))
        
        strength = calculate_password_strength(password)
        expires_at = None
        if expires_days:
            try:
                expires_at = datetime.utcnow() + timedelta(days=int(expires_days))
            except:
                pass
        
        entry = PasswordEntry(
            user_id=current_user.id,
            title=title,
            username=username,
            password_encrypted=encrypt_data(password),
            url=url,
            notes=notes,
            category=category,
            strength_score=strength['score'],
            tags=tags,
            expires_at=expires_at
        )
        db.session.add(entry)
        db.session.commit()
        log_action(current_user.id, 'PASSWORD_ADDED', f'Added password: {title}')
        flash('Password saved securely.', 'success')
        return redirect(url_for('vault.passwords'))
    
    return render_template('vault/add_password.html')

@vault_bp.route('/passwords/<int:entry_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_password(entry_id):
    entry = PasswordEntry.query.filter_by(id=entry_id, user_id=current_user.id, is_deleted=False).first_or_404()
    
    if request.method == 'POST':
        entry.title = request.form.get('title', entry.title).strip()
        entry.username = request.form.get('username', '').strip()
        new_pass = request.form.get('password', '')
        entry.url = request.form.get('url', '').strip()
        entry.notes = request.form.get('notes', '').strip()
        entry.category = request.form.get('category', 'General').strip()
        entry.tags = request.form.get('tags', '').strip()
        
        if new_pass:
            strength = calculate_password_strength(new_pass)
            entry.password_encrypted = encrypt_data(new_pass)
            entry.strength_score = strength['score']
        
        entry.updated_at = datetime.utcnow()
        db.session.commit()
        log_action(current_user.id, 'PASSWORD_UPDATED', f'Updated password: {entry.title}')
        flash('Password updated.', 'success')
        return redirect(url_for('vault.passwords'))
    
    entry._decrypted = decrypt_data(entry.password_encrypted)
    return render_template('vault/edit_password.html', entry=entry)

@vault_bp.route('/passwords/<int:entry_id>/delete', methods=['POST'])
@login_required
def delete_password(entry_id):
    entry = PasswordEntry.query.filter_by(id=entry_id, user_id=current_user.id).first_or_404()
    entry.is_deleted = True
    entry.deleted_at = datetime.utcnow()
    db.session.commit()
    log_action(current_user.id, 'PASSWORD_DELETED', f'Deleted password: {entry.title}')
    return jsonify({'success': True})

@vault_bp.route('/passwords/<int:entry_id>/reveal', methods=['POST'])
@login_required
def reveal_password(entry_id):
    entry = PasswordEntry.query.filter_by(id=entry_id, user_id=current_user.id, is_deleted=False).first_or_404()
    entry.last_used = datetime.utcnow()
    db.session.commit()
    log_action(current_user.id, 'PASSWORD_REVEALED', f'Revealed: {entry.title}', 'medium')
    return jsonify({'password': decrypt_data(entry.password_encrypted)})

@vault_bp.route('/passwords/<int:entry_id>/favourite', methods=['POST'])
@login_required
def toggle_favourite(entry_id):
    entry = PasswordEntry.query.filter_by(id=entry_id, user_id=current_user.id).first_or_404()
    entry.is_favourite = not entry.is_favourite
    db.session.commit()
    return jsonify({'success': True, 'favourite': entry.is_favourite})

@vault_bp.route('/passwords/generate', methods=['POST'])
@login_required
def gen_password():
    data = request.get_json() or {}
    length = min(64, max(8, int(data.get('length', 16))))
    mode = data.get('mode', 'standard')
    
    if mode == 'passphrase':
        pwd = generate_passphrase(int(data.get('words', 4)))
    else:
        pwd = generate_password(
            length=length,
            use_upper=data.get('upper', True),
            use_lower=data.get('lower', True),
            use_digits=data.get('digits', True),
            use_symbols=data.get('symbols', True),
            exclude_ambiguous=data.get('no_ambiguous', False),
            memorable=data.get('memorable', False)
        )
    
    strength = calculate_password_strength(pwd)
    return jsonify({'password': pwd, 'strength': strength})

@vault_bp.route('/passwords/strength', methods=['POST'])
@login_required
def check_strength():
    data = request.get_json() or {}
    password = data.get('password', '')
    result = calculate_password_strength(password)
    return jsonify(result)

# ─── SECURE NOTES ─────────────────────────────────────────────────────────────

@vault_bp.route('/notes')
@login_required
def notes():
    category = request.args.get('category', '')
    search = request.args.get('search', '')
    query = SecureNote.query.filter_by(user_id=current_user.id, is_deleted=False)
    if category:
        query = query.filter_by(category=category)
    if search:
        query = query.filter(SecureNote.title.ilike(f'%{search}%'))
    all_notes = query.order_by(SecureNote.is_pinned.desc(), SecureNote.updated_at.desc()).all()
    categories = db.session.query(SecureNote.category).filter_by(user_id=current_user.id, is_deleted=False).distinct().all()
    categories = [c[0] for c in categories if c[0]]
    return render_template('vault/notes.html', notes=all_notes, categories=categories, current_category=category, search=search)

@vault_bp.route('/notes/add', methods=['GET', 'POST'])
@login_required
def add_note():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '')
        category = request.form.get('category', 'General')
        if not title:
            flash('Title is required.', 'error')
            return redirect(url_for('vault.add_note'))
        note = SecureNote(
            user_id=current_user.id,
            title=title,
            content_encrypted=encrypt_data(content),
            category=category
        )
        db.session.add(note)
        db.session.commit()
        log_action(current_user.id, 'NOTE_ADDED', f'Added note: {title}')
        flash('Note saved securely.', 'success')
        return redirect(url_for('vault.notes'))
    return render_template('vault/add_note.html')

@vault_bp.route('/notes/<int:note_id>', methods=['GET'])
@login_required
def view_note(note_id):
    note = SecureNote.query.filter_by(id=note_id, user_id=current_user.id, is_deleted=False).first_or_404()
    note._content = decrypt_data(note.content_encrypted)
    log_action(current_user.id, 'NOTE_VIEWED', f'Viewed note: {note.title}')
    return render_template('vault/view_note.html', note=note)

@vault_bp.route('/notes/<int:note_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_note(note_id):
    note = SecureNote.query.filter_by(id=note_id, user_id=current_user.id, is_deleted=False).first_or_404()
    if request.method == 'POST':
        note.title = request.form.get('title', note.title).strip()
        note.content_encrypted = encrypt_data(request.form.get('content', ''))
        note.category = request.form.get('category', 'General')
        note.updated_at = datetime.utcnow()
        db.session.commit()
        log_action(current_user.id, 'NOTE_UPDATED', f'Updated note: {note.title}')
        flash('Note updated.', 'success')
        return redirect(url_for('vault.notes'))
    note._content = decrypt_data(note.content_encrypted)
    return render_template('vault/edit_note.html', note=note)

@vault_bp.route('/notes/<int:note_id>/delete', methods=['POST'])
@login_required
def delete_note(note_id):
    note = SecureNote.query.filter_by(id=note_id, user_id=current_user.id).first_or_404()
    note.is_deleted = True
    note.deleted_at = datetime.utcnow()
    db.session.commit()
    return jsonify({'success': True})

@vault_bp.route('/notes/<int:note_id>/pin', methods=['POST'])
@login_required
def pin_note(note_id):
    note = SecureNote.query.filter_by(id=note_id, user_id=current_user.id).first_or_404()
    note.is_pinned = not note.is_pinned
    db.session.commit()
    return jsonify({'success': True, 'pinned': note.is_pinned})

# ─── SECURE FILE VAULT ────────────────────────────────────────────────────────

@vault_bp.route('/files')
@login_required
def files():
    all_files = SecureFile.query.filter_by(user_id=current_user.id, is_deleted=False)\
        .order_by(SecureFile.created_at.desc()).all()
    return render_template('vault/files.html', files=all_files)

@vault_bp.route('/files/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'success': False, 'message': 'File type not allowed'}), 400
    
    file_data = file.read()
    if len(file_data) > 16 * 1024 * 1024:
        return jsonify({'success': False, 'message': 'File too large (max 16MB)'}), 400
    
    encrypted_data = encrypt_file(file_data)
    stored_name = f"{secrets.token_hex(16)}.enc"
    
    upload_dir = current_app.config['UPLOAD_FOLDER']
    os.makedirs(upload_dir, exist_ok=True)
    
    file_path = os.path.join(upload_dir, stored_name)
    with open(file_path, 'wb') as f:
        f.write(encrypted_data)
    
    secure_file = SecureFile(
        user_id=current_user.id,
        original_name=file.filename,
        stored_name=stored_name,
        file_size=len(file_data),
        file_type=file.content_type or 'application/octet-stream',
        category=request.form.get('category', 'General')
    )
    db.session.add(secure_file)
    db.session.commit()
    log_action(current_user.id, 'FILE_UPLOADED', f'Uploaded: {file.filename}')
    return jsonify({'success': True, 'message': f'File "{file.filename}" encrypted and stored.'})

@vault_bp.route('/files/<int:file_id>/download')
@login_required
def download_file(file_id):
    secure_file = SecureFile.query.filter_by(id=file_id, user_id=current_user.id, is_deleted=False).first_or_404()
    
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], secure_file.stored_name)
    if not os.path.exists(file_path):
        flash('File not found on server.', 'error')
        return redirect(url_for('vault.files'))
    
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    
    decrypted_data = decrypt_file(encrypted_data)
    log_action(current_user.id, 'FILE_DOWNLOADED', f'Downloaded: {secure_file.original_name}', 'medium')
    
    return send_file(
        io.BytesIO(decrypted_data),
        download_name=secure_file.original_name,
        as_attachment=True,
        mimetype=secure_file.file_type
    )

@vault_bp.route('/files/<int:file_id>/delete', methods=['POST'])
@login_required
def delete_file(file_id):
    secure_file = SecureFile.query.filter_by(id=file_id, user_id=current_user.id).first_or_404()
    secure_file.is_deleted = True
    secure_file.deleted_at = datetime.utcnow()
    db.session.commit()
    return jsonify({'success': True})

# ─── RECYCLE BIN ──────────────────────────────────────────────────────────────

@vault_bp.route('/recycle-bin')
@login_required
def recycle_bin():
    deleted_passwords = PasswordEntry.query.filter_by(user_id=current_user.id, is_deleted=True).all()
    deleted_notes = SecureNote.query.filter_by(user_id=current_user.id, is_deleted=True).all()
    deleted_files = SecureFile.query.filter_by(user_id=current_user.id, is_deleted=True).all()
    return render_template('vault/recycle_bin.html', 
        passwords=deleted_passwords, notes=deleted_notes, files=deleted_files)

@vault_bp.route('/restore/<string:item_type>/<int:item_id>', methods=['POST'])
@login_required
def restore_item(item_type, item_id):
    if item_type == 'password':
        item = PasswordEntry.query.filter_by(id=item_id, user_id=current_user.id).first_or_404()
    elif item_type == 'note':
        item = SecureNote.query.filter_by(id=item_id, user_id=current_user.id).first_or_404()
    elif item_type == 'file':
        item = SecureFile.query.filter_by(id=item_id, user_id=current_user.id).first_or_404()
    else:
        return jsonify({'success': False}), 400
    
    item.is_deleted = False
    item.deleted_at = None
    db.session.commit()
    log_action(current_user.id, 'ITEM_RESTORED', f'Restored {item_type}')
    return jsonify({'success': True})

@vault_bp.route('/permanent-delete/<string:item_type>/<int:item_id>', methods=['POST'])
@login_required
def permanent_delete(item_type, item_id):
    if item_type == 'password':
        item = PasswordEntry.query.filter_by(id=item_id, user_id=current_user.id).first_or_404()
    elif item_type == 'note':
        item = SecureNote.query.filter_by(id=item_id, user_id=current_user.id).first_or_404()
    elif item_type == 'file':
        item = SecureFile.query.filter_by(id=item_id, user_id=current_user.id).first_or_404()
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], item.stored_name)
        if os.path.exists(file_path):
            os.remove(file_path)
    else:
        return jsonify({'success': False}), 400
    
    db.session.delete(item)
    db.session.commit()
    log_action(current_user.id, 'ITEM_PERMANENTLY_DELETED', f'Permanently deleted {item_type}', 'medium')
    return jsonify({'success': True})

# ─── BACKUP ───────────────────────────────────────────────────────────────────

@vault_bp.route('/backup/export', methods=['POST'])
@login_required
def export_backup():
    from app.services.encryption import create_encrypted_backup
    backup_password = request.form.get('backup_password', 'default-backup-key')
    
    passwords = PasswordEntry.query.filter_by(user_id=current_user.id, is_deleted=False).all()
    notes = SecureNote.query.filter_by(user_id=current_user.id, is_deleted=False).all()
    
    backup_data = {
        'version': '1.0',
        'exported_at': datetime.utcnow().isoformat(),
        'username': current_user.username,
        'passwords': [{
            'title': p.title,
            'username': p.username,
            'password': decrypt_data(p.password_encrypted),
            'url': p.url,
            'notes': p.notes,
            'category': p.category
        } for p in passwords],
        'notes': [{
            'title': n.title,
            'content': decrypt_data(n.content_encrypted),
            'category': n.category
        } for n in notes]
    }
    
    backup_json = json.dumps(backup_data, indent=2)
    encrypted_backup = create_encrypted_backup(backup_json, backup_password)
    
    log_action(current_user.id, 'BACKUP_EXPORTED', 'Encrypted backup exported', 'medium')
    
    return send_file(
        io.BytesIO(encrypted_backup),
        download_name=f'vaultx-backup-{datetime.utcnow().strftime("%Y%m%d")}.vxb',
        as_attachment=True,
        mimetype='application/octet-stream'
    )
