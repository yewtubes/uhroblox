"""Independent local identity storage. No Roblox credentials or account linking."""
import hashlib
import hmac
import json
import secrets
import sqlite3
import time
from pathlib import Path


class Store:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript('''
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL COLLATE NOCASE UNIQUE,
                    display_name TEXT NOT NULL,
                    password_salt TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    created INTEGER NOT NULL,
                    settings TEXT NOT NULL DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY,
                    csrf TEXT NOT NULL,
                    user_id INTEGER NOT NULL REFERENCES users(id),
                    expires INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS catalog (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    asset_type INTEGER NOT NULL,
                    price INTEGER NOT NULL DEFAULT 0 CHECK(price>=0),
                    creator_id INTEGER NOT NULL REFERENCES users(id),
                    metadata TEXT NOT NULL DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS inventory (
                    user_id INTEGER NOT NULL REFERENCES users(id),
                    asset_id INTEGER NOT NULL REFERENCES catalog(id),
                    acquired INTEGER NOT NULL,
                    PRIMARY KEY(user_id,asset_id)
                );
                CREATE TABLE IF NOT EXISTS wallet (
                    user_id INTEGER PRIMARY KEY REFERENCES users(id),
                    balance INTEGER NOT NULL DEFAULT 0 CHECK(balance>=0)
                );
                CREATE TABLE IF NOT EXISTS friendships (
                    requester INTEGER NOT NULL REFERENCES users(id),
                    recipient INTEGER NOT NULL REFERENCES users(id),
                    state TEXT NOT NULL CHECK(state IN ('pending','accepted')),
                    PRIMARY KEY(requester,recipient),
                    CHECK(requester<>recipient)
                );
                CREATE TABLE IF NOT EXISTS games (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_id INTEGER NOT NULL REFERENCES users(id),
                    name TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    created INTEGER NOT NULL
                );
            ''')

    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        return db

    @staticmethod
    def password_hash(password, salt):
        return hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()

    def create(self, name, password):
        import re
        if not re.fullmatch(r'[A-Za-z0-9_]{3,20}', name):
            raise ValueError('Username must be 3–20 letters, digits, or underscores')
        if not 12 <= len(password) <= 200:
            raise ValueError('Use a separate local password, 12–200 characters')
        salt = secrets.token_hex(16)
        with self.connect() as db:
            cursor = db.execute('INSERT INTO users(name,display_name,password_salt,password_hash,created) VALUES (?,?,?,?,?)',
                                (name, name, salt, self.password_hash(password, salt), int(time.time())))
            return cursor.lastrowid

    def user(self, user_id):
        with self.connect() as db:
            return db.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()

    def login(self, name, password):
        with self.connect() as db:
            user = db.execute('SELECT * FROM users WHERE name=?', (name,)).fetchone()
        # Perform the same KDF when a username does not exist.
        computed = self.password_hash(password, user['password_salt'] if user else '00' * 16)
        if not user or not hmac.compare_digest(computed, user['password_hash']):
            return None
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        with self.connect() as db:
            db.execute('DELETE FROM sessions WHERE expires<?', (int(time.time()),))
            db.execute('INSERT INTO sessions VALUES (?,?,?,?)',
                       (hashlib.sha256(token.encode()).hexdigest(), csrf, user['id'], int(time.time()) + 86400))
        return token, csrf, user

    def session(self, token):
        with self.connect() as db:
            return db.execute('SELECT * FROM sessions WHERE token_hash=? AND expires>?',
                              (hashlib.sha256(token.encode()).hexdigest(), int(time.time()))).fetchone()

    def logout(self, token):
        with self.connect() as db:
            db.execute('DELETE FROM sessions WHERE token_hash=?', (hashlib.sha256(token.encode()).hexdigest(),))

    def update(self, user_id, field, value):
        if field not in ('description', 'display_name', 'settings'):
            raise ValueError('Unknown field')
        if field == 'settings':
            value = json.dumps(value)
        with self.connect() as db:
            db.execute(f'UPDATE users SET {field}=? WHERE id=?', (value, user_id))

    def catalog_search(self, keyword='', limit=30, offset=0):
        with self.connect() as db:
            return db.execute('SELECT c.*,u.name AS creator_name FROM catalog c JOIN users u ON u.id=c.creator_id WHERE instr(lower(c.name),lower(?))>0 ORDER BY c.id LIMIT ? OFFSET ?',
                              (keyword, limit, offset)).fetchall()

    def friend_count(self, user_id):
        with self.connect() as db:
            return db.execute("SELECT count(*) FROM friendships WHERE state='accepted' AND (requester=? OR recipient=?)", (user_id, user_id)).fetchone()[0]

    def friends(self,user_id):
        with self.connect() as db:
            return db.execute("SELECT u.* FROM users u JOIN friendships f ON u.id=CASE WHEN f.requester=? THEN f.recipient ELSE f.requester END WHERE f.state='accepted' AND (f.requester=? OR f.recipient=?) ORDER BY u.id",
                              (user_id,user_id,user_id)).fetchall()

    def balance(self, user_id):
        with self.connect() as db:
            row = db.execute('SELECT balance FROM wallet WHERE user_id=?', (user_id,)).fetchone()
            return row[0] if row else 0

    def settings(self,user_id):
        user=self.user(user_id)
        if not user:
            raise ValueError('Independent user not found')
        return {'accountTheme':'Default','whoCanSeeMyInventory':'AllUsers',**json.loads(user['settings'])}

    def update_settings(self,user_id,changes):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT settings FROM users WHERE id=?',(user_id,)).fetchone()
            settings=json.loads(row['settings'])
            settings.update(changes)
            db.execute('UPDATE users SET settings=? WHERE id=?',(json.dumps(settings),user_id))

    def are_friends(self,first,second):
        with self.connect() as db:
            return db.execute("SELECT 1 FROM friendships WHERE state='accepted' AND ((requester=? AND recipient=?) OR (requester=? AND recipient=?))",
                              (first,second,second,first)).fetchone() is not None

    def can_view_inventory(self,owner,viewer):
        if owner==viewer:
            return True
        policy=self.settings(owner)['whoCanSeeMyInventory']
        return policy=='AllUsers' or (policy=='Friends' and viewer is not None and self.are_friends(owner,viewer))

    def inventory(self,user_id,asset_type,limit,offset,descending=True):
        order='DESC' if descending else 'ASC'
        with self.connect() as db:
            return db.execute(f'SELECT c.*,i.acquired FROM inventory i JOIN catalog c ON c.id=i.asset_id WHERE i.user_id=? AND c.asset_type=? ORDER BY i.acquired {order},c.id {order} LIMIT ? OFFSET ?',
                              (user_id,asset_type,limit,offset)).fetchall()

    def catalog_items(self,ids):
        if not ids:
            return []
        with self.connect() as db:
            return db.execute('SELECT c.*,u.name AS creator_name FROM catalog c JOIN users u ON u.id=c.creator_id WHERE c.id IN ('+','.join('?' for _ in ids)+')',ids).fetchall()

    def create_catalog_record(self,name,asset_type,creator_id,price=0):
        if not isinstance(name,str) or not 1<=len(name.strip())<=100:
            raise ValueError('Asset name must contain 1–100 characters')
        if type(asset_type) is not int or asset_type<=0 or type(price) is not int or price<0:
            raise ValueError('Invalid asset type or price')
        with self.connect() as db:
            if not db.execute('SELECT 1 FROM users WHERE id=?',(creator_id,)).fetchone():
                raise ValueError('Independent creator not found')
            return db.execute('INSERT INTO catalog(name,asset_type,price,creator_id) VALUES (?,?,?,?)',
                              (name.strip(),asset_type,price,creator_id)).lastrowid

    def grant_asset(self,user_id,asset_id):
        with self.connect() as db:
            if not db.execute('SELECT 1 FROM users WHERE id=?',(user_id,)).fetchone():
                raise ValueError('Independent user not found')
            if not db.execute('SELECT 1 FROM catalog WHERE id=?',(asset_id,)).fetchone():
                raise ValueError('Local catalog asset not found')
            return db.execute('INSERT OR IGNORE INTO inventory(user_id,asset_id,acquired) VALUES (?,?,?)',
                              (user_id,asset_id,int(time.time()))).rowcount==1
