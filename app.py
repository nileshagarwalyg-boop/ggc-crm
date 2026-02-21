#!/usr/bin/env python3
"""
GGC Real Estate CRM — Flask Backend (Supabase)
================================================
Run: python3 app.py
Open: http://localhost:5001
"""

import os, json, secrets, base64
from datetime import datetime
from functools import wraps

# Flask import with path fix (local dev only)
import sys
local_site = os.path.expanduser('~/Library/Python/3.9/lib/python/site-packages')
if os.path.exists(local_site):
    sys.path.insert(0, local_site)

from flask import Flask, request, jsonify, send_from_directory
from dotenv import load_dotenv
from supabase import create_client
import jwt as pyjwt

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SUPABASE_URL = os.environ['SUPABASE_URL']
SUPABASE_ANON_KEY = os.environ['SUPABASE_ANON_KEY']
SUPABASE_SERVICE_ROLE_KEY = os.environ['SUPABASE_SERVICE_ROLE_KEY']
SUPABASE_SECRET_KEY = os.environ.get('SUPABASE_SECRET_KEY', '')

# Supabase client (uses service_role key — bypasses RLS)
sb = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

app = Flask(__name__, static_folder=BASE_DIR)
app.secret_key = secrets.token_hex(32)

# All available permissions (granular: feature.action)
ALL_PERMISSIONS = 'rates.view,rates.edit,users.view,users.add,users.edit,users.delete,customers.view,customers.add,customers.edit,customers.delete,bookings.view,bookings.add,bookings.edit,bookings.delete,channel_partners.view,channel_partners.add,channel_partners.edit,channel_partners.delete,inventory.view'

# ─────────────────────────────────────────────
# HELPER: Generate next customer UID
# ─────────────────────────────────────────────
def next_cust_uid():
    """Generate next customer UID like GGC-0001, GGC-0002, etc."""
    result = sb.table('customers').select('cust_uid').neq('cust_uid', '').not_.is_('cust_uid', 'null').order('id', desc=True).limit(1).execute()
    next_num = 1
    if result.data and result.data[0].get('cust_uid'):
        try:
            next_num = int(result.data[0]['cust_uid'].split('-')[1]) + 1
        except:
            count_res = sb.table('customers').select('id', count='exact').execute()
            next_num = (count_res.count or 0) + 1
    return f"GGC-{next_num:04d}"

# ─────────────────────────────────────────────
# AUTH MIDDLEWARE (Supabase JWT)
# ─────────────────────────────────────────────
def get_current_user():
    """Extract and validate user from Authorization header (Supabase JWT)."""
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return None
    token = auth_header[7:]
    try:
        # Decode JWT — Supabase uses HS256
        # Try verification with secret key first, fallback to unverified decode
        try:
            payload = pyjwt.decode(token, SUPABASE_SECRET_KEY, algorithms=['HS256'], audience='authenticated')
        except:
            # Fallback: decode without verification (trust Supabase issued it)
            payload = pyjwt.decode(token, options={"verify_signature": False})

        user_id = payload.get('sub')
        if not user_id:
            return None

        # Look up profile
        result = sb.table('profiles').select('*').eq('id', user_id).execute()
        if result.data and len(result.data) > 0:
            return result.data[0]
        return None
    except Exception as e:
        print(f"JWT decode error: {e}")
        return None

def permission_required(*perms):
    """Check if user has ANY of the required permissions. Superadmin bypasses all."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = get_current_user()
            if not user:
                return jsonify({'error': 'Unauthorized'}), 401
            # Superadmin bypasses all permission checks
            if user['role'] == 'superadmin':
                return f(*args, **kwargs)
            # Check if user has any of the required permissions
            user_perms = set(p.strip() for p in (user.get('permissions') or '').split(',') if p.strip())
            if not user_perms.intersection(perms):
                return jsonify({'error': 'Access denied. You don\'t have permission for this.'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

# ─────────────────────────────────────────────
# ROUTES — Static files
# ─────────────────────────────────────────────
@app.route('/')
def index():
    return send_from_directory(BASE_DIR, 'index.html')

@app.route('/<path:filename>')
def static_files(filename):
    return send_from_directory(BASE_DIR, filename)

# ─────────────────────────────────────────────
# AUTH — Profile endpoint (replaces /api/login)
# ─────────────────────────────────────────────
@app.route('/api/me', methods=['GET'])
def get_me():
    """Return current user's profile. Called by frontend after Supabase Auth login."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({
        'id': user['id'],
        'name': user.get('name', ''),
        'role': user.get('role', ''),
        'permissions': user.get('permissions', ''),
        'username': user.get('username', '')
    })

# ─────────────────────────────────────────────
# RATES (public read, rates permission write)
# ─────────────────────────────────────────────
@app.route('/api/rates', methods=['GET'])
def get_rates():
    result = sb.table('admin_rates').select('*').execute()
    return jsonify({r['building']: {'base': r['base_rate'], 'updated': r['updated_at']} for r in result.data})

@app.route('/api/rates', methods=['PUT'])
@permission_required('rates.edit')
def update_rates():
    data = request.get_json()
    now = datetime.now().isoformat()
    for bld, info in data.items():
        sb.table('admin_rates').update({
            'base_rate': info.get('base', 0),
            'updated_at': now
        }).eq('building', bld).execute()
    return jsonify({'ok': True})

# ─────────────────────────────────────────────
# USER MANAGEMENT (superadmin / users permission)
# ─────────────────────────────────────────────
@app.route('/api/users', methods=['GET'])
@permission_required('users.view')
def list_users():
    result = sb.table('profiles').select('id, username, name, role, permissions').order('created_at').execute()
    return jsonify(result.data)

@app.route('/api/users', methods=['POST'])
@permission_required('users.add')
def create_user():
    d = request.get_json()
    username = d.get('username', '').strip()
    password = d.get('password', '').strip()
    name = d.get('name', '').strip()
    role = d.get('role', '').strip()
    permissions = d.get('permissions', '').strip()

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400
    if role not in ('superadmin', 'sales', 'crm', 'custom'):
        return jsonify({'error': 'Invalid role'}), 400
    if role == 'superadmin':
        permissions = ALL_PERMISSIONS

    email = f"{username}@ggc.local"
    try:
        # Create user in Supabase Auth
        auth_res = sb.auth.admin.create_user({
            'email': email,
            'password': password,
            'email_confirm': True,
            'user_metadata': {'username': username}
        })
        user_id = str(auth_res.user.id)

        # Create profile
        sb.table('profiles').insert({
            'id': user_id,
            'username': username,
            'name': name,
            'role': role,
            'permissions': permissions
        }).execute()

        return jsonify({'id': user_id, 'ok': True})
    except Exception as e:
        err_str = str(e)
        if 'already' in err_str.lower() or 'duplicate' in err_str.lower():
            return jsonify({'error': 'Username already exists'}), 409
        return jsonify({'error': f'Failed to create user: {err_str}'}), 500

@app.route('/api/users/<uid>', methods=['PUT'])
@permission_required('users.edit')
def update_user(uid):
    d = request.get_json()

    # Check user exists
    result = sb.table('profiles').select('*').eq('id', uid).execute()
    if not result.data:
        return jsonify({'error': 'User not found'}), 404

    user = result.data[0]
    updates = {}

    if 'name' in d:
        updates['name'] = d['name'].strip()
    if 'role' in d:
        role = d['role'].strip()
        if role not in ('superadmin', 'sales', 'crm', 'custom'):
            return jsonify({'error': 'Invalid role'}), 400
        updates['role'] = role
        if role == 'superadmin':
            updates['permissions'] = ALL_PERMISSIONS
    if 'permissions' in d and d.get('role', user['role']) != 'superadmin':
        updates['permissions'] = d['permissions'].strip()
    if 'password' in d and d['password'].strip():
        # Update password in Supabase Auth
        try:
            sb.auth.admin.update_user_by_id(uid, {'password': d['password'].strip()})
        except Exception as e:
            return jsonify({'error': f'Failed to update password: {str(e)}'}), 500

    if updates:
        sb.table('profiles').update(updates).eq('id', uid).execute()

    return jsonify({'ok': True})

@app.route('/api/users/<uid>', methods=['DELETE'])
@permission_required('users.delete')
def delete_user(uid):
    current = get_current_user()
    if uid == current['id']:
        return jsonify({'error': 'Cannot delete your own account'}), 400

    # Check user exists
    result = sb.table('profiles').select('id').eq('id', uid).execute()
    if not result.data:
        return jsonify({'error': 'User not found'}), 404

    try:
        # Delete from Supabase Auth (cascade deletes profile)
        sb.auth.admin.delete_user(uid)
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': f'Delete failed: {str(e)}'}), 500

# ─────────────────────────────────────────────
# CUSTOMERS
# ─────────────────────────────────────────────
@app.route('/api/customers', methods=['GET'])
@permission_required('customers.view')
def list_customers():
    q = request.args.get('q', '').strip()
    if q:
        like = f'%{q}%'
        result = sb.table('customers').select('*').or_(f'name.ilike.{like},phone.ilike.{like},email.ilike.{like}').order('name').execute()
    else:
        result = sb.table('customers').select('*').order('id', desc=True).execute()
    return jsonify(result.data)

@app.route('/api/customers', methods=['POST'])
@permission_required('customers.add')
def create_customer():
    d = request.get_json()

    # ── Duplicate detection ──
    dupes = []
    phone = d.get('phone','').strip()
    email = d.get('email','').strip()
    pan   = d.get('pan','').strip().upper()
    aadhar= d.get('aadhar','').strip().replace(' ','')

    if phone:
        res = sb.table('customers').select('id,name').eq('phone', phone).execute()
        if res.data: dupes.append(f"Phone '{phone}' already exists -> {res.data[0]['name']} (ID #{res.data[0]['id']})")
    if email:
        res = sb.table('customers').select('id,name').eq('email', email).execute()
        if res.data: dupes.append(f"Email '{email}' already exists -> {res.data[0]['name']} (ID #{res.data[0]['id']})")
    if pan:
        res = sb.table('customers').select('id,name').eq('pan', pan).execute()
        if res.data: dupes.append(f"PAN '{pan}' already exists -> {res.data[0]['name']} (ID #{res.data[0]['id']})")
    if aadhar and len(aadhar) >= 10:
        res = sb.table('customers').select('id,name').eq('aadhar', aadhar).execute()
        if res.data: dupes.append(f"Aadhar already exists -> {res.data[0]['name']} (ID #{res.data[0]['id']})")

    if dupes:
        return jsonify({'error': 'Duplicate found', 'duplicates': dupes}), 409

    now = datetime.now().isoformat()
    uid = next_cust_uid()
    result = sb.table('customers').insert({
        'cust_uid': uid,
        'name': d.get('name',''),
        'phone': phone,
        'email': email,
        'pan': pan,
        'aadhar': d.get('aadhar',''),
        'dob': d.get('dob',''),
        'address': d.get('address',''),
        'company': d.get('company',''),
        'profession': d.get('profession',''),
        'status': d.get('status','Resident'),
        'notes': d.get('notes',''),
        'created_at': now
    }).execute()

    cid = result.data[0]['id'] if result.data else None
    return jsonify({'id': cid, 'cust_uid': uid, 'ok': True})

@app.route('/api/customers/<int:cid>', methods=['GET'])
@permission_required('customers.view')
def get_customer(cid):
    result = sb.table('customers').select('*').eq('id', cid).execute()
    if result.data:
        return jsonify(result.data[0])
    return jsonify({'error': 'Not found'}), 404

@app.route('/api/customers/<int:cid>', methods=['PUT'])
@permission_required('customers.edit')
def update_customer(cid):
    d = request.get_json()

    # ── Duplicate detection (skip own record) ──
    dupes = []
    phone = d.get('phone','').strip() if 'phone' in d else None
    email = d.get('email','').strip() if 'email' in d else None
    pan   = d.get('pan','').strip().upper() if 'pan' in d else None
    aadhar= d.get('aadhar','').strip().replace(' ','') if 'aadhar' in d else None

    if phone:
        res = sb.table('customers').select('id,name').eq('phone', phone).neq('id', cid).execute()
        if res.data: dupes.append(f"Phone '{phone}' already used by {res.data[0]['name']} (ID #{res.data[0]['id']})")
    if email:
        res = sb.table('customers').select('id,name').eq('email', email).neq('id', cid).execute()
        if res.data: dupes.append(f"Email '{email}' already used by {res.data[0]['name']} (ID #{res.data[0]['id']})")
    if pan:
        res = sb.table('customers').select('id,name').eq('pan', pan).neq('id', cid).execute()
        if res.data: dupes.append(f"PAN '{pan}' already used by {res.data[0]['name']} (ID #{res.data[0]['id']})")
    if aadhar and len(aadhar) >= 10:
        res = sb.table('customers').select('id,name').eq('aadhar', aadhar).neq('id', cid).execute()
        if res.data: dupes.append(f"Aadhar already used by {res.data[0]['name']} (ID #{res.data[0]['id']})")

    if dupes:
        return jsonify({'error': 'Duplicate found', 'duplicates': dupes}), 409

    fields = ['name','phone','email','pan','aadhar','dob','address','company','profession','status','notes']
    updates = {f: d[f] for f in fields if f in d}
    if updates:
        sb.table('customers').update(updates).eq('id', cid).execute()
    return jsonify({'ok': True})

@app.route('/api/customers/<int:cid>', methods=['DELETE'])
@permission_required('customers.delete')
def delete_customer(cid):
    try:
        # Check if customer has active bookings
        bk = sb.table('bookings').select('id').eq('customer_id', cid).eq('status', 'booked').execute()
        if bk.data:
            return jsonify({'error': 'Cannot delete — customer has active bookings. Cancel bookings first.'}), 400
        # Nullify customer_id in any old/cancelled bookings
        sb.table('bookings').update({'customer_id': None}).eq('customer_id', cid).execute()
        sb.table('customers').delete().eq('id', cid).execute()
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': f'Delete failed: {str(e)}'}), 500

# ─────────────────────────────────────────────
# CHANNEL PARTNERS
# ─────────────────────────────────────────────
@app.route('/api/cp', methods=['GET'])
@permission_required('channel_partners.view')
def list_cp():
    result = sb.table('channel_partners').select('*, fos_persons(*)').order('id', desc=True).execute()
    data = result.data
    for cp in data:
        cp['fos'] = cp.pop('fos_persons', []) or []
    return jsonify(data)

@app.route('/api/cp', methods=['POST'])
@permission_required('channel_partners.add')
def create_cp():
    d = request.get_json()

    # ── Duplicate detection ──
    dupes = []
    firm = d.get('firm_name','').strip()
    phone = d.get('phone','').strip()
    rera = d.get('rera_no','').strip()

    if firm:
        res = sb.table('channel_partners').select('id,firm_name').ilike('firm_name', firm).execute()
        if res.data: dupes.append(f"Firm '{firm}' already exists (ID #{res.data[0]['id']})")
    if phone:
        res = sb.table('channel_partners').select('id,firm_name').eq('phone', phone).execute()
        if res.data: dupes.append(f"Phone '{phone}' already used by {res.data[0]['firm_name']} (ID #{res.data[0]['id']})")
    if rera:
        res = sb.table('channel_partners').select('id,firm_name').eq('rera_no', rera).execute()
        if res.data: dupes.append(f"RERA '{rera}' already used by {res.data[0]['firm_name']} (ID #{res.data[0]['id']})")

    if dupes:
        return jsonify({'error': 'Duplicate found', 'duplicates': dupes}), 409

    now = datetime.now().isoformat()
    result = sb.table('channel_partners').insert({
        'firm_name': firm,
        'contact_person': d.get('contact_person',''),
        'phone': phone,
        'email': d.get('email',''),
        'rera_no': rera,
        'address': d.get('address',''),
        'created_at': now
    }).execute()

    cpid = result.data[0]['id'] if result.data else None
    return jsonify({'id': cpid, 'ok': True})

@app.route('/api/cp/<int:cpid>', methods=['PUT'])
@permission_required('channel_partners.edit')
def update_cp(cpid):
    d = request.get_json()
    fields = ['firm_name','contact_person','phone','email','rera_no','address']
    updates = {f: d[f] for f in fields if f in d}
    if updates:
        sb.table('channel_partners').update(updates).eq('id', cpid).execute()
    return jsonify({'ok': True})

@app.route('/api/cp/<int:cpid>', methods=['DELETE'])
@permission_required('channel_partners.delete')
def delete_cp(cpid):
    try:
        # Check if CP has active bookings
        bk = sb.table('bookings').select('id').eq('cp_id', cpid).eq('status', 'booked').execute()
        if bk.data:
            return jsonify({'error': 'Cannot delete — CP has active bookings. Cancel bookings first.'}), 400
        # Nullify cp_id in any old bookings referencing this CP
        sb.table('bookings').update({'cp_id': None}).eq('cp_id', cpid).execute()
        # Delete associated FOS persons (CASCADE should handle, but be explicit)
        sb.table('fos_persons').delete().eq('cp_id', cpid).execute()
        sb.table('channel_partners').delete().eq('id', cpid).execute()
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': f'Delete failed: {str(e)}'}), 500

@app.route('/api/cp/<int:cpid>/photo', methods=['POST'])
@permission_required('channel_partners.edit')
def upload_cp_photo(cpid):
    """Upload photo for a channel partner to Supabase Storage."""
    filename = f"cp_{cpid}_{int(datetime.now().timestamp())}.jpg"

    if request.is_json:
        data = request.get_json()
        img_data = data.get('photo', '')
        if ',' in img_data:
            img_data = img_data.split(',', 1)[1]
        file_bytes = base64.b64decode(img_data)
    else:
        file = request.files.get('photo')
        if not file:
            return jsonify({'error': 'No photo provided'}), 400
        file_bytes = file.read()

    try:
        # Upload to Supabase Storage
        sb.storage.from_('uploads').upload(
            filename, file_bytes,
            file_options={"content-type": "image/jpeg", "upsert": "true"}
        )
        # Get public URL
        public_url = sb.storage.from_('uploads').get_public_url(filename)
        # Save URL to DB
        sb.table('channel_partners').update({'photo': public_url}).eq('id', cpid).execute()
        return jsonify({'ok': True, 'photo': public_url})
    except Exception as e:
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500

@app.route('/api/cp/<int:cpid>/fos', methods=['POST'])
@permission_required('channel_partners.add')
def add_fos(cpid):
    d = request.get_json()
    result = sb.table('fos_persons').insert({
        'cp_id': cpid,
        'name': d.get('name',''),
        'phone': d.get('phone',''),
        'email': d.get('email','')
    }).execute()
    fid = result.data[0]['id'] if result.data else None
    return jsonify({'id': fid, 'ok': True})

@app.route('/api/cp/<int:cpid>/fos/<int:fid>', methods=['DELETE'])
@permission_required('channel_partners.delete')
def delete_fos(cpid, fid):
    sb.table('fos_persons').delete().eq('id', fid).eq('cp_id', cpid).execute()
    return jsonify({'ok': True})

# ─────────────────────────────────────────────
# SALES STAFF
# ─────────────────────────────────────────────
@app.route('/api/sales-staff', methods=['GET'])
@permission_required('bookings.view')
def list_sales_staff():
    result = sb.table('sales_staff').select('*').eq('active', 1).order('name').execute()
    return jsonify(result.data)

@app.route('/api/sales-staff', methods=['POST'])
@permission_required('users.add')
def add_sales_staff():
    d = request.get_json()
    now = datetime.now().isoformat()
    result = sb.table('sales_staff').insert({
        'name': d.get('name',''),
        'phone': d.get('phone',''),
        'email': d.get('email',''),
        'active': 1,
        'created_at': now
    }).execute()
    sid = result.data[0]['id'] if result.data else None
    return jsonify({'id': sid, 'ok': True})

@app.route('/api/sales-staff/<int:sid>', methods=['PUT'])
@permission_required('users.edit')
def update_sales_staff(sid):
    d = request.get_json()
    updates = {}
    for f in ['name','phone','email','active']:
        if f in d:
            updates[f] = d[f]
    if updates:
        sb.table('sales_staff').update(updates).eq('id', sid).execute()
    return jsonify({'ok': True})

@app.route('/api/sales-staff/<int:sid>', methods=['DELETE'])
@permission_required('users.delete')
def delete_sales_staff(sid):
    sb.table('sales_staff').delete().eq('id', sid).execute()
    return jsonify({'ok': True})

# ─────────────────────────────────────────────
# BOOKINGS
# ─────────────────────────────────────────────
@app.route('/api/bookings', methods=['GET'])
@permission_required('bookings.view')
def list_bookings():
    result = sb.table('bookings').select(
        '*, customers!customer_id(name, phone, cust_uid), channel_partners!cp_id(firm_name)'
    ).neq('status', 'cancelled').order('id', desc=True).execute()

    # Flatten the nested structure to match current API response format
    rows = []
    for b in result.data:
        cust = b.pop('customers', None) or {}
        cp = b.pop('channel_partners', None) or {}
        b['customer_name'] = cust.get('name')
        b['customer_phone'] = cust.get('phone')
        b['customer_uid'] = cust.get('cust_uid')
        b['cp_name'] = cp.get('firm_name')
        rows.append(b)
    return jsonify(rows)

@app.route('/api/bookings', methods=['POST'])
@permission_required('bookings.add')
def create_booking():
    d = request.get_json()

    # ── Duplicate detection: same flat cannot be booked twice ──
    building = d.get('building','')
    flat_no = d.get('flat_no')
    if building and flat_no:
        existing = sb.table('bookings').select('id, customer_id').eq('building', building).eq('flat_no', flat_no).eq('status', 'booked').execute()
        if existing.data:
            eid = existing.data[0]['id']
            # Get buyer name
            buyer = 'Unknown'
            cid = existing.data[0].get('customer_id')
            if cid:
                cr = sb.table('customers').select('name').eq('id', cid).execute()
                if cr.data: buyer = cr.data[0]['name']
            return jsonify({
                'error': 'Duplicate found',
                'duplicates': [f"Flat {flat_no} in {building} is already booked (Booking #{eid}, Buyer: {buyer})"]
            }), 409

    now = datetime.now().isoformat()
    insert_data = {
        'customer_id': d.get('customer_id'),
        'customer2_id': d.get('customer2_id'),
        'building': building,
        'flat_no': flat_no,
        'flat_type': d.get('flat_type'),
        'floor': d.get('floor'),
        'carpet_area': d.get('carpet_area'),
        'base_rate': d.get('base_rate'),
        'total_package': d.get('total_package'),
        'discount': d.get('discount', 0),
        'booking_amount': d.get('booking_amount'),
        'payment_mode': d.get('payment_mode'),
        'payment_ref': d.get('payment_ref'),
        'cp_id': d.get('cp_id'),
        'sales_person': d.get('sales_person'),
        'remarks': d.get('remarks'),
        'status': d.get('status', 'booked'),
        'form_data': d.get('form_data', {}),
        'created_at': now,
        'updated_at': now
    }
    result = sb.table('bookings').insert(insert_data).execute()
    bid = result.data[0]['id'] if result.data else None
    return jsonify({'id': bid, 'ok': True})

@app.route('/api/bookings/<int:bid>', methods=['GET'])
@permission_required('bookings.view')
def get_booking(bid):
    result = sb.table('bookings').select(
        '*, customers!customer_id(name, phone), channel_partners!cp_id(firm_name)'
    ).eq('id', bid).execute()

    if result.data:
        b = result.data[0]
        cust = b.pop('customers', None) or {}
        cp = b.pop('channel_partners', None) or {}
        b['customer_name'] = cust.get('name')
        b['customer_phone'] = cust.get('phone')
        b['cp_name'] = cp.get('firm_name')
        # form_data is already a dict (JSONB), no need for json.loads
        return jsonify(b)
    return jsonify({'error': 'Not found'}), 404

@app.route('/api/bookings/<int:bid>', methods=['PUT'])
@permission_required('bookings.edit')
def update_booking(bid):
    d = request.get_json()

    # ── Duplicate detection: same flat cannot be booked by another booking ──
    building = d.get('building','')
    flat_no = d.get('flat_no')
    new_status = d.get('status')
    if building and flat_no and new_status != 'cancelled':
        existing = sb.table('bookings').select('id, customer_id').eq('building', building).eq('flat_no', flat_no).eq('status', 'booked').neq('id', bid).execute()
        if existing.data:
            eid = existing.data[0]['id']
            buyer = 'Unknown'
            cid = existing.data[0].get('customer_id')
            if cid:
                cr = sb.table('customers').select('name').eq('id', cid).execute()
                if cr.data: buyer = cr.data[0]['name']
            return jsonify({
                'error': 'Duplicate found',
                'duplicates': [f"Flat {flat_no} in {building} is already booked (Booking #{eid}, Buyer: {buyer})"]
            }), 409

    now = datetime.now().isoformat()
    fields = ['customer_id','customer2_id','building','flat_no','flat_type','floor',
              'carpet_area','base_rate','total_package','discount','booking_amount',
              'payment_mode','payment_ref','cp_id','sales_person','remarks','status']

    updates = {'updated_at': now}
    for f in fields:
        if f in d:
            updates[f] = d[f]
    if 'form_data' in d:
        updates['form_data'] = d['form_data']  # JSONB handles serialization

    sb.table('bookings').update(updates).eq('id', bid).execute()
    return jsonify({'ok': True})

# ─────────────────────────────────────────────
# INVENTORY
# ─────────────────────────────────────────────
@app.route('/api/inventory', methods=['GET'])
@permission_required('inventory.view')
def get_inventory():
    result = sb.table('bookings').select(
        'flat_no, building, flat_type, status, customers!customer_id(name)'
    ).eq('status', 'booked').execute()

    sold = {}
    for r in result.data:
        cust = r.pop('customers', None) or {}
        key = f"{r['building']}_{r['flat_no']}"
        sold[key] = {
            'flat_no': r['flat_no'],
            'building': r['building'],
            'type': r['flat_type'],
            'buyer': cust.get('name') or 'Booked'
        }
    return jsonify(sold)

# ─────────────────────────────────────────────
# STARTUP
# ─────────────────────────────────────────────
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    debug = os.environ.get('FLASK_DEBUG', 'true').lower() == 'true'
    print("\n" + "="*50)
    print("  GGC Real Estate CRM (Supabase)")
    print(f"  Open: http://localhost:{port}")
    print("  Super Admin: n1 / n1")
    print("  CRM User:    crm / crm")
    print("="*50 + "\n")
    app.run(host='0.0.0.0', port=port, debug=debug)
