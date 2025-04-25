import sqlite3
import uuid
import re  # 비밀번호 강도 검사용 정규표현식
# ✅ 1:1 채팅 기능 추가 - 상품 페이지에서 판매자와 대화 연결
from flask import jsonify, request, abort, flash
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, IntegerField
from wtforms.validators import DataRequired, Length, NumberRange, Regexp
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash # bcrypt 추가
from flask_socketio import SocketIO, send

# ✅ CSRF 보호를 위한 WTForm 클래스 정의
class ReportForm(FlaskForm):
    target_id = StringField('Target ID', validators=[DataRequired()])
    reason = TextAreaField('Reason', validators=[DataRequired(), Length(min=5)])

# 이건 TranferForm 클래스
class TransferForm(FlaskForm):
    recipient = StringField('Recipient Username', validators=[DataRequired()])
    amount = IntegerField('Amount', validators=[DataRequired(), NumberRange(min=1)])
    
#Depositform
class DepositForm(FlaskForm):
    account = StringField('Account Number', validators=[
        DataRequired(),
        Regexp(r'^\d{3}-\d{2}-\d{5}$', message="계좌번호 형식은 000-00-00000이어야 합니다.")
    ])
    amount = IntegerField('Amount', validators=[DataRequired(), NumberRange(min=1)])

    
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
DATABASE = 'market.db'
socketio = SocketIO(app)

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 관리자 전용 데코레이터
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT is_admin FROM user WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        if not user or user['is_admin'] != 1:
            abort(403)
        return f(*args, **kwargs)
    return decorated

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                balance INTEGER DEFAULT 0,
                is_admin BOOLEAN DEFAULT 0
            )
        """)
        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL
            )
        """)
        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)
        db.commit()

# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# 회원가입
def is_strong_password(pw):
    return (
        len(pw) >= 8 and
        re.search(r'[0-9]', pw) and
        (re.search(r'[a-z]', pw) or
        re.search(r'[A-Z]', pw)) and
        re.search(r'[\W_]', pw)
    )

# 회원가입 시 비밀번호 강도 검사 추가
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not is_strong_password(password):
            flash('비밀번호는 8자 이상, 대소문자, 숫자, 특수문자를 포함해야 합니다.')
            return redirect(url_for('register'))

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))

        user_id = str(uuid.uuid4())
        hashed_password = generate_password_hash(password)
        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                       (user_id, username, hashed_password))
        db.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')
# ✅ CSRF 보호를 위한 WTForm 클래스 정의
class ReportForm(FlaskForm):
    target_id = StringField('Target ID', validators=[DataRequired()])
    reason = TextAreaField('Reason', validators=[DataRequired(), Length(min=5)])

class TransferForm(FlaskForm):
    recipient = StringField('Recipient Username', validators=[DataRequired()])
    amount = IntegerField('Amount', validators=[DataRequired(), NumberRange(min=1)])

# ✅ 유저 간 송금 기능
@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    form = TransferForm()
    db = get_db()
    cursor = db.cursor()

    # 사용자 잔액 조회
    cursor.execute("SELECT balance FROM user WHERE id = ?", (session['user_id'],))
    balance = cursor.fetchone()['balance']

    if form.validate_on_submit():
        recipient_name = form.recipient.data.strip()
        amount = form.amount.data

        cursor.execute("SELECT id FROM user WHERE username = ?", (recipient_name,))
        recipient_row = cursor.fetchone()

        if not recipient_row:
            flash('존재하지 않는 사용자입니다.')
            return redirect(url_for('transfer'))

        recipient_id = recipient_row['id']
        sender_id = session['user_id']

        if recipient_id == sender_id:
            flash('자기 자신에게는 송금할 수 없습니다.')
            return redirect(url_for('transfer'))

        cursor.execute("SELECT balance FROM user WHERE id = ?", (sender_id,))
        sender_balance = cursor.fetchone()['balance']

        if sender_balance < amount:
            flash('잔액이 부족합니다.')
            return redirect(url_for('transfer'))

        try:
            cursor.execute("UPDATE user SET balance = balance - ? WHERE id = ?", (amount, sender_id))
            cursor.execute("UPDATE user SET balance = balance + ? WHERE id = ?", (amount, recipient_id))
            db.commit()
            flash('송금이 완료되었습니다.')
        except Exception as e:
            db.rollback()
            flash(f'송금 중 오류가 발생했습니다: {e}')

        return redirect(url_for('dashboard'))

    return render_template('transfer.html', form=form, balance=balance)

# ✅ 충전 기능
@app.route('/deposit', methods=['GET', 'POST'])
def deposit():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    form = DepositForm()
    db = get_db()
    cursor = db.cursor()

    if form.validate_on_submit():
        amount = form.amount.data
        cursor.execute("UPDATE user SET balance = balance + ? WHERE id = ?", (amount, session['user_id']))
        db.commit()
        flash('충전이 완료되었습니다.')
        return redirect(url_for('transfer'))

    return render_template('deposit.html', form=form)

# 상품 검색 기능
@app.route('/search')
def search():
    query = request.args.get('q', '').strip()
    results = []
    if len(query) >= 2:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            SELECT * FROM product
            WHERE LOWER(title) LIKE ?
        """, (f"%{query.lower()}%",))
        results = cursor.fetchall()
    elif query:
        flash('검색어는 최소 2자 이상 입력해주세요.')
    return render_template('search.html', results=results, keyword=query)

# 프로필 페이지: bio 업데이트 + 비밀번호 변경 분리 및 보안 추가
@app.route('/profile', methods=['GET'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    return render_template('profile.html', user=current_user)

@app.route('/update_bio', methods=['POST'])
def update_bio():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    bio = request.form.get('bio', '')
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
    db.commit()
    flash('소개글이 업데이트되었습니다.')
    return redirect(url_for('profile'))

@app.route('/change_password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_pw = request.form.get('current_password', '')
    new_pw = request.form.get('new_password', '')

    if not is_strong_password(new_pw):
        flash('비밀번호는 8자 이상이며 대소문자, 숫자, 특수문자를 포함해야 합니다.')
        return redirect(url_for('profile'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()

    if not user or not check_password_hash(user['password'], current_pw):
        flash('현재 비밀번호가 틀렸습니다.')
        return redirect(url_for('profile'))

    new_hashed_pw = generate_password_hash(new_pw)
    cursor.execute("UPDATE user SET password = ? WHERE id = ?", (new_hashed_pw, session['user_id']))
    db.commit()
    flash('비밀번호가 성공적으로 변경되었습니다.')
    return redirect(url_for('profile'))

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))
    return render_template('login.html')

# 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    # 현재 사용자 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    # 모든 상품 조회
    cursor.execute("SELECT * FROM product")
    all_products = cursor.fetchall()
    return render_template('dashboard.html', products=all_products, user=current_user)

def is_valid_price(value): # 숫자 검증
    try:
        price = float(value)
        return 0 <= price <= 100000000  # 적당한 상한 제한
    except ValueError:
        return False
    
# 상품 등록 라우트 보완: 입력 검증 + 로그인 인증 + 가격 검사
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title'].strip()
        description = request.form['description'].strip()
        price = request.form['price'].strip()

        if not title or not description or not price:
            flash('모든 항목을 입력해주세요.')
            return redirect(url_for('new_product'))

        if not is_valid_price(price):
            flash('가격은 숫자로 입력하고 0 이상이어야 합니다.')
            return redirect(url_for('new_product'))

        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'])
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')

# 상품 상세 보기: URL로 접근 가능하도록 복원
# ✅ 상품 상세 보기: XSS 방지 필터 적용 및 판매자 정보 최소화
@app.route('/product/<product_id>')
def view_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))

    cursor.execute("SELECT id, username, bio FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    return render_template('view_product.html', product=product, seller=seller)

# 상품 수정 및 삭제 기능 추가: 인증된 사용자 + 소유자 검증
@app.route('/product/edit/<product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    if not product or product['seller_id'] != session['user_id']:
        flash('수정 권한이 없습니다.')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        title = request.form['title'].strip()
        description = request.form['description'].strip()
        price = request.form['price'].strip()

        if not title or not description or not price:
            flash('모든 항목을 입력해주세요.')
            return redirect(url_for('edit_product', product_id=product_id))

        if not is_valid_price(price):
            flash('가격은 숫자로 입력하고 0 이상이어야 합니다.')
            return redirect(url_for('edit_product', product_id=product_id))

        cursor.execute("UPDATE product SET title = ?, description = ?, price = ? WHERE id = ?",
                       (title, description, price, product_id))
        db.commit()
        flash('상품 정보가 수정되었습니다.')
        return redirect(url_for('dashboard'))

    return render_template('edit_product.html', product=product)

@app.route('/product/delete/<product_id>', methods=['POST'])
def delete_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    if not product or product['seller_id'] != session['user_id']:
        flash('삭제 권한이 없습니다.')
        return redirect(url_for('dashboard'))

    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('dashboard'))

# ✅ 신고하기 기능 개선 (CSRF 토큰 적용 + 사용자명/상품명도 허용)
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    form = ReportForm()
    db = get_db()
    cursor = db.cursor()

    if form.validate_on_submit():
        target_input = form.target_id.data.strip()
        reason = form.reason.data.strip()

        # 사용자 ID 또는 사용자명 허용
        cursor.execute("SELECT id FROM user WHERE id = ? OR username = ?", (target_input, target_input))
        user_row = cursor.fetchone()

        # 상품 ID 또는 제목 허용
        cursor.execute("SELECT id FROM product WHERE id = ? OR title = ?", (target_input, target_input))
        product_row = cursor.fetchone()

        if user_row:
            target_id = user_row['id']
        elif product_row:
            target_id = product_row['id']
        else:
            flash('존재하지 않는 사용자명 또는 상품명입니다.')
            return redirect(url_for('report'))

        # 동일 사용자 중복 신고 제한
        cursor.execute("SELECT COUNT(*) FROM report WHERE reporter_id = ? AND target_id = ?", (session['user_id'], target_id))
        if cursor.fetchone()[0] >= 3:
            flash('이미 해당 대상에 대해 여러 번 신고하셨습니다.')
            return redirect(url_for('dashboard'))

        # 신고 기록 저장
        report_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
            (report_id, session['user_id'], target_id, reason)
        )
        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))

    return render_template('report.html', form=form)

# 1:1 채팅 페이지 접속 라우트
@app.route('/chat/<receiver_id>')
def private_chat(receiver_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if session['user_id'] == receiver_id:
        flash('자기 자신과는 채팅할 수 없습니다.')
        return redirect(url_for('dashboard'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT username FROM user WHERE id = ?", (receiver_id,))
    receiver = cursor.fetchone()
    if not receiver:
        flash('사용자를 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))

    # ✅ 과거 메시지 필터링 (메모리 기준)
    messages = [m for m in direct_message_store if
                (m['from'] == session['user_id'] and m['to'] == receiver_id) or
                (m['from'] == receiver_id and m['to'] == session['user_id'])]

    return render_template('chat_private.html',
                           receiver_id=receiver_id,
                           receiver_name=receiver['username'],
                           my_id=session['user_id'],
                           messages=messages)

# SocketIO 기반 1:1 메시지 전달 이벤트 처리
direct_message_store = []  # 간단한 메모리 저장 (실제에선 DB 필요)
@app.route('/chat/inbox')
def chat_inbox():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    my_id = session['user_id']
    unique_senders = set()

    for m in direct_message_store:
        if m['to'] == my_id:
            unique_senders.add(m['from'])

    db = get_db()
    cursor = db.cursor()
    senders = []
    for uid in unique_senders:
        cursor.execute("SELECT id, username FROM user WHERE id = ?", (uid,))
        user = cursor.fetchone()
        if user:
            senders.append(user)

    return render_template("chat_inbox.html", senders=senders)

@socketio.on('private_message')
def handle_private_message(data):
    sender_id = session.get('user_id')
    receiver_id = data.get('to')
    msg = data.get('message', '').strip()

    if not sender_id or not receiver_id or not msg:
        return

    if len(msg) > 200:
        msg = msg[:200]

    msg_data = {
        'from': sender_id,
        'to': receiver_id,
        'message': msg,
        'id': str(uuid.uuid4())
    }
    direct_message_store.append(msg_data)
    send(msg_data, room=receiver_id)  # receiver_id를 room으로 사용
    send(msg_data, room=sender_id)    # sender에게도 echo

# 접속 시 사용자를 자신의 room에 join
@socketio.on('join_private')
def on_join_private():
    uid = session.get('user_id')
    if uid:
        join_room(uid)
        
# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message')
def handle_send_message_event(data):
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)

if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    socketio.run(app, debug=True)
