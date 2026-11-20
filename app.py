from flask import Flask, request, jsonify, session, redirect, render_template_string
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import sqlite3
import secrets
import os
import time

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
DB = os.environ.get("DATABASE_PATH", "nova_chat.db")

# ---------- قاعدة البيانات ----------

def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = db()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender INTEGER NOT NULL,
        receiver INTEGER NOT NULL,
        body TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        FOREIGN KEY(sender) REFERENCES users(id),
        FOREIGN KEY(receiver) REFERENCES users(id)
    );
    """)
    con.commit()
    con.close()

init_db()

# ---------- الحماية وتسجيل الدخول ----------

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "uid" not in session:
            return jsonify({"error": "سجّل الدخول أولاً"}), 401
        return fn(*args, **kwargs)
    return wrapper

def csrf_ok():
    return secrets.compare_digest(
        request.headers.get("X-CSRF-Token", ""),
        session.get("csrf", "")
    )

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    return response

# ---------- واجهة التطبيق ----------

PAGE = r"""
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#075e54">
<title>NOVA CHAT</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#e9edef;font-family:Tahoma,Arial;color:#17252a}
button,input{font:inherit}
.top{height:65px;background:#075e54;color:white;display:flex;
align-items:center;justify-content:space-between;padding:0 20px}
.logo{font-size:22px;font-weight:bold}
.layout{max-width:1100px;height:calc(100dvh - 85px);margin:10px auto;
display:grid;grid-template-columns:340px 1fr;background:white;
border-radius:12px;overflow:hidden;box-shadow:0 4px 25px #0001}
.sidebar{border-left:1px solid #ddd;display:flex;flex-direction:column;min-height:0}
.sidehead{padding:18px;background:#f0f2f5;font-weight:bold}
.search{padding:10px;background:#fff}
.search input{width:100%;padding:12px;border:0;background:#f0f2f5;border-radius:9px;outline:none}
.users{overflow:auto}
.person{padding:15px;border-bottom:1px solid #eee;cursor:pointer;display:flex;gap:12px;align-items:center}
.person:hover,.person.active{background:#e9f5f2}
.avatar{width:43px;height:43px;border-radius:50%;background:#d5eee8;
display:grid;place-items:center;color:#075e54;font-weight:bold}
.chat{display:flex;flex-direction:column;min-width:0;min-height:0}
.chathead{padding:14px;background:#f0f2f5;display:flex;align-items:center;gap:12px}
.chatname{font-weight:bold}
.messages{flex:1;overflow:auto;padding:20px;
background-color:#efeae2;
background-image:radial-gradient(#d8d0c5 0.6px,transparent .6px);
background-size:15px 15px}
.bubble{max-width:78%;padding:10px 13px;margin:8px 0;
border-radius:12px;background:white;box-shadow:0 1px 2px #0001;
overflow-wrap:anywhere;white-space:pre-wrap}
.mine{background:#d9fdd3;margin-right:auto}
.time{font-size:10px;color:#667;margin-top:5px;text-align:left}
.send{display:flex;gap:9px;padding:12px;background:#f0f2f5}
.send input{flex:1;border:0;border-radius:25px;padding:13px;outline:none}
.send button,.mainbtn{border:0;border-radius:25px;background:#075e54;color:white;
padding:12px 20px;cursor:pointer}
.empty{margin:auto;text-align:center;color:#667;padding:25px;line-height:2}
.hidden{display:none!important}
.auth{max-width:410px;margin:55px auto;background:white;padding:28px;
border-radius:16px;box-shadow:0 8px 35px #0001}
.auth h2{text-align:center;color:#075e54}
.auth input{width:100%;padding:14px;margin:8px 0;border:1px solid #ddd;border-radius:9px}
.auth button{width:100%;margin-top:12px}
.auth a{color:#075e54;cursor:pointer}
.notice{color:#b42318;text-align:center;min-height:24px}
@media(max-width:700px){
 .layout{height:calc(100dvh - 75px);margin:0;border-radius:0}
 .top{height:60px}
 .layout{grid-template-columns:115px 1fr}
 .person{padding:12px 5px;display:block;text-align:center;font-size:12px}
 .avatar{margin:auto auto 7px}
 .sidehead{padding:12px 5px;text-align:center;font-size:13px}
 .search{padding:5px}
 .search input{font-size:11px;padding:9px}
 .chathead{padding:12px 8px}
 .bubble{max-width:90%}
 .send{padding:8px}
 .send button{padding:10px}
}
</style>
</head>
<body>
<div class="top">
 <div class="logo">💬 NOVA CHAT</div>
 <button onclick="logout()" style="background:#ffffff22;color:white;border:0;padding:9px;border-radius:8px">خروج</button>
</div>

<div class="layout">
 <aside class="sidebar">
  <div class="sidehead">المحادثات والأشخاص</div>
  <div class="search"><input id="search" placeholder="ابحث عن شخص..." oninput="filterUsers()"></div>
  <div class="users" id="users"></div>
 </aside>

 <main class="chat">
  <div class="chathead">
   <div class="avatar" id="chatavatar">N</div>
   <div class="chatname" id="chatname">اختر شخصاً للمراسلة</div>
  </div>
  <div class="messages" id="messages">
   <div class="empty">مرحباً بك في NOVA CHAT 👋<br>اختر شخصاً من القائمة وابدأ المحادثة.</div>
  </div>
  <form class="send" onsubmit="sendMessage(event)">
   <input id="message" maxlength="2000" placeholder="اكتب رسالتك..." autocomplete="off">
   <button id="sendbtn">إرسال</button>
  </form>
 </main>
</div>

<script>
const CSRF = {{ csrf|tojson }};
let selected = null;
let people = [];
let lastId = 0;
let loading = false;

async function api(url, options={}) {
 const headers = options.headers || {};
 headers["X-CSRF-Token"] = CSRF;
 if(options.body) headers["Content-Type"] = "application/json";
 const res = await fetch(url,{...options,headers});
 const data = await res.json();
 if(!res.ok) throw new Error(data.error || "حدث خطأ");
 return data;
}

async function loadUsers(){
 try{
  people = await api("/api/users");
  renderUsers();
 }catch(e){ alert(e.message); }
}

function renderUsers(){
 const q=document.getElementById("search").value.toLowerCase();
 const box=document.getElementById("users");
 box.replaceChildren();
 people.filter(p=>p.username.toLowerCase().includes(q)).forEach(p=>{
  const el=document.createElement("div");
  el.className="person"+(selected===p.id?" active":"");
  const av=document.createElement("div");
  av.className="avatar";
  av.textContent=p.username[0].toUpperCase();
  const name=document.createElement("div");
  name.textContent=p.username;
  el.append(av,name);
  el.onclick=()=>chooseUser(p);
  box.append(el);
 });
 if(!box.children.length){
  const empty=document.createElement("div");
  empty.className="empty";
  empty.textContent="لا يوجد أشخاص";
  box.append(empty);
 }
}
function filterUsers(){renderUsers()}

function chooseUser(p){
 selected=p.id;
 lastId=0;
 document.getElementById("chatname").textContent=p.username;
 document.getElementById("chatavatar").textContent=p.username[0].toUpperCase();
 document.getElementById("messages").replaceChildren();
 renderUsers();
 loadMessages();
}

function addMessage(m){
 const box=document.getElementById("messages");
 const bubble=document.createElement("div");
 bubble.className="bubble"+(m.mine?" mine":"");
 const body=document.createElement("div");
 body.textContent=m.body;
 const time=document.createElement("div");
 time.className="time";
 time.textContent=new Date(m.created_at*1000).toLocaleTimeString("ar",{hour:"2-digit",minute:"2-digit"});
 bubble.append(body,time);
 box.append(bubble);
 box.scrollTop=box.scrollHeight;
 lastId=Math.max(lastId,m.id);
}

async function loadMessages(){
 if(!selected || loading)return;
 loading=true;
 try{
  const data=await api(`/api/messages/${selected}?after=${lastId}`);
  data.forEach(addMessage);
 }catch(e){console.log(e.message)}
 loading=false;
}

async function sendMessage(e){
 e.preventDefault();
 const input=document.getElementById("message");
 const body=input.value.trim();
 if(!selected){alert("اختر شخصاً أولاً");return}
 if(!body)return;
 input.value="";
 try{
  await api("/api/messages",{method:"POST",body:JSON.stringify({receiver:selected,body})});
  await loadMessages();
 }catch(err){alert(err.message);input.value=body}
}

async function logout(){
 try{await api("/logout",{method:"POST"});location.reload()}
 catch(e){alert(e.message)}
}
loadUsers();
setInterval(loadMessages,2000);
</script>
</body>
</html>
"""

AUTH = r"""
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#075e54">
<title>NOVA CHAT - دخول</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:linear-gradient(135deg,#063d39,#101b2d);
font-family:Tahoma,Arial;min-height:100vh;display:grid;place-items:center;padding:18px}
.card{width:min(420px,100%);background:white;padding:30px;border-radius:20px}
h1{text-align:center;color:#075e54}
p{text-align:center;color:#667}
input{width:100%;padding:14px;margin:8px 0;border:1px solid #ddd;border-radius:10px}
button{width:100%;padding:14px;background:#075e54;color:white;border:0;
border-radius:10px;margin-top:12px;font-weight:bold}
a{color:#075e54;cursor:pointer}
.error{color:#b42318;text-align:center}
</style>
</head>
<body>
<div class="card">
<h1>💬 NOVA CHAT</h1>
<p>تواصل مع الأشخاص من أي مكان</p>
<div class="error">{{ error }}</div>
<form method="post">
<input type="hidden" name="csrf" value="{{ csrf }}">
<input name="username" placeholder="اسم المستخدم" minlength="3" maxlength="24" required>
<input name="password" type="password" placeholder="كلمة المرور" minlength="8" required>
<button name="action" value="login">تسجيل الدخول</button>
<button name="action" value="register" style="background:#263b50">إنشاء حساب جديد</button>
</form>
</div>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def index():
    if "uid" in session:
        return render_template_string(PAGE, csrf=session["csrf"])

    error = ""
    if request.method == "POST":
        if not secrets.compare_digest(request.form.get("csrf", ""), session.get("csrf", "")):
            error = "انتهت صلاحية الصفحة، أعد تحميلها."
        else:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            action = request.form.get("action")

            if not username.replace("_", "").isalnum() or not 3 <= len(username) <= 24:
                error = "اسم المستخدم يجب أن يكون 3 إلى 24 حرفاً أو رقماً أو _"
            elif len(password) < 8:
                error = "كلمة المرور يجب ألا تقل عن 8 أحرف."
            else:
                con = db()
                user = con.execute(
                    "SELECT * FROM users WHERE username=?", (username,)
                ).fetchone()

                if action == "register":
                    if user:
                        error = "اسم المستخدم مستخدم بالفعل."
                    else:
                        con.execute(
                            "INSERT INTO users(username,password,created_at) VALUES(?,?,?)",
                            (username, generate_password_hash(password), int(time.time()))
                        )
                        con.commit()
                        user = con.execute(
                            "SELECT * FROM users WHERE username=?", (username,)
                        ).fetchone()

                elif not user or not check_password_hash(user["password"], password):
                    error = "اسم المستخدم أو كلمة المرور غير صحيحة."

                if user and not error:
                    session.clear()
                    session["uid"] = user["id"]
                    session["username"] = user["username"]
                    session["csrf"] = secrets.token_urlsafe(32)
                    con.close()
                    return redirect("/")
                con.close()

    session.setdefault("csrf", secrets.token_urlsafe(32))
    return render_template_string(AUTH, csrf=session["csrf"], error=error)

@app.route("/api/users")
@login_required
def users():
    con = db()
    rows = con.execute(
        "SELECT id,username FROM users WHERE id != ? ORDER BY username",
        (session["uid"],)
    ).fetchall()
    con.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/messages/<int:other_id>")
@login_required
def get_messages(other_id):
    after = request.args.get("after", "0")
    try:
        after = max(0, int(after))
    except ValueError:
        after = 0

    me = session["uid"]
    con = db()
    other = con.execute("SELECT id FROM users WHERE id=?", (other_id,)).fetchone()
    if not other or other_id == me:
        con.close()
        return jsonify({"error": "المستخدم غير موجود"}), 404

    rows = con.execute("""
        SELECT id,sender,receiver,body,created_at
        FROM messages
        WHERE id > ? AND (
            (sender=? AND receiver=?) OR
            (sender=? AND receiver=?)
        )
        ORDER BY id LIMIT 200
    """, (after, me, other_id, other_id, me)).fetchall()
    con.close()

    return jsonify([{
        "id": r["id"],
        "body": r["body"],
        "mine": r["sender"] == me,
        "created_at": r["created_at"]
    } for r in rows])

@app.route("/api/messages", methods=["POST"])
@login_required
def send_message():
    if not csrf_ok():
        return jsonify({"error": "طلب غير صالح"}), 403

    data = request.get_json(silent=True) or {}
    body = str(data.get("body", "")).strip()
    try:
        receiver = int(data.get("receiver"))
    except (ValueError, TypeError):
        return jsonify({"error": "المستلم غير صحيح"}), 400

    if not body or len(body) > 2000:
        return jsonify({"error": "الرسالة يجب أن تكون بين 1 و2000 حرف"}), 400

    me = session["uid"]
    if receiver == me:
        return jsonify({"error": "لا يمكنك مراسلة نفسك"}), 400

    con = db()
    exists = con.execute("SELECT id FROM users WHERE id=?", (receiver,)).fetchone()
    if not exists:
        con.close()
        return jsonify({"error": "المستخدم غير موجود"}), 404

    now = int(time.time())
    cur = con.execute(
        "INSERT INTO messages(sender,receiver,body,created_at) VALUES(?,?,?,?)",
        (me, receiver, body, now)
    )
    con.commit()
    message_id = cur.lastrowid
    con.close()
    return jsonify({"ok": True, "id": message_id})

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    if not csrf_ok():
        return jsonify({"error": "طلب غير صالح"}), 403
    session.clear()
    return jsonify({"ok": True})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
