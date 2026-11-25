'use strict';
/*
 * EduTrack — School Management System
 * Single-file Express app: role-based dashboards for Admin, Teacher,
 * Student and Parent. Data lives in data/edutrack.json (seeded on first
 * boot). Passwords are hashed with scrypt; sessions are cookie tokens.
 */
const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'edutrack.json');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── Passwords & sessions ────────────────────────────────────────────────────
const hashPassword = (password, salt = crypto.randomBytes(16).toString('hex')) => {
    const hash = crypto.scryptSync(String(password), salt, 32).toString('hex');
    return `${salt}:${hash}`;
};
const checkPassword = (password, stored) => {
    const [salt, hash] = String(stored || '').split(':');
    if (!salt || !hash) return false;
    const candidate = crypto.scryptSync(String(password), salt, 32).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(candidate));
};
// Stateless sessions: the cookie itself carries an HMAC-signed payload
// (user id + role + expiry), so logins survive BeraHost running more
// than one app instance — a server-side session map does not.
const SESSION_SECRET = process.env.EDU_SESSION_SECRET || 'edutrack-demo-secret-change-me'
const signSession = user => {
    const payload = Buffer.from(JSON.stringify({ id: user.id, role: user.role, exp: Date.now() + 1000 * 60 * 60 * 8 })).toString('base64url')
    const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url')
    return `${payload}.${sig}`
}
const readSession = token => {
    try {
        const [payload, sig] = String(token || '').split('.')
        if (!payload || !sig) return null
        const expected = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url')
        if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null
        const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'))
        if (!data.exp || data.exp < Date.now()) return null
        return data
    } catch { return null }
}

// ── Seed data ───────────────────────────────────────────────────────────────
const seed = () => ({
    users: [
        { id: 'u-admin', role: 'admin', name: 'Mary Wanjiku', email: 'admin@edutrack.ke', password: hashPassword('admin123') },
        { id: 'u-teacher', role: 'teacher', name: 'David Otieno', email: 'teacher@edutrack.ke', password: hashPassword('teach123'), className: 'Grade 7 East' },
        { id: 'u-student', role: 'student', name: 'Amina Hassan', email: 'student@edutrack.ke', password: hashPassword('study123'), studentId: 'STU-001' },
        { id: 'u-parent', role: 'parent', name: 'Peter Hassan', email: 'parent@edutrack.ke', password: hashPassword('parent123'), childId: 'STU-001' },
    ],
    students: [
        { id: 'STU-001', name: 'Amina Hassan', className: 'Grade 7 East', guardian: 'Peter Hassan' },
        { id: 'STU-002', name: 'Brian Kiprop', className: 'Grade 7 East', guardian: 'Faith Kiprop' },
        { id: 'STU-003', name: 'Cynthia Njeri', className: 'Grade 7 East', guardian: 'John Njeri' },
        { id: 'STU-004', name: 'Daniel Mwangi', className: 'Grade 8 West', guardian: 'Grace Mwangi' },
        { id: 'STU-005', name: 'Esther Achieng', className: 'Grade 8 West', guardian: 'Paul Achieng' },
    ],
    teachers: [
        { id: 'TCH-001', name: 'David Otieno', subject: 'Mathematics', className: 'Grade 7 East' },
        { id: 'TCH-002', name: 'Sarah Kimani', subject: 'English', className: 'Grade 8 West' },
    ],
    classes: [
        { name: 'Grade 7 East', teacher: 'David Otieno', students: 3 },
        { name: 'Grade 8 West', teacher: 'Sarah Kimani', students: 2 },
    ],
    attendance: [
        { studentId: 'STU-001', date: '2026-11-24', status: 'present' },
        { studentId: 'STU-001', date: '2026-11-25', status: 'present' },
        { studentId: 'STU-002', date: '2026-11-25', status: 'absent' },
    ],
    results: [
        { studentId: 'STU-001', subject: 'Mathematics', score: 86, term: 'Term 3' },
        { studentId: 'STU-001', subject: 'English', score: 78, term: 'Term 3' },
        { studentId: 'STU-001', subject: 'Science', score: 91, term: 'Term 3' },
        { studentId: 'STU-002', subject: 'Mathematics', score: 64, term: 'Term 3' },
    ],
    fees: [
        { studentId: 'STU-001', total: 45000, paid: 30000, term: 'Term 3' },
        { studentId: 'STU-002', total: 45000, paid: 45000, term: 'Term 3' },
        { studentId: 'STU-003', total: 45000, paid: 12000, term: 'Term 3' },
    ],
    timetable: [
        { day: 'Monday', period: '08:00', subject: 'Mathematics', className: 'Grade 7 East' },
        { day: 'Monday', period: '09:00', subject: 'English', className: 'Grade 7 East' },
        { day: 'Tuesday', period: '08:00', subject: 'Science', className: 'Grade 7 East' },
        { day: 'Wednesday', period: '10:00', subject: 'Kiswahili', className: 'Grade 7 East' },
    ],
});

const loadDb = () => {
    try {
        const raw = fs.readFileSync(DATA_FILE, 'utf8');
        const parsed = JSON.parse(raw);
        if (parsed && Array.isArray(parsed.users)) return parsed;
    } catch {}
    const fresh = seed();
    saveDb(fresh);
    return fresh;
};
const saveDb = data => {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
};
let db = loadDb();

// ── Auth helpers ────────────────────────────────────────────────────────────
const parseCookies = req => Object.fromEntries(String(req.headers.cookie || '').split(';').map(p => p.trim().split('=')).filter(p => p[0]));
const currentUser = req => {
    const session = readSession(parseCookies(req).edutrack_session);
    if (!session) return null;
    return db.users.find(u => u.id === session.id) || null;
};
const requireRole = role => (req, res, next) => {
    const user = currentUser(req);
    if (!user) return res.redirect('/login');
    if (role && user.role !== role) return res.status(403).send(page('Access denied', `<h1>Access denied</h1><p>This area is for ${role} accounts. You are signed in as ${user.role}.</p><p><a href="/${user.role}">Go to your dashboard</a></p>`));
    req.user = user;
    next();
};

// ── Pages ───────────────────────────────────────────────────────────────────
const page = (title, body) => `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title} · EduTrack</title>
<style>
:root{--ink:#14231c;--muted:#5c6f64;--green:#176b52;--paper:#f4f7f3;--line:#dbe5dc;--card:#fff}
*{box-sizing:border-box}body{margin:0;font:16px/1.55 system-ui,sans-serif;color:var(--ink);background:var(--paper)}
header{background:var(--green);color:#fff;padding:14px 22px;display:flex;justify-content:space-between;align-items:center}
header a{color:#fff;text-decoration:none;font-weight:600}main{max-width:1020px;margin:0 auto;padding:28px 20px 60px}
h1{font-size:1.9rem;margin:.2em 0 .4em}h2{font-size:1.25rem;margin:1.4em 0 .5em}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px}
.card b{font-size:1.6rem;display:block}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden}
th,td{padding:10px 12px;border-bottom:1px solid var(--line);text-align:left}th{background:#eef4ee}
input,select,button{font:inherit;padding:10px 12px;border-radius:10px;border:1px solid var(--line)}
button{background:var(--green);color:#fff;border:none;cursor:pointer;font-weight:600}
label{display:block;margin:10px 0 4px;font-weight:600}.muted{color:var(--muted)}
.pill{display:inline-block;padding:2px 10px;border-radius:999px;background:#e6f2ea;color:var(--green);font-size:.85rem;font-weight:700}
form.inline{display:flex;gap:8px;flex-wrap:wrap;align-items:end}
</style></head><body>
<header><a href="/">🎓 EduTrack</a><span>School Management System</span></header>
<main>${body}</main>
<script>
document.addEventListener('submit', function (e) {
    var form = e.target;
    e.preventDefault();
    var data = {};
    new FormData(form).forEach(function (v, k) { data[k] = v; });
    fetch(form.action, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) })
        .then(function (r) { return r.json().catch(function () { return {}; }); })
        .then(function (j) {
            if (j.redirect) { window.location = j.redirect; return; }
            if (j.ok === false) { alert(j.error || 'Something went wrong'); return; }
            window.location.reload();
        })
        .catch(function () { alert('Network error — please try again.'); });
});
</script></body></html>`;

app.get('/', (req, res) => {
    const user = currentUser(req);
    res.send(page('Welcome', `
        <h1>EduTrack School Management System</h1>
        <p class="muted">One system for the whole school — administrators, teachers, students and parents, each with their own dashboard.</p>
        ${user ? `<p><a href="/${user.role}"><button>Open my ${user.role} dashboard</button></a> <a href="/logout">Log out</a></p>`
               : `<p><a href="/login"><button>Log in</button></a></p>`}
        <div class="grid">
            <div class="card"><b>👩🏽‍💼 Admin</b>Manage students, teachers, classes, fees and school-wide reports.</div>
            <div class="card"><b>👨🏾‍🏫 Teacher</b>Mark attendance, enter results and see class lists.</div>
            <div class="card"><b>🧑🏾‍🎓 Student</b>Check results, timetable and fee balance.</div>
            <div class="card"><b>👨‍👧 Parent</b>Follow your child's progress, attendance and fees.</div>
        </div>
        <h2>Demo accounts</h2>
        <table><tr><th>Role</th><th>Email</th><th>Password</th></tr>
        <tr><td>Admin</td><td>admin@edutrack.ke</td><td>admin123</td></tr>
        <tr><td>Teacher</td><td>teacher@edutrack.ke</td><td>teach123</td></tr>
        <tr><td>Student</td><td>student@edutrack.ke</td><td>study123</td></tr>
        <tr><td>Parent</td><td>parent@edutrack.ke</td><td>parent123</td></tr></table>`));
});

app.get('/login', (req, res) => {
    res.send(page('Log in', `
        <h1>Log in to EduTrack</h1>
        ${req.query.error ? '<p style="color:#b3261e">Wrong email or password — try again.</p>' : ''}
        <form method="post" action="/login" class="card" style="max-width:420px">
            <label>Email</label><input name="email" type="email" required style="width:100%">
            <label>Password</label><input name="password" type="password" required style="width:100%">
            <p><button type="submit" style="width:100%">Log in</button></p>
        </form>`));
});

app.post('/login', (req, res) => {
    const user = db.users.find(u => u.email === String(req.body.email || '').toLowerCase());
    const wantsJson = req.is('json');
    if (!user || !checkPassword(req.body.password || '', user.password)) {
        return wantsJson ? res.status(401).json({ ok: false, error: 'Wrong email or password' }) : res.redirect('/login?error=1');
    }
    res.setHeader('Set-Cookie', `edutrack_session=${signSession(user)}; Path=/; HttpOnly; SameSite=Lax`);
    return wantsJson ? res.json({ ok: true, redirect: `/${user.role}` }) : res.redirect(`/${user.role}`);
});

app.get('/logout', (req, res) => {
    res.setHeader('Set-Cookie', 'edutrack_session=; Path=/; Max-Age=0');
    res.redirect('/');
});

// ── Dashboards ──────────────────────────────────────────────────────────────
const feeBalance = studentId => {
    const fee = db.fees.find(f => f.studentId === studentId);
    return fee ? fee.total - fee.paid : 0;
};
const studentName = id => (db.students.find(s => s.id === id) || {}).name || id;

app.get('/admin', requireRole('admin'), (req, res) => {
    const feesCollected = db.fees.reduce((sum, f) => sum + f.paid, 0);
    const feesOutstanding = db.fees.reduce((sum, f) => sum + (f.total - f.paid), 0);
    res.send(page('Admin dashboard', `
        <h1>Admin dashboard</h1><p class="muted">Signed in as ${req.user.name} · <a href="/logout">Log out</a></p>
        <div class="grid">
            <div class="card"><b>${db.students.length}</b>Students</div>
            <div class="card"><b>${db.teachers.length}</b>Teachers</div>
            <div class="card"><b>${db.classes.length}</b>Classes</div>
            <div class="card"><b>KSh ${feesCollected.toLocaleString()}</b>Fees collected</div>
            <div class="card"><b>KSh ${feesOutstanding.toLocaleString()}</b>Fees outstanding</div>
        </div>
        <h2>Students</h2>
        <table><tr><th>ID</th><th>Name</th><th>Class</th><th>Guardian</th><th>Fee balance</th></tr>
        ${db.students.map(s => `<tr><td>${s.id}</td><td>${s.name}</td><td>${s.className}</td><td>${s.guardian}</td><td>KSh ${feeBalance(s.id).toLocaleString()}</td></tr>`).join('')}
        </table>
        <h2>Add a student</h2>
        <form class="inline" method="post" action="/api/students">
            <span><label>Name</label><input name="name" required></span>
            <span><label>Class</label><input name="className" required placeholder="Grade 7 East"></span>
            <span><label>Guardian</label><input name="guardian" required></span>
            <button type="submit">Add student</button>
        </form>
        <h2>Classes</h2>
        <table><tr><th>Class</th><th>Class teacher</th><th>Students</th></tr>
        ${db.classes.map(c => `<tr><td>${c.name}</td><td>${c.teacher}</td><td>${c.students}</td></tr>`).join('')}
        </table>`));
});

app.get('/teacher', requireRole('teacher'), (req, res) => {
    const myClass = req.user.className;
    const classStudents = db.students.filter(s => s.className === myClass);
    res.send(page('Teacher dashboard', `
        <h1>Teacher dashboard</h1><p class="muted">${req.user.name} · Class teacher, ${myClass} · <a href="/logout">Log out</a></p>
        <h2>My class list</h2>
        <table><tr><th>ID</th><th>Name</th><th>Guardian</th></tr>
        ${classStudents.map(s => `<tr><td>${s.id}</td><td>${s.name}</td><td>${s.guardian}</td></tr>`).join('')}
        </table>
        <h2>Mark attendance (today)</h2>
        <form class="inline" method="post" action="/api/attendance">
            <span><label>Student</label><select name="studentId">${classStudents.map(s => `<option value="${s.id}">${s.name}</option>`).join('')}</select></span>
            <span><label>Status</label><select name="status"><option>present</option><option>absent</option><option>late</option></select></span>
            <button type="submit">Save attendance</button>
        </form>
        <h2>Enter a result</h2>
        <form class="inline" method="post" action="/api/results">
            <span><label>Student</label><select name="studentId">${classStudents.map(s => `<option value="${s.id}">${s.name}</option>`).join('')}</select></span>
            <span><label>Subject</label><input name="subject" required placeholder="Mathematics"></span>
            <span><label>Score</label><input name="score" type="number" min="0" max="100" required></span>
            <button type="submit">Save result</button>
        </form>
        <h2>Recent results</h2>
        <table><tr><th>Student</th><th>Subject</th><th>Score</th><th>Term</th></tr>
        ${db.results.slice(-8).reverse().map(r => `<tr><td>${studentName(r.studentId)}</td><td>${r.subject}</td><td>${r.score}</td><td>${r.term}</td></tr>`).join('')}
        </table>`));
});

const studentDashboard = (user, heading) => {
    const studentId = user.role === 'parent' ? user.childId : user.studentId;
    const results = db.results.filter(r => r.studentId === studentId);
    const average = results.length ? Math.round(results.reduce((a, r) => a + r.score, 0) / results.length) : 0;
    const attendance = db.attendance.filter(a => a.studentId === studentId);
    return `
        <h1>${heading}</h1><p class="muted">${user.name} · viewing ${studentName(studentId)} · <a href="/logout">Log out</a></p>
        <div class="grid">
            <div class="card"><b>${average}%</b>Average score</div>
            <div class="card"><b>KSh ${feeBalance(studentId).toLocaleString()}</b>Fee balance</div>
            <div class="card"><b>${attendance.filter(a => a.status === 'present').length}/${attendance.length}</b>Days present</div>
        </div>
        <h2>Results — Term 3</h2>
        <table><tr><th>Subject</th><th>Score</th></tr>
        ${results.map(r => `<tr><td>${r.subject}</td><td>${r.score}</td></tr>`).join('') || '<tr><td colspan="2">No results yet</td></tr>'}
        </table>
        <h2>Timetable</h2>
        <table><tr><th>Day</th><th>Time</th><th>Subject</th></tr>
        ${db.timetable.map(t => `<tr><td>${t.day}</td><td>${t.period}</td><td>${t.subject}</td></tr>`).join('')}
        </table>
        <h2>Attendance</h2>
        <table><tr><th>Date</th><th>Status</th></tr>
        ${attendance.map(a => `<tr><td>${a.date}</td><td><span class="pill">${a.status}</span></td></tr>`).join('') || '<tr><td colspan="2">No attendance records yet</td></tr>'}
        </table>`;
};

app.get('/student', requireRole('student'), (req, res) => res.send(page('Student dashboard', studentDashboard(req.user, 'Student dashboard'))));
app.get('/parent', requireRole('parent'), (req, res) => res.send(page('Parent dashboard', studentDashboard(req.user, 'Parent dashboard'))));

// ── API ─────────────────────────────────────────────────────────────────────
app.get('/api/summary', (req, res) => {
    res.json({ name: 'EduTrack School Management System', version: '1.0.0', students: db.students.length, teachers: db.teachers.length, classes: db.classes.length });
});
app.post('/api/students', requireRole('admin'), (req, res) => {
    const id = `STU-${String(db.students.length + 1).padStart(3, '0')}`;
    db.students.push({ id, name: String(req.body.name || '').trim(), className: String(req.body.className || '').trim(), guardian: String(req.body.guardian || '').trim() });
    db.fees.push({ studentId: id, total: 45000, paid: 0, term: 'Term 3' });
    saveDb(db);
    return req.is('json') ? res.json({ ok: true, redirect: '/admin' }) : res.redirect('/admin');
});
app.post('/api/attendance', requireRole('teacher'), (req, res) => {
    db.attendance.push({ studentId: String(req.body.studentId), date: new Date().toISOString().slice(0, 10), status: String(req.body.status || 'present') });
    saveDb(db);
    return req.is('json') ? res.json({ ok: true, redirect: '/teacher' }) : res.redirect('/teacher');
});
app.post('/api/results', requireRole('teacher'), (req, res) => {
    db.results.push({ studentId: String(req.body.studentId), subject: String(req.body.subject || '').trim(), score: Number(req.body.score) || 0, term: 'Term 3' });
    saveDb(db);
    return req.is('json') ? res.json({ ok: true, redirect: '/teacher' }) : res.redirect('/teacher');
});

app.use((req, res) => res.status(404).send(page('Not found', '<h1>Page not found</h1><p><a href="/">Back to EduTrack home</a></p>')));

app.listen(PORT, () => console.log(`EduTrack running on port ${PORT}`));
