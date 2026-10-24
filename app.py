import os
import io
import uuid
import zipfile
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    send_file, abort, send_from_directory
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from flask_wtf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-secret-key")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///portal.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024
app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, "uploads")

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

db = SQLAlchemy(app)
csrf = CSRFProtect(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "warning"

ALLOWED_EXTENSIONS = {
    "pdf", "doc", "docx", "ppt", "pptx", "xls", "xlsx",
    "txt", "zip", "rar", "png", "jpg", "jpeg"
}
VALID_STATUSES = {"pending", "submitted", "accepted", "rejected"}


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    roll_number = db.Column(db.String(50), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="student")
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    submissions = db.relationship(
        "Submission", backref="student", cascade="all, delete-orphan", lazy=True
    )


class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)
    code = db.Column(db.String(30), nullable=True)
    tasks = db.relationship(
        "Task", backref="subject", cascade="all, delete-orphan", lazy=True
    )


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject_id = db.Column(db.Integer, db.ForeignKey("subject.id"), nullable=False)
    type = db.Column(db.String(20), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    deadline = db.Column(db.DateTime, nullable=False)
    task_file = db.Column(db.String(255), nullable=True)
    task_file_name = db.Column(db.String(255), nullable=True)
    allow_resubmit = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    submissions = db.relationship(
        "Submission", backref="task", cascade="all, delete-orphan", lazy=True
    )


class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey("task.id"), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default="submitted", nullable=False)
    admin_note = db.Column(db.Text, nullable=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    __table_args__ = (
        db.UniqueConstraint("task_id", "student_id", name="unique_task_student_submission"),
    )


class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("login"))
        if current_user.role != "admin":
            abort(403)
        return f(*args, **kwargs)
    return wrapper


def student_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("login"))
        if current_user.role != "student":
            abort(403)
        return f(*args, **kwargs)
    return wrapper


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def save_file(file, subdir, prefix=""):
    original = secure_filename(file.filename) or "file"
    ext = os.path.splitext(original)[1].lower()
    unique_name = f"{prefix}{uuid.uuid4().hex}{ext}"
    rel_path = os.path.join(subdir, unique_name).replace("\\", "/")
    abs_path = os.path.join(app.config["UPLOAD_FOLDER"], rel_path)
    os.makedirs(os.path.dirname(abs_path), exist_ok=True)
    file.save(abs_path)
    return rel_path, original


def remove_file(rel_path):
    if not rel_path:
        return
    abs_path = os.path.join(app.config["UPLOAD_FOLDER"], rel_path)
    if os.path.exists(abs_path):
        os.remove(abs_path)


def parse_deadline(value):
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None


def safe_folder_name(value, fallback="item"):
    cleaned = secure_filename(value or "")
    return cleaned or fallback


def seed_database():
    admin_roll = os.environ.get("ADMIN_ROLL", "admin")
    admin_password = os.environ.get("ADMIN_PASSWORD", "GIMS@123")
    if not User.query.filter_by(roll_number=admin_roll).first():
        db.session.add(User(
            name="Class Representative",
            roll_number=admin_roll,
            role="admin",
            password_hash=generate_password_hash(admin_password),
            is_active=True
        ))
    subjects = [
        "Calculus and Analytical Geometry",
        "Discrete Structures",
        "Functional English",
        "Fahm-ul-Quran",
        "Pakistan Studies",
        "Information and Communication Technology (ICT)",
        "Programming Fundamentals",
    ]
    for subject_name in subjects:
        if not Subject.query.filter_by(name=subject_name).first():
            db.session.add(Subject(name=subject_name))
    db.session.commit()


@app.route("/")
def index():
    if current_user.is_authenticated:
        if current_user.role == "admin":
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("student_dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    if request.method == "POST":
        roll_number = request.form.get("roll_number", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(roll_number=roll_number).first()
        if user and user.is_active and check_password_hash(user.password_hash, password):
            login_user(user)
            flash("Logged in successfully.", "success")
            if user.role == "admin":
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("student_dashboard"))
        flash("Invalid roll number or password, or account is disabled.", "error")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/admin")
@login_required
@admin_required
def admin_dashboard():
    stats = {
        "students": User.query.filter_by(role="student").count(),
        "tasks": Task.query.count(),
        "submissions": Submission.query.count(),
        "pending": Submission.query.filter(
            Submission.status.in_(["pending", "submitted"])
        ).count(),
    }
    recent_submissions = Submission.query.order_by(
        Submission.submitted_at.desc()
    ).limit(8).all()
    return render_template(
        "admin_dashboard.html",
        stats=stats,
        recent_submissions=recent_submissions
    )


@app.route("/admin/students", methods=["GET", "POST"])
@login_required
@admin_required
def admin_students():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        roll_number = request.form.get("roll_number", "").strip()
        password = request.form.get("password", "")
        if not name or not roll_number or len(password) < 6:
            flash("Name, roll number, and a password of at least 6 characters are required.", "error")
        elif User.query.filter_by(roll_number=roll_number).first():
            flash("A user with this roll number already exists.", "error")
        else:
            db.session.add(User(
                name=name,
                roll_number=roll_number,
                password_hash=generate_password_hash(password),
                role="student",
                is_active=True
            ))
            db.session.commit()
            flash("Student added successfully.", "success")
            return redirect(url_for("admin_students"))
    students = User.query.filter_by(role="student").order_by(User.roll_number).all()
    return render_template("admin_students.html", students=students)


@app.route("/admin/students/<int:user_id>/toggle", methods=["POST"])
@login_required
@admin_required
def admin_toggle_student(user_id):
    user = User.query.get_or_404(user_id)
    if user.role == "admin":
        abort(403)
    user.is_active = not user.is_active
    db.session.commit()
    flash(f"Account {'enabled' if user.is_active else 'disabled'} for {user.name}.", "success")
    return redirect(url_for("admin_students"))


@app.route("/admin/students/<int:user_id>/reset-password", methods=["POST"])
@login_required
@admin_required
def admin_reset_password(user_id):
    user = User.query.get_or_404(user_id)
    if user.role == "admin":
        abort(403)
    new_password = request.form.get("new_password", "")
    if len(new_password) < 6:
        flash("New password must be at least 6 characters.", "error")
    else:
        user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        flash(f"Password reset for {user.name}.", "success")
    return redirect(url_for("admin_students"))


@app.route("/admin/students/<int:user_id>/delete", methods=["POST"])
@login_required
@admin_required
def admin_delete_student(user_id):
    user = User.query.get_or_404(user_id)
    if user.role == "admin":
        abort(403)
    for submission in user.submissions:
        remove_file(submission.stored_filename)
    db.session.delete(user)
    db.session.commit()
    flash("Student and their submissions were deleted.", "success")
    return redirect(url_for("admin_students"))


@app.route("/admin/tasks", methods=["GET", "POST"])
@login_required
@admin_required
def admin_tasks():
    if request.method == "POST":
        subject_id = request.form.get("subject_id", type=int)
        task_type = request.form.get("type", "").strip().lower()
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        deadline = parse_deadline(request.form.get("deadline", ""))
        allow_resubmit = request.form.get("allow_resubmit") == "on"
        if not subject_id or task_type not in {"assignment", "quiz"} or not title or not deadline:
            flash("Subject, type, title, and deadline are required.", "error")
            return redirect(url_for("admin_tasks"))
        if not Subject.query.get(subject_id):
            flash("Invalid subject.", "error")
            return redirect(url_for("admin_tasks"))
        task_file_rel = None
        task_file_name = None
        uploaded = request.files.get("task_file")
        if uploaded and uploaded.filename:
            if not allowed_file(uploaded.filename):
                flash("Task file type is not allowed.", "error")
                return redirect(url_for("admin_tasks"))
            task_file_rel, task_file_name = save_file(uploaded, "tasks", prefix="task_")
        db.session.add(Task(
            subject_id=subject_id,
            type=task_type,
            title=title,
            description=description,
            deadline=deadline,
            task_file=task_file_rel,
            task_file_name=task_file_name,
            allow_resubmit=allow_resubmit
        ))
        db.session.commit()
        flash("Task uploaded successfully.", "success")
        return redirect(url_for("admin_tasks"))
    tasks = Task.query.order_by(Task.deadline.desc()).all()
    subjects = Subject.query.order_by(Subject.name).all()
    return render_template("admin_tasks.html", tasks=tasks, subjects=subjects)


@app.route("/admin/tasks/<int:task_id>/delete", methods=["POST"])
@login_required
@admin_required
def admin_delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    remove_file(task.task_file)
    for submission in task.submissions:
        remove_file(submission.stored_filename)
    db.session.delete(task)
    db.session.commit()
    flash("Task and all related submissions were deleted.", "success")
    return redirect(url_for("admin_tasks"))


@app.route("/admin/submissions")
@login_required
@admin_required
def admin_submissions():
    tasks = Task.query.order_by(Task.deadline.desc()).all()
    task_id = request.args.get("task_id", type=int)
    status = request.args.get("status", "").strip()
    query = Submission.query
    if task_id:
        query = query.filter_by(task_id=task_id)
    if status in VALID_STATUSES:
        query = query.filter_by(status=status)
    submissions = query.order_by(Submission.submitted_at.desc()).all()
    selected_task = None
    missing_students = []
    if task_id:
        selected_task = Task.query.get(task_id)
        if selected_task:
            submitted_ids = [s.student_id for s in selected_task.submissions]
            missing_query = User.query.filter(
                User.role == "student", User.is_active == True
            )
            if submitted_ids:
                missing_query = missing_query.filter(~User.id.in_(submitted_ids))
            missing_students = missing_query.order_by(User.roll_number).all()
    return render_template(
        "admin_submissions.html",
        tasks=tasks,
        submissions=submissions,
        selected_task=selected_task,
        missing_students=missing_students,
        status=status
    )


@app.route("/admin/submissions/<int:submission_id>/status", methods=["POST"])
@login_required
@admin_required
def admin_update_submission(submission_id):
    submission = Submission.query.get_or_404(submission_id)
    new_status = request.form.get("status", "").strip()
    note = request.form.get("admin_note", "").strip()
    if new_status not in VALID_STATUSES:
        flash("Invalid submission status.", "error")
        return redirect(request.referrer or url_for("admin_submissions"))
    submission.status = new_status
    submission.admin_note = note
    submission.reviewed_at = datetime.utcnow()
    db.session.commit()
    flash("Submission status updated.", "success")
    return redirect(request.referrer or url_for("admin_submissions"))


@app.route("/admin/tasks/<int:task_id>/download-all")
@login_required
@admin_required
def admin_download_all(task_id):
    task = Task.query.get_or_404(task_id)
    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, "w", zipfile.ZIP_DEFLATED) as zf:
        subject_folder = safe_folder_name(task.subject.name, "Subject")
        task_folder = safe_folder_name(f"{task.type}_{task.title}", "Task")
        for submission in task.submissions:
            student_folder = safe_folder_name(
                f"{submission.student.roll_number}_{submission.student.name}",
                f"student_{submission.student_id}"
            )
            abs_path = os.path.join(app.config["UPLOAD_FOLDER"], submission.stored_filename)
            if os.path.exists(abs_path):
                arcname = os.path.join(
                    subject_folder, task_folder, student_folder, submission.original_filename
                ).replace("\\", "/")
                zf.write(abs_path, arcname)
    memory_file.seek(0)
    filename = f"{safe_folder_name(task.title, 'task')}_submissions.zip"
    return send_file(memory_file, mimetype="application/zip", as_attachment=True, download_name=filename)


@app.route("/submission/<int:submission_id>/download")
@login_required
def download_submission(submission_id):
    submission = Submission.query.get_or_404(submission_id)
    if current_user.role != "admin" and submission.student_id != current_user.id:
        abort(403)
    abs_path = os.path.join(app.config["UPLOAD_FOLDER"], submission.stored_filename)
    if not os.path.exists(abs_path):
        abort(404)
    return send_file(abs_path, as_attachment=True, download_name=submission.original_filename)


@app.route("/admin/announcements", methods=["GET", "POST"])
@login_required
@admin_required
def admin_announcements():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        body = request.form.get("body", "").strip()
        if not title or not body:
            flash("Announcement title and body are required.", "error")
        else:
            db.session.add(Announcement(title=title, body=body, created_by=current_user.id))
            db.session.commit()
            flash("Announcement posted.", "success")
            return redirect(url_for("admin_announcements"))
    announcements = Announcement.query.order_by(Announcement.created_at.desc()).all()
    return render_template("admin_announcements.html", announcements=announcements)


@app.route("/admin/announcements/<int:announcement_id>/delete", methods=["POST"])
@login_required
@admin_required
def admin_delete_announcement(announcement_id):
    a = Announcement.query.get_or_404(announcement_id)
    db.session.delete(a)
    db.session.commit()
    flash("Announcement deleted.", "success")
    return redirect(url_for("admin_announcements"))


@app.route("/student")
@login_required
@student_required
def student_dashboard():
    subjects = Subject.query.order_by(Subject.name).all()
    announcements = Announcement.query.order_by(Announcement.created_at.desc()).limit(5).all()
    return render_template("student_dashboard.html", subjects=subjects, announcements=announcements)


@app.route("/subject/<int:subject_id>")
@login_required
@student_required
def subject(subject_id):
    subject_obj = Subject.query.get_or_404(subject_id)
    tasks = Task.query.filter_by(subject_id=subject_obj.id).order_by(Task.deadline).all()
    task_ids = [t.id for t in tasks]
    submissions = {}
    if task_ids:
        submissions = {
            s.task_id: s
            for s in Submission.query.filter(
                Submission.student_id == current_user.id,
                Submission.task_id.in_(task_ids)
            ).all()
        }
    return render_template("subject.html", subject=subject_obj, tasks=tasks, submissions=submissions)


@app.route("/task/<int:task_id>")
@login_required
def task(task_id):
    task_obj = Task.query.get_or_404(task_id)
    submission = None
    if current_user.role == "student":
        submission = Submission.query.filter_by(
            task_id=task_obj.id, student_id=current_user.id
        ).first()
    return render_template("task.html", task=task_obj, submission=submission)


@app.route("/task/<int:task_id>/submit", methods=["POST"])
@login_required
@student_required
def submit_task(task_id):
    task_obj = Task.query.get_or_404(task_id)
    existing = Submission.query.filter_by(
        task_id=task_obj.id, student_id=current_user.id
    ).first()
    if existing and not task_obj.allow_resubmit:
        flash("Resubmission is not allowed for this task.", "error")
        return redirect(url_for("task", task_id=task_obj.id))
    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        flash("Please choose a file to upload.", "error")
        return redirect(url_for("task", task_id=task_obj.id))
    if not allowed_file(uploaded.filename):
        flash("This file type is not allowed.", "error")
        return redirect(url_for("task", task_id=task_obj.id))
    stored_path, original_name = save_file(
        uploaded, f"submissions/{task_obj.id}",
        prefix=f"{secure_filename(current_user.roll_number)}_"
    )
    if existing:
        remove_file(existing.stored_filename)
        existing.stored_filename = stored_path
        existing.original_filename = original_name
        existing.submitted_at = datetime.utcnow()
        existing.status = "submitted"
        existing.admin_note = None
        existing.reviewed_at = None
    else:
        db.session.add(Submission(
            task_id=task_obj.id,
            student_id=current_user.id,
            stored_filename=stored_path,
            original_filename=original_name,
            submitted_at=datetime.utcnow(),
            status="submitted"
        ))
    db.session.commit()
    flash("Submission uploaded successfully.", "success")
    return redirect(url_for("task", task_id=task_obj.id))


@app.route("/task/<int:task_id>/file")
@login_required
def download_task_file(task_id):
    task_obj = Task.query.get_or_404(task_id)
    if not task_obj.task_file:
        abort(404)
    abs_path = os.path.join(app.config["UPLOAD_FOLDER"], task_obj.task_file)
    if not os.path.exists(abs_path):
        abort(404)
    return send_file(abs_path, as_attachment=True, download_name=task_obj.task_file_name or "task_file")


with app.app_context():
    db.create_all()
    seed_database()


if __name__ == "__main__":
    app.run(debug=True)
