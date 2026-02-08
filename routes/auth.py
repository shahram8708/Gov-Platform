"""Authentication and verification blueprint."""
from datetime import datetime, timedelta

from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from flask_wtf import FlaskForm
from sqlalchemy.exc import IntegrityError
from wtforms import BooleanField, PasswordField, SelectField, StringField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError

from extensions import db
from models import AuditLog, EmailVerificationToken, Role, User
from utils.identity_linker import resolve_user_entity_links, active_entity_context
from utils.security import generate_token, hash_value, is_safe_redirect_url, password_meets_policy
from utils.email_service import send_verification_email

auth_bp = Blueprint("auth", __name__)


ROLE_CHOICES: list[tuple[str, str]] = [
    ("Citizen", "Citizen"),
    ("Government Officer", "Government Officer"),
    ("Contractor", "Contractor"),
]

ROLE_DESCRIPTIONS: dict[str, str] = {
    "Citizen": "Default role for citizens",
    "Government Officer": "Role for verified government officers",
    "Contractor": "Role for registered contractors",
}


class RegistrationForm(FlaskForm):
    full_name = StringField("Full Name", validators=[DataRequired(), Length(max=150)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=255)])
    role = SelectField("Role", choices=ROLE_CHOICES, validators=[DataRequired()], default="Citizen")
    password = PasswordField("Password", validators=[DataRequired(), Length(min=12)])
    confirm_password = PasswordField(
        "Confirm Password", validators=[DataRequired(), EqualTo("password", message="Passwords must match.")]
    )
    submit = SubmitField("Create Account")

    def validate_email(self, field):
        if User.query.filter_by(email=field.data.lower()).first():
            raise ValidationError("An account with this email already exists.")

    def validate_role(self, field):
        valid_roles = {choice[0] for choice in self.role.choices}
        if field.data not in valid_roles:
            raise ValidationError("Invalid role selected.")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=255)])
    password = PasswordField("Password", validators=[DataRequired()])
    remember_me = BooleanField("Remember me")
    submit = SubmitField("Sign In")


class ResendVerificationForm(FlaskForm):
    submit = SubmitField("Resend Verification Email")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    form = RegistrationForm()
    if form.validate_on_submit():
        password_ok, reason = password_meets_policy(form.password.data)
        if not password_ok:
            form.password.errors.append(reason)
            return render_template("auth/register.html", form=form, page_title="Register")

        try:
            role = Role.get_or_create(form.role.data, description=ROLE_DESCRIPTIONS.get(form.role.data, ""))
            user = User(
                full_name=form.full_name.data.strip(),
                email=form.email.data.lower().strip(),
                role=role,
                is_email_verified=False,
                is_active=True,
            )
            user.set_password(form.password.data)

            db.session.add(user)
            db.session.flush()

            token, expires_at = create_email_verification_token(user)
            log_action("REGISTER", user)

            db.session.commit()
            send_verification_email(user.email, user.full_name, url_for("auth.verify_email", token=token, _external=True), expires_at.strftime("%Y-%m-%d %H:%M"))
            flash("Registration successful. Please verify your email to activate your account.", "success")
            return redirect(url_for("auth.login"))
        except IntegrityError:
            db.session.rollback()
            flash("Unable to register with the provided details. Please try again.", "danger")

    return render_template("auth/register.html", form=form, page_title="Register")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower().strip()).first()
        if not user or not user.check_password(form.password.data):
            log_action("LOGIN_FAILED", user)
            db.session.commit()
            flash("Invalid credentials provided.", "danger")
            return render_template("auth/login.html", form=form, page_title="Login"), 401

        if not user.is_active:
            flash("Your account is inactive. Please contact support.", "warning")
            return render_template("auth/login.html", form=form, page_title="Login"), 403

        if not user.is_email_verified:
            flash("Email not verified. Please verify your email before logging in.", "warning")
            return redirect(url_for("auth.resend_verification"))

        login_user(user, remember=True, duration=timedelta(days=365))
        session.permanent = True
        user.last_login_at = datetime.utcnow()
        db.session.add(user)
        link = resolve_user_entity_links(user)
        if link:
            db.session.add(link)
        log_action("LOGIN", user)
        db.session.commit()

        next_page = request.args.get("next")
        if next_page and is_safe_redirect_url(next_page):
            return redirect(next_page)
        return redirect(role_based_redirect(user))

    return render_template("auth/login.html", form=form, page_title="Login")


@auth_bp.route("/logout")
@login_required
def logout():
    user = current_user
    logout_user()
    session.clear()
    log_action("LOGOUT", user)
    db.session.commit()
    flash("You have been logged out.", "success")
    return redirect(url_for("auth.login"))


@auth_bp.route("/verify/<token>")
def verify_email(token):
    token_hash = hash_value(token)
    record = EmailVerificationToken.query.filter_by(token_hash=token_hash).first()
    if not record:
        flash("Invalid or expired verification link.", "danger")
        return redirect(url_for("auth.login"))

    if record.is_used:
        flash("This verification link has already been used.", "info")
        return redirect(url_for("auth.login"))

    if record.is_expired:
        flash("Verification link has expired. Please request a new one.", "warning")
        return redirect(url_for("auth.resend_verification"))

    user = record.user
    user.is_email_verified = True
    record.consumed_at = datetime.utcnow()
    db.session.add_all([user, record])
    log_action("VERIFY_EMAIL", user)
    db.session.commit()
    flash("Email successfully verified. You may now log in.", "success")
    return redirect(url_for("auth.login"))


@auth_bp.route("/resend-verification", methods=["GET", "POST"])
def resend_verification():
    form = ResendVerificationForm()
    user = current_user

    if user.is_email_verified:
        flash("Your email is already verified.", "info")
        return redirect(url_for("main.dashboard"))

    if form.validate_on_submit():
        token, expires_at = create_email_verification_token(user)
        db.session.commit()
        send_verification_email(user.email, user.full_name, url_for("auth.verify_email", token=token, _external=True), expires_at.strftime("%Y-%m-%d %H:%M"))
        log_action("RESEND_VERIFICATION", user)
        db.session.commit()
        flash("A new verification link has been sent to your email.", "success")
        return redirect(url_for("main.dashboard"))

    return render_template("auth/resend_verification.html", form=form, page_title="Verify Email")


def role_based_redirect(user: User) -> str:
    mapping = {
        "citizen": "main.citizen_dashboard",
        "government officer": "main.officer_dashboard",
        "officer": "main.officer_dashboard",
        "contractor": "main.contractor_dashboard",
        "admin": "main.admin_dashboard",
    }
    role_name = (user.role.name if user.role else "").lower()
    endpoint = mapping.get(role_name, "main.dashboard")
    return url_for(endpoint)


def create_email_verification_token(user: User, validity_minutes: int = 60) -> tuple[str, datetime]:
    token = generate_token(24)
    token_hash = hash_value(token)
    expires_at = datetime.utcnow() + timedelta(minutes=validity_minutes)

    record = EmailVerificationToken(
        user=user,
        token_hash=token_hash,
        expires_at=expires_at,
    )
    # Remove previous unused tokens for cleanliness
    EmailVerificationToken.query.filter_by(user_id=user.id, consumed_at=None).delete()
    db.session.add(record)
    return token, expires_at
def log_action(action: str, user: User | None, context: str | None = None):
    ctx_value = context
    try:
        if not ctx_value and user:
            ctx = active_entity_context(user)
            if ctx:
                ctx_value = f"{ctx.get('entity_type')}:{ctx.get('entity_id')}"
    except Exception:
        ctx_value = context
    entry = AuditLog(
        user_id=user.id if user else None,
        action_type=action,
        ip_address=request.remote_addr,
        user_agent=request.headers.get("User-Agent", "unknown"),
        context_entity=ctx_value,
    )
    db.session.add(entry)
