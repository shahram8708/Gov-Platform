"""Authorization decorators for role-based access control."""
from functools import wraps

from flask import abort, current_app, request
from flask_login import current_user, login_required

from extensions import db
from models import AuditLog


def roles_required(*roles):
    allowed = {r.lower() for r in roles}

    def decorator(view_func):
        @wraps(view_func)
        @login_required
        def wrapped(*args, **kwargs):
            role_name = (current_user.role.name if current_user.role else "").lower()
            if role_name in allowed:
                return view_func(*args, **kwargs)

            current_app.logger.warning(
                "Unauthorized role access attempt",
                extra={"user_id": current_user.id, "role": current_user.role.name if current_user.role else None},
            )
            audit = AuditLog(
                user_id=current_user.id,
                action_type="UNAUTHORIZED_ACCESS",
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", "unknown"),
            )
            db.session.add(audit)
            db.session.commit()
            abort(403)

        return wrapped

    return decorator
