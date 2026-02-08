"""Core data models for authentication, RBAC, audit trails, and project discovery."""
import uuid
from datetime import datetime, timedelta
from urllib.parse import urlparse

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from extensions import db


def generate_uuid() -> str:
	return str(uuid.uuid4())


PROJECT_STATUS_VALUES: tuple[str, ...] = (
	"On Track",
	"In Progress",
	"Delayed",
	"Completed",
	"Stalled",
	"Critical",
	"Cancelled",
)

COMPLAINT_TYPES: tuple[str, ...] = (
	"Crack",
	"Leakage",
	"Poor Quality",
	"Delay",
	"Corruption",
	"Other",
)

COMPLAINT_STATUSES: tuple[str, ...] = (
	"SUBMITTED",
	"UNDER_REVIEW",
	"IN_PROGRESS",
	"RESOLVED",
	"CLOSED",
)

COMPLAINT_SEVERITY: tuple[str, ...] = (
	"LOW",
	"MEDIUM",
	"HIGH",
	"CRITICAL",
)

RTI_ENTITY_TYPES: tuple[str, ...] = (
	"PROJECT",
	"COMPLAINT",
)

RTI_EVENT_TYPES: tuple[str, ...] = (
	"GENERATED",
	"DOWNLOADED",
)

ALERT_SEVERITIES: tuple[str, ...] = (
	"INFO",
	"MEDIUM",
	"HIGH",
	"CRITICAL",
)

ALERT_STATUSES: tuple[str, ...] = (
	"OPEN",
	"ACKED",
	"RESOLVED",
)

FLAG_ENTITY_TYPES: tuple[str, ...] = (
	"CONTRACTOR",
	"DEPARTMENT",
	"PROJECT",
	"REGION",
	"LOCATION",
)

FLAG_STATUSES: tuple[str, ...] = (
	"ACTIVE",
	"CLEARED",
	"SUPPRESSED",
)

SYNC_STATUSES: tuple[str, ...] = (
	"PENDING",
	"SYNCED",
	"CONFLICT",
)

AUTHENTICITY_FLAGS: tuple[str, ...] = (
	"LIKELY_GENUINE",
	"SUSPICIOUS",
	"UNVERIFIABLE",
)

VISIBILITY_LEVELS: tuple[str, ...] = (
	"PUBLIC",
	"ANONYMIZED",
	"PRIVATE",
)

EMAIL_DELIVERY_STATUSES: tuple[str, ...] = (
	"SENT",
	"FAILED",
	"RETRY_PENDING",
)


class Role(db.Model):
	__tablename__ = "roles"

	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(50), unique=True, nullable=False, index=True)
	description = db.Column(db.String(255), nullable=True)

	users = db.relationship("User", back_populates="role", lazy="dynamic")

	@staticmethod
	def get_or_create(name: str, description: str = ""):
		role = Role.query.filter_by(name=name).first()
		if role:
			return role
		role = Role(name=name, description=description)
		db.session.add(role)
		db.session.commit()
		return role


class User(UserMixin, db.Model):
	__tablename__ = "users"

	id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
	full_name = db.Column(db.String(150), nullable=False)
	email = db.Column(db.String(255), unique=True, nullable=False, index=True)
	password_hash = db.Column(db.String(255), nullable=False)
	role_id = db.Column(db.Integer, db.ForeignKey("roles.id"), nullable=False)
	is_email_verified = db.Column(db.Boolean, default=False, nullable=False)
	language_preference = db.Column(db.String(8), nullable=False, default="en")
	is_active = db.Column(db.Boolean, default=True, nullable=False)
	created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
	last_login_at = db.Column(db.DateTime, nullable=True)

	role = db.relationship("Role", back_populates="users")
	audit_logs = db.relationship("AuditLog", back_populates="user", lazy="dynamic")
	entity_links = db.relationship("UserEntityLink", back_populates="user", lazy="dynamic")
	otps = db.relationship("OTP", back_populates="user", lazy="dynamic")
	verification_tokens = db.relationship("EmailVerificationToken", back_populates="user", lazy="dynamic")
	location_queries = db.relationship("LocationQuery", back_populates="user", lazy="dynamic")
	complaints = db.relationship("Complaint", back_populates="user", lazy="dynamic")
	complaint_supports = db.relationship("ComplaintSupport", back_populates="user", lazy="dynamic")

	def set_password(self, password: str) -> None:
		self.password_hash = generate_password_hash(password, method="pbkdf2:sha256", salt_length=16)

	def check_password(self, password: str) -> bool:
		return check_password_hash(self.password_hash, password)

	@property
	def is_admin(self) -> bool:
		return bool(self.role and self.role.name.lower() == "admin")

	@property
	def active(self) -> bool:  # Flask-Login compatibility alias
		return self.is_active


class AuditLog(db.Model):
	__tablename__ = "audit_logs"

	id = db.Column(db.Integer, primary_key=True)
	user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=True)
	action_type = db.Column(db.String(50), nullable=False)
	ip_address = db.Column(db.String(64), nullable=True)
	user_agent = db.Column(db.String(255), nullable=True)
	context_entity = db.Column(db.String(120), nullable=True)
	timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

	user = db.relationship("User", back_populates="audit_logs")


class UserEntityLink(db.Model):
	__tablename__ = "user_entity_links"

	id = db.Column(db.Integer, primary_key=True)
	user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False, index=True)
	entity_type = db.Column(db.String(30), nullable=False, index=True)
	entity_id = db.Column(db.String(64), nullable=False, index=True)
	linked_by = db.Column(db.String(30), nullable=False, default="EMAIL_MATCH", index=True)
	linked_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
	is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)
	notes = db.Column(db.String(255), nullable=True)

	__table_args__ = (
		db.UniqueConstraint("user_id", "entity_type", "entity_id", name="uq_user_entity_link"),
		db.CheckConstraint("entity_type IN ('CONTRACTOR','OFFICER','DEPARTMENT')", name="ck_user_entity_link_type"),
		db.CheckConstraint("linked_by IN ('EMAIL_MATCH')", name="ck_user_entity_link_source"),
	)

	user = db.relationship("User", back_populates="entity_links")


class EmailVerificationToken(db.Model):
	__tablename__ = "email_verification_tokens"

	id = db.Column(db.Integer, primary_key=True)
	user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False)
	token_hash = db.Column(db.String(128), nullable=False, unique=True, index=True)
	expires_at = db.Column(db.DateTime, nullable=False)
	consumed_at = db.Column(db.DateTime, nullable=True)
	created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

	user = db.relationship("User", back_populates="verification_tokens")

	@property
	def is_expired(self) -> bool:
		return datetime.utcnow() > self.expires_at

	@property
	def is_used(self) -> bool:
		return self.consumed_at is not None


class OTP(db.Model):
	__tablename__ = "otps"

	id = db.Column(db.Integer, primary_key=True)
	user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False)
	purpose = db.Column(db.String(50), nullable=False)
	otp_hash = db.Column(db.String(128), nullable=False)
	expires_at = db.Column(db.DateTime, nullable=False)
	consumed_at = db.Column(db.DateTime, nullable=True)
	created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
	ip_address = db.Column(db.String(64), nullable=True)

	user = db.relationship("User", back_populates="otps")

	@staticmethod
	def create_for(user, purpose: str, otp_value: str, ttl_seconds: int = 600, ip_address: str | None = None):
		expires_at = datetime.utcnow() + timedelta(seconds=ttl_seconds)
		record = OTP(
			user=user,
			purpose=purpose,
			otp_hash=generate_password_hash(otp_value, method="pbkdf2:sha256", salt_length=12),
			expires_at=expires_at,
			ip_address=ip_address,
		)
		db.session.add(record)
		db.session.commit()
		return record

	def verify(self, candidate: str) -> bool:
		if self.consumed_at or datetime.utcnow() > self.expires_at:
			return False
		return check_password_hash(self.otp_hash, candidate)


class LocationQuery(db.Model):
	__tablename__ = "location_queries"

	id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
	user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False, index=True)
	location_name = db.Column(db.String(255), nullable=False)
	manual_input = db.Column(db.String(255), nullable=True)
	latitude = db.Column(db.Numeric(9, 6), nullable=True)
	longitude = db.Column(db.Numeric(9, 6), nullable=True)
	query_type = db.Column(db.String(20), nullable=False)  # gps|manual
	project_types = db.Column(db.JSON, nullable=False, default=list)
	created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

	user = db.relationship("User", back_populates="location_queries")
	projects = db.relationship("InfrastructureProject", back_populates="location_query", lazy="dynamic")


class MaintenanceAuthority(db.Model):
	__tablename__ = "maintenance_authorities"

	id = db.Column(db.Integer, primary_key=True)
	authority_name = db.Column(db.String(255), nullable=False, index=True)
	contact_email = db.Column(db.String(255), nullable=True)
	contact_phone = db.Column(db.String(50), nullable=True)
	office_address = db.Column(db.String(500), nullable=True)
	created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

	projects = db.relationship("InfrastructureProject", back_populates="maintenance_authority", lazy="dynamic")


class Contractor(db.Model):
	__tablename__ = "contractors"

	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(255), nullable=False, index=True)
	company_name = db.Column(db.String(255), nullable=True, index=True)
	registration_number = db.Column(db.String(120), nullable=True, index=True)
	email = db.Column(db.String(255), nullable=True)
	phone = db.Column(db.String(50), nullable=True)
	office_address = db.Column(db.String(500), nullable=True)
	public_image_url = db.Column(db.String(1024), nullable=True)
	public_image_source_domain = db.Column(db.String(255), nullable=True)
	public_image_note = db.Column(
		db.String(255),
		nullable=True,
		default="Image sourced from public domain (unverified identity)",
	)
	created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

	projects = db.relationship("InfrastructureProject", back_populates="contractor", lazy="dynamic")


class GovernmentDepartment(db.Model):
	__tablename__ = "government_departments"

	id = db.Column(db.Integer, primary_key=True)
	department_name = db.Column(db.String(255), nullable=False, index=True)
	ministry_level = db.Column(db.String(50), nullable=True, index=True)
	official_email = db.Column(db.String(255), nullable=True)
	official_phone = db.Column(db.String(50), nullable=True)
	office_address = db.Column(db.String(500), nullable=True)
	created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

	projects = db.relationship("InfrastructureProject", back_populates="department", lazy="dynamic")
	officers = db.relationship("DepartmentOfficer", back_populates="department", cascade="all, delete-orphan")


class DepartmentOfficer(db.Model):
	__tablename__ = "department_officers"

	id = db.Column(db.Integer, primary_key=True)
	department_id = db.Column(db.Integer, db.ForeignKey("government_departments.id"), nullable=False, index=True)
	officer_name = db.Column(db.String(255), nullable=False, index=True)
	designation = db.Column(db.String(150), nullable=True)
	official_email = db.Column(db.String(255), nullable=True)
	official_phone = db.Column(db.String(50), nullable=True)
	is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)
	public_image_url = db.Column(db.String(1024), nullable=True)
	public_image_source_domain = db.Column(db.String(255), nullable=True)
	public_image_note = db.Column(
		db.String(255),
		nullable=True,
		default="Image sourced from public domain (unverified identity)",
	)
	created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

	department = db.relationship("GovernmentDepartment", back_populates="officers")


class InfrastructureProject(db.Model):
	__tablename__ = "infrastructure_projects"

	id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
	location_query_id = db.Column(db.String(36), db.ForeignKey("location_queries.id"), nullable=False, index=True)
	project_type = db.Column(db.String(80), nullable=False)
	project_name = db.Column(db.String(255), nullable=False)
	project_cost = db.Column(db.String(120), nullable=True)
	start_date = db.Column(db.String(50), nullable=True)
	expected_end_date = db.Column(db.String(50), nullable=True)
	current_status = db.Column(db.String(50), nullable=False, default="In Progress", index=True)
	is_public = db.Column(db.Boolean, nullable=False, default=True, index=True)
	visibility_level = db.Column(db.String(20), nullable=False, default="PUBLIC", index=True)
	integrity_hash = db.Column(db.String(128), nullable=True, index=True)
	blockchain_anchor_id = db.Column(db.String(36), db.ForeignKey("blockchain_anchors.id"), nullable=True)
	contractor_id = db.Column(db.Integer, db.ForeignKey("contractors.id"), nullable=True, index=True)
	department_id = db.Column(db.Integer, db.ForeignKey("government_departments.id"), nullable=True, index=True)
	maintenance_authority_id = db.Column(db.Integer, db.ForeignKey("maintenance_authorities.id"), nullable=True, index=True)
	created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

	__table_args__ = (
		db.CheckConstraint(
			"current_status IN ('On Track','In Progress','Delayed','Completed','Stalled','Critical','Cancelled')",
			name="ck_infrastructure_status_valid",
		),
		db.CheckConstraint(
			"visibility_level IN ('PUBLIC','PRIVATE')",
			name="ck_project_visibility",
		),
		db.Index("ix_infra_project_lookup", "project_name", "project_type"),
	)

	location_query = db.relationship("LocationQuery", back_populates="projects")
	contractor = db.relationship("Contractor", back_populates="projects")
	department = db.relationship("GovernmentDepartment", back_populates="projects")
	maintenance_authority = db.relationship("MaintenanceAuthority", back_populates="projects")
	source_links = db.relationship("ProjectSourceLink", back_populates="project", cascade="all, delete-orphan")
	tender_references = db.relationship("TenderReference", back_populates="project", cascade="all, delete-orphan")
	status_history = db.relationship(
		"ProjectStatusHistory",
		back_populates="project",
		order_by="ProjectStatusHistory.updated_at",
		cascade="all, delete-orphan",
	)
	complaints = db.relationship("Complaint", back_populates="project", cascade="all, delete-orphan")
	snapshots = db.relationship("ProjectSnapshot", back_populates="project", cascade="all, delete-orphan")
	blockchain_anchor = db.relationship("BlockchainAnchor")

	@staticmethod
	def public_query():
		"""Return a base query restricted to public-safe projects."""
		return InfrastructureProject.query.filter(
			InfrastructureProject.is_public.is_(True),
			InfrastructureProject.visibility_level == "PUBLIC",
		)

	@property
	def area_label(self) -> str:
		location_name = self.location_query.location_name if self.location_query else ""
		return (location_name or "").split(",")[0].strip() if location_name else ""

	def public_payload(self) -> dict:
		return {
			"id": str(self.id),
			"name": self.project_name,
			"type": self.project_type,
			"status": self.current_status,
			"department": self.department.department_name if self.department else None,
			"area": self.area_label,
			"created_at": self.created_at,
		}


class ProjectSourceLink(db.Model):
	__tablename__ = "project_source_links"

	id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
	project_id = db.Column(db.String(36), db.ForeignKey("infrastructure_projects.id"), nullable=False, index=True)
	url = db.Column(db.String(1024), nullable=False)
	created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

	project = db.relationship("InfrastructureProject", back_populates="source_links")

	@property
	def display_domain(self) -> str:
		"""Return a human-friendly domain for the source link."""
		try:
			parsed = urlparse(self.url or "")
			if parsed.netloc:
				return parsed.netloc
			clean_path = (parsed.path or "").lstrip("/")
			return clean_path.split("/")[0] if clean_path else (self.url or "")
		except Exception:
			return self.url or ""

	@property
	def is_image(self) -> bool:
		"""Return True when the link likely points to an image asset."""
		path = (self.url or "").lower().split("?")[0]
		return path.endswith((".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".svg"))


class TenderReference(db.Model):
	__tablename__ = "tender_references"

	id = db.Column(db.Integer, primary_key=True)
	project_id = db.Column(db.String(36), db.ForeignKey("infrastructure_projects.id"), nullable=False, index=True)
	tender_id = db.Column(db.String(150), nullable=True)
	tender_portal_name = db.Column(db.String(255), nullable=True)
	tender_url = db.Column(db.String(1024), nullable=True)
	published_date = db.Column(db.String(50), nullable=True)
	data_hash = db.Column(db.String(128), nullable=True, index=True)
	blockchain_anchor_id = db.Column(db.String(36), db.ForeignKey("blockchain_anchors.id"), nullable=True, index=True)
	created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

	__table_args__ = (db.UniqueConstraint("project_id", "tender_id", name="uq_tender_project_id"),)

	project = db.relationship("InfrastructureProject", back_populates="tender_references")
	blockchain_anchor = db.relationship("BlockchainAnchor")


class ProjectStatusHistory(db.Model):
	__tablename__ = "project_status_history"

	id = db.Column(db.Integer, primary_key=True)
	project_id = db.Column(db.String(36), db.ForeignKey("infrastructure_projects.id"), nullable=False, index=True)
	status = db.Column(db.String(50), nullable=False, index=True)
	remarks = db.Column(db.String(500), nullable=True)
	status_date_text = db.Column(db.String(50), nullable=True)
	updated_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
	updated_by = db.Column(db.String(120), nullable=True)

	__table_args__ = (
		db.CheckConstraint(
			"status IN ('On Track','In Progress','Delayed','Completed','Stalled','Critical','Cancelled')",
			name="ck_status_history_valid",
		),
	)

	project = db.relationship("InfrastructureProject", back_populates="status_history")


class Complaint(db.Model):
	__tablename__ = "complaints"

	id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
	user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False, index=True)
	project_id = db.Column(db.String(36), db.ForeignKey("infrastructure_projects.id"), nullable=False, index=True)
	complaint_type = db.Column(db.String(50), nullable=False, index=True)
	title = db.Column(db.String(255), nullable=False)
	description = db.Column(db.Text, nullable=False)
	ai_generated_summary = db.Column(db.Text, nullable=True)
	severity_level = db.Column(db.String(20), nullable=False, default="MEDIUM", index=True)
	status = db.Column(db.String(20), nullable=False, default="SUBMITTED", index=True)
	is_public = db.Column(db.Boolean, nullable=False, default=True, index=True)
	visibility_level = db.Column(db.String(20), nullable=False, default="ANONYMIZED", index=True)
	is_offline_submission = db.Column(db.Boolean, nullable=False, default=False, index=True)
	sync_status = db.Column(db.String(20), nullable=True, default="PENDING", index=True)
	sync_reference = db.Column(db.String(64), nullable=True, index=True)
	notification_sent_at = db.Column(db.DateTime, nullable=True, index=True)
	last_follow_up_at = db.Column(db.DateTime, nullable=True, index=True)
	follow_up_count = db.Column(db.Integer, default=0, nullable=False)
	last_email_status = db.Column(db.String(20), nullable=True, index=True)
	location_snapshot = db.Column(db.JSON, nullable=True)
	created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
	updated_at = db.Column(
		db.DateTime,
		default=datetime.utcnow,
		onupdate=datetime.utcnow,
		nullable=False,
		index=True,
	)

	__table_args__ = (
		db.CheckConstraint(
			"complaint_type IN ('Crack','Leakage','Poor Quality','Delay','Corruption','Other')",
			name="ck_complaint_type_valid",
		),
		db.CheckConstraint(
			"severity_level IN ('LOW','MEDIUM','HIGH','CRITICAL')",
			name="ck_complaint_severity_valid",
		),
		db.CheckConstraint(
			"status IN ('SUBMITTED','UNDER_REVIEW','IN_PROGRESS','RESOLVED','CLOSED')",
			name="ck_complaint_status_valid",
		),
		db.CheckConstraint(
			"last_email_status IS NULL OR last_email_status IN ('SENT','FAILED','RETRY_PENDING')",
			name="ck_complaint_last_email_status",
		),
		db.CheckConstraint(
			"sync_status IS NULL OR sync_status IN ('PENDING','SYNCED','CONFLICT')",
			name="ck_complaint_sync_status",
		),
			db.CheckConstraint(
				"visibility_level IN ('PUBLIC','ANONYMIZED','PRIVATE')",
				name="ck_complaint_visibility",
			),
		db.Index("ix_complaints_user_project", "user_id", "project_id"),
	)

	user = db.relationship("User", back_populates="complaints")
	project = db.relationship("InfrastructureProject", back_populates="complaints")
	images = db.relationship("ComplaintImage", back_populates="complaint", cascade="all, delete-orphan")
	status_history = db.relationship(
		"ComplaintStatusHistory",
		back_populates="complaint",
		order_by="ComplaintStatusHistory.changed_at",
		cascade="all, delete-orphan",
	)
	email_logs = db.relationship(
		"EmailAuditLog",
		back_populates="complaint",
		order_by="EmailAuditLog.sent_at",
		cascade="all, delete-orphan",
	)
	supports = db.relationship(
		"ComplaintSupport",
		back_populates="complaint",
		order_by="ComplaintSupport.created_at",
		cascade="all, delete-orphan",
	)

	@property
	def immutable_fields(self) -> set[str]:
		return {"user_id", "project_id", "created_at"}

	@staticmethod
	def public_query():
		"""Restrict complaints to public-safe, anonymized records."""
		return Complaint.query.filter(
			Complaint.is_public.is_(True),
			Complaint.visibility_level.in_(["PUBLIC", "ANONYMIZED"]),
		)

	def public_payload(self) -> dict:
		area = None
		if self.location_snapshot:
			area = self.location_snapshot.get("location_name") or None
		if not area and self.project and self.project.location_query:
			area = self.project.location_query.location_name
		return {
			"id": str(self.id),
			"project_name": self.project.project_name if self.project else None,
			"issue_type": self.complaint_type,
			"severity": self.severity_level,
			"status": self.status,
			"area": (area or "").split(",")[0].strip() if area else None,
			"created_at": self.created_at,
		}


class ComplaintImage(db.Model):
	__tablename__ = "complaint_images"

	id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
	complaint_id = db.Column(db.String(36), db.ForeignKey("complaints.id"), nullable=False, index=True)
	image_path = db.Column(db.String(500), nullable=False, unique=True)
	image_hash = db.Column(db.String(128), nullable=False, index=True)
	ai_analysis_result = db.Column(db.JSON, nullable=True)
	authenticity_flag = db.Column(db.String(20), nullable=False, default="UNVERIFIABLE", index=True)
	exif_metadata = db.Column(db.JSON, nullable=True)
	uploaded_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

	__table_args__ = (
		db.UniqueConstraint("complaint_id", "image_hash", name="uq_complaint_image_hash"),
		db.CheckConstraint(
			"authenticity_flag IN ('LIKELY_GENUINE','SUSPICIOUS','UNVERIFIABLE')",
			name="ck_complaint_image_authenticity",
		),
	)

	complaint = db.relationship("Complaint", back_populates="images")


class ComplaintStatusHistory(db.Model):
	__tablename__ = "complaint_status_history"

	id = db.Column(db.Integer, primary_key=True)
	complaint_id = db.Column(db.String(36), db.ForeignKey("complaints.id"), nullable=False, index=True)
	previous_status = db.Column(db.String(20), nullable=True)
	new_status = db.Column(db.String(20), nullable=False, index=True)
	remarks = db.Column(db.String(500), nullable=True)
	changed_by = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=True)
	changed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

	__table_args__ = (
		db.CheckConstraint(
			"new_status IN ('SUBMITTED','UNDER_REVIEW','IN_PROGRESS','RESOLVED','CLOSED')",
			name="ck_complaint_status_history_valid",
		),
	)

	complaint = db.relationship("Complaint", back_populates="status_history")
	actor = db.relationship("User")


class ComplaintSupport(db.Model):
	__tablename__ = "complaint_supports"

	id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
	complaint_id = db.Column(db.String(36), db.ForeignKey("complaints.id"), nullable=False, index=True)
	user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False, index=True)
	remark = db.Column(db.String(500), nullable=True)
	created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

	__table_args__ = (
		db.Index("ix_support_complaint_user", "complaint_id", "user_id"),
	)

	complaint = db.relationship("Complaint", back_populates="supports")
	user = db.relationship("User", back_populates="complaint_supports")
	images = db.relationship(
		"ComplaintSupportImage",
		back_populates="support",
		order_by="ComplaintSupportImage.uploaded_at",
		cascade="all, delete-orphan",
	)


class ComplaintSupportImage(db.Model):
	__tablename__ = "complaint_support_images"

	id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
	support_id = db.Column(db.String(36), db.ForeignKey("complaint_supports.id"), nullable=False, index=True)
	image_path = db.Column(db.String(500), nullable=False, unique=True)
	image_hash = db.Column(db.String(128), nullable=False, index=True)
	ai_analysis_result = db.Column(db.JSON, nullable=True)
	authenticity_flag = db.Column(db.String(20), nullable=False, default="UNVERIFIABLE", index=True)
	exif_metadata = db.Column(db.JSON, nullable=True)
	uploaded_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

	__table_args__ = (
		db.UniqueConstraint("support_id", "image_hash", name="uq_support_image_hash"),
		db.CheckConstraint(
			"authenticity_flag IN ('LIKELY_GENUINE','SUSPICIOUS','UNVERIFIABLE')",
			name="ck_support_image_authenticity",
		),
	)

	support = db.relationship("ComplaintSupport", back_populates="images")


class EmailAuditLog(db.Model):
	__tablename__ = "email_audit_logs"

	id = db.Column(db.Integer, primary_key=True)
	complaint_id = db.Column(db.String(36), db.ForeignKey("complaints.id"), nullable=False, index=True)
	sender_email = db.Column(db.String(255), nullable=False)
	recipient_email = db.Column(db.String(255), nullable=False)
	cc_emails = db.Column(db.JSON, nullable=True)
	resolved_user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=True, index=True)
	subject = db.Column(db.String(255), nullable=False)
	email_body_snapshot = db.Column(db.Text, nullable=False)
	attachments_metadata = db.Column(db.JSON, nullable=True)
	sent_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
	delivery_status = db.Column(db.String(20), nullable=False, index=True)
	error_message = db.Column(db.Text, nullable=True)

	__table_args__ = (
		db.CheckConstraint(
			"delivery_status IN ('SENT','FAILED','RETRY_PENDING')",
			name="ck_email_delivery_status",
		),
		db.Index("ix_email_audit_complaint_sent", "complaint_id", "sent_at"),
	)

	complaint = db.relationship("Complaint", back_populates="email_logs")
	resolved_user = db.relationship("User")


class RTIRequest(db.Model):
	__tablename__ = "rti_requests"

	id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
	reference_id = db.Column(db.String(36), nullable=False, unique=True, index=True)
	entity_type = db.Column(db.String(20), nullable=False, index=True)
	entity_id = db.Column(db.String(36), nullable=False, index=True)
	generated_by = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=True, index=True)
	generated_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
	is_public = db.Column(db.Boolean, nullable=False, default=True, index=True)
	visibility_level = db.Column(db.String(20), nullable=False, default="PUBLIC", index=True)
	pdf_path = db.Column(db.String(500), nullable=False)
	pdf_checksum = db.Column(db.String(128), nullable=False)
	hash_algorithm = db.Column(db.String(20), nullable=False, default="sha256")
	extra_metadata = db.Column("metadata", db.JSON, nullable=True)

	__table_args__ = (
		db.CheckConstraint("entity_type IN ('PROJECT','COMPLAINT')", name="ck_rti_entity_type"),
		db.CheckConstraint("visibility_level IN ('PUBLIC','PRIVATE')", name="ck_rti_visibility"),
		db.Index("ix_rti_entity_lookup", "entity_type", "entity_id", "generated_at"),
	)

	logs = db.relationship("RTIAuditLog", back_populates="rti_request", cascade="all, delete-orphan")
	requestor = db.relationship("User")

	@property
	def reference(self) -> str:
		return self.reference_id

	def public_payload(self) -> dict:
		return {
			"reference_id": self.reference_id,
			"entity_type": self.entity_type,
			"entity_id": str(self.entity_id),
			"generated_at": self.generated_at,
		}


class RTIAuditLog(db.Model):
	__tablename__ = "rti_audit_logs"

	id = db.Column(db.Integer, primary_key=True)
	rti_request_id = db.Column(db.String(36), db.ForeignKey("rti_requests.id"), nullable=False, index=True)
	event_type = db.Column(db.String(30), nullable=False, index=True)
	triggered_by = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=True, index=True)
	triggered_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
	ip_address = db.Column(db.String(64), nullable=True)
	user_agent = db.Column(db.String(255), nullable=True)
	notes = db.Column(db.String(500), nullable=True)

	__table_args__ = (
		db.CheckConstraint("event_type IN ('GENERATED','DOWNLOADED')", name="ck_rti_event_type"),
		db.Index("ix_rti_audit_lookup", "event_type", "triggered_at"),
	)

	rti_request = db.relationship("RTIRequest", back_populates="logs")
	actor = db.relationship("User")


class AnalyticsSnapshot(db.Model):
	__tablename__ = "analytics_snapshots"

	id = db.Column(db.Integer, primary_key=True)
	snapshot_type = db.Column(db.String(50), nullable=False, index=True)
	entity_type = db.Column(db.String(30), nullable=True, index=True)
	entity_id = db.Column(db.String(64), nullable=True, index=True)
	payload = db.Column(db.JSON, nullable=False)
	computed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

	__table_args__ = (
		db.Index("ix_analytics_entity", "snapshot_type", "entity_type", "entity_id", "computed_at"),
	)

	@property
	def latest(self) -> dict:
		return self.payload or {}


class SectionDataFetchLog(db.Model):
	__tablename__ = "section_data_fetch_logs"

	id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
	project_id = db.Column(db.String(36), db.ForeignKey("infrastructure_projects.id"), nullable=False, index=True)
	section_name = db.Column(db.String(80), nullable=False, index=True)
	missing_fields = db.Column(db.JSON, nullable=False)
	fetched_payload = db.Column(db.JSON, nullable=False)
	markdown = db.Column(db.Text, nullable=True)
	triggered_by = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=True, index=True)
	notes = db.Column(db.String(255), nullable=True)
	created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

	project = db.relationship("InfrastructureProject")
	user = db.relationship("User")


class BlockchainAnchor(db.Model):
	__tablename__ = "blockchain_anchors"

	id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
	record_type = db.Column(db.String(50), nullable=False, index=True)
	record_id = db.Column(db.String(64), nullable=False, index=True)
	data_hash = db.Column(db.String(128), nullable=False, index=True)
	tx_reference = db.Column(db.String(128), nullable=True)
	status = db.Column(db.String(20), nullable=False, default="PENDING", index=True)
	anchored_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
	extra_metadata = db.Column("metadata", db.JSON, nullable=True)

	__table_args__ = (
		db.Index("ix_anchor_lookup", "record_type", "record_id", "anchored_at"),
	)


class ProjectSnapshot(db.Model):
	__tablename__ = "project_snapshots"

	id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
	project_id = db.Column(db.String(36), db.ForeignKey("infrastructure_projects.id"), nullable=False, index=True)
	image_path = db.Column(db.String(500), nullable=False, unique=True)
	image_hash = db.Column(db.String(128), nullable=False, index=True)
	capture_date = db.Column(db.Date, nullable=False, index=True)
	source_type = db.Column(db.String(20), nullable=False, index=True)
	location_metadata = db.Column(db.JSON, nullable=True)
	created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

	__table_args__ = (
		db.CheckConstraint("source_type IN ('CITIZEN','PUBLIC','OFFICIAL')", name="ck_snapshot_source_type"),
		db.UniqueConstraint("project_id", "capture_date", "image_hash", name="uq_snapshot_unique"),
	)

	project = db.relationship("InfrastructureProject", back_populates="snapshots")


class CorruptionPattern(db.Model):
	__tablename__ = "corruption_patterns"

	id = db.Column(db.Integer, primary_key=True)
	code = db.Column(db.String(80), nullable=False, unique=True, index=True)
	description = db.Column(db.String(500), nullable=False)
	threshold_value = db.Column(db.Float, nullable=False)
	severity_weight = db.Column(db.Integer, nullable=False, default=1)
	metric = db.Column(db.String(80), nullable=False)
	created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

	flags = db.relationship("CorruptionFlag", back_populates="pattern", cascade="all, delete-orphan")


class CorruptionFlag(db.Model):
	__tablename__ = "corruption_flags"

	id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
	pattern_code = db.Column(db.String(80), db.ForeignKey("corruption_patterns.code"), nullable=False, index=True)
	entity_type = db.Column(db.String(30), nullable=False, index=True)
	entity_id = db.Column(db.String(64), nullable=False, index=True)
	risk_score = db.Column(db.Integer, nullable=False, index=True)
	location_key = db.Column(db.String(255), nullable=True, index=True)
	status = db.Column(db.String(20), nullable=False, default="ACTIVE", index=True)
	evidence = db.Column(db.JSON, nullable=False)
	flagged_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
	cleared_at = db.Column(db.DateTime, nullable=True)
	notes = db.Column(db.String(500), nullable=True)

	__table_args__ = (
		db.CheckConstraint("entity_type IN ('CONTRACTOR','DEPARTMENT','PROJECT','REGION','LOCATION')", name="ck_flag_entity_type"),
		db.CheckConstraint("status IN ('ACTIVE','CLEARED','SUPPRESSED')", name="ck_flag_status"),
		db.Index("ix_flag_entity", "entity_type", "entity_id", "status"),
	)

	pattern = db.relationship("CorruptionPattern", back_populates="flags")


class SmartAlert(db.Model):
	__tablename__ = "smart_alerts"

	id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
	alert_type = db.Column(db.String(80), nullable=False, index=True)
	severity = db.Column(db.String(20), nullable=False, default="INFO", index=True)
	message = db.Column(db.String(500), nullable=False)
	entity_type = db.Column(db.String(30), nullable=True, index=True)
	entity_id = db.Column(db.String(64), nullable=True, index=True)
	target_role = db.Column(db.String(80), nullable=True, index=True)
	target_user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=True, index=True)
	dedup_key = db.Column(db.String(150), nullable=False, unique=True)
	status = db.Column(db.String(20), nullable=False, default="OPEN", index=True)
	extra_metadata = db.Column("metadata", db.JSON, nullable=True)
	created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
	acknowledged_at = db.Column(db.DateTime, nullable=True)
	resolved_at = db.Column(db.DateTime, nullable=True)

	__table_args__ = (
		db.CheckConstraint("severity IN ('INFO','MEDIUM','HIGH','CRITICAL')", name="ck_alert_severity"),
		db.CheckConstraint("status IN ('OPEN','ACKED','RESOLVED')", name="ck_alert_status"),
		db.Index("ix_alert_target", "target_role", "status", "severity"),
	)

	target_user = db.relationship("User")


class ModerationEvent(db.Model):
	__tablename__ = "moderation_events"

	id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
	complaint_id = db.Column(db.String(36), db.ForeignKey("complaints.id"), nullable=True, index=True)
	user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=True, index=True)
	event_type = db.Column(db.String(50), nullable=False, index=True)
	notes = db.Column(db.String(500), nullable=True)
	created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

	__table_args__ = (
		db.CheckConstraint("event_type IN ('DUPLICATE_IMAGE','RATE_LIMIT','SPAM_PATTERN','MODERATOR_ACTION')", name="ck_moderation_event"),
	)

	complaint = db.relationship("Complaint")
	user = db.relationship("User")

