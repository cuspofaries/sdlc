# =============================================================================
# OPA Security Exceptions Policy
# =============================================================================
# Validates security-exceptions.yaml and provides audit trail.
#
# Rules:
#   deny  — expired exception, missing required fields
#   warn  — exception expiring within 7 days, active exceptions list
#
# Data input: data.exceptions[] (YAML converted to JSON)
# =============================================================================
package sbom

import rego.v1

# Required fields for each exception
exception_required_fields := {"id", "package", "reason", "approved_by", "expires", "ticket"}

# ── DENY: exception with missing required fields ────────────────────────────

deny contains msg if {
	some i, exception in data.exceptions
	some field in exception_required_fields
	not exception[field]
	msg := sprintf("Security exception #%d ('%s') is missing required field '%s'", [i + 1, object.get(exception, "id", "unknown"), field])
}

deny contains msg if {
	some i, exception in data.exceptions
	some field in exception_required_fields
	exception[field] == ""
	msg := sprintf("Security exception #%d ('%s') has empty required field '%s'", [i + 1, object.get(exception, "id", "unknown"), field])
}

# ── DENY: expired exception (defense in depth) ─────────────────────────────
# The trivy-exceptions.sh script already excludes expired CVEs from
# .trivyignore, but OPA catches stale files as a second gate.

deny contains msg if {
	some exception in data.exceptions
	exception.expires != ""
	time.parse_rfc3339_ns(sprintf("%sT00:00:00Z", [exception.expires])) < time.now_ns()
	msg := sprintf("Security exception '%s' (%s) has EXPIRED on %s — remove it or update the expiry date (approved by: %s, ticket: %s)", [exception.id, exception.package, exception.expires, exception.approved_by, exception.ticket])
}

# ── WARN: exception expiring within 7 days ──────────────────────────────────

warn contains msg if {
	some exception in data.exceptions
	exception.expires != ""
	expires_ns := time.parse_rfc3339_ns(sprintf("%sT00:00:00Z", [exception.expires]))
	now := time.now_ns()
	seven_days_ns := 7 * 24 * 60 * 60 * 1000000000
	expires_ns >= now
	expires_ns < now + seven_days_ns
	msg := sprintf("Security exception '%s' (%s) expires in less than 7 days (%s) — renew or remediate (ticket: %s)", [exception.id, exception.package, exception.expires, exception.ticket])
}

# ── WARN: list all active exceptions (audit trail) ──────────────────────────
# Every pipeline run shows active exceptions so auditors can see them in logs.

warn contains msg if {
	some exception in data.exceptions
	exception.expires != ""
	time.parse_rfc3339_ns(sprintf("%sT00:00:00Z", [exception.expires])) >= time.now_ns()
	msg := sprintf("Active security exception: '%s' (%s) — reason: %s, approved by: %s, expires: %s, ticket: %s", [exception.id, exception.package, exception.reason, exception.approved_by, exception.expires, exception.ticket])
}
