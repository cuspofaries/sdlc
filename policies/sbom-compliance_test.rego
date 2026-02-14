# =============================================================================
# OPA Unit Tests for SBOM Compliance Policies
# =============================================================================
# Run with: opa test policies/ -v
# =============================================================================
package sbom_test

import rego.v1

import data.sbom

# ----- Helper: minimal valid SBOM -----

valid_sbom := {
	"specVersion": "1.5",
	"bomFormat": "CycloneDX",
	"metadata": {
		"timestamp": "2025-01-01T00:00:00Z",
		"tools": [{"name": "trivy"}],
		"component": {
			"supplier": {"name": "test"},
		},
	},
	"components": [{
		"name": "express",
		"version": "4.18.2",
		"type": "library",
		"purl": "pkg:npm/express@4.18.2",
		"licenses": [{"license": {"id": "MIT"}}],
	}],
}

# ----- DENY: blocked packages -----

test_deny_blocked_package if {
	inp := json.patch(valid_sbom, [{"op": "add", "path": "/components/1", "value": {
		"name": "event-stream",
		"version": "3.3.6",
		"type": "library",
		"purl": "pkg:npm/event-stream@3.3.6",
	}}])
	result := sbom.deny with input as inp
	count([m | some m in result; contains(m, "BLOCKED package")]) > 0
}

test_no_deny_safe_package if {
	result := sbom.deny with input as valid_sbom
	count([m | some m in result; contains(m, "BLOCKED")]) == 0
}

# ----- DENY: missing version -----

test_deny_missing_version if {
	inp := json.patch(valid_sbom, [{"op": "add", "path": "/components/1", "value": {
		"name": "mystery-lib",
		"type": "library",
		"purl": "pkg:npm/mystery-lib",
	}}])
	result := sbom.deny with input as inp
	count([m | some m in result; contains(m, "no version")]) > 0
}

test_no_deny_file_without_version if {
	inp := json.patch(valid_sbom, [{"op": "add", "path": "/components/1", "value": {
		"name": "/usr/bin/curl",
		"type": "file",
	}}])
	result := sbom.deny with input as inp
	count([m | some m in result; contains(m, "no version")]) == 0
}

test_no_deny_os_without_version if {
	inp := json.patch(valid_sbom, [{"op": "add", "path": "/components/1", "value": {
		"name": "alpine",
		"type": "operating-system",
	}}])
	result := sbom.deny with input as inp
	count([m | some m in result; contains(m, "no version")]) == 0
}

# ----- DENY: missing purl -----

test_deny_library_without_purl if {
	inp := json.patch(valid_sbom, [{"op": "replace", "path": "/components/0", "value": {
		"name": "express",
		"version": "4.18.2",
		"type": "library",
		"licenses": [{"license": {"id": "MIT"}}],
	}}])
	result := sbom.deny with input as inp
	count([m | some m in result; contains(m, "Package URL")]) > 0
}

# ----- DENY: missing timestamp -----

test_deny_missing_timestamp if {
	inp := json.remove(valid_sbom, ["/metadata/timestamp"])
	result := sbom.deny with input as inp
	count([m | some m in result; contains(m, "timestamp")]) > 0
}

# ----- DENY: zero components -----

test_deny_zero_components if {
	inp := json.patch(valid_sbom, [{"op": "replace", "path": "/components", "value": []}])
	result := sbom.deny with input as inp
	count([m | some m in result; contains(m, "zero components")]) > 0
}

# ----- DENY: copyleft in app library -----

test_deny_copyleft_in_app_library if {
	inp := json.patch(valid_sbom, [{"op": "add", "path": "/components/1", "value": {
		"name": "gpl-lib",
		"version": "1.0.0",
		"type": "library",
		"purl": "pkg:npm/gpl-lib@1.0.0",
		"licenses": [{"license": {"id": "GPL-3.0-only"}}],
	}}])
	result := sbom.deny with input as inp
	count([m | some m in result; contains(m, "Copyleft")]) > 0
}

test_no_deny_copyleft_in_os_package if {
	inp := json.patch(valid_sbom, [{"op": "add", "path": "/components/1", "value": {
		"name": "busybox",
		"version": "1.36.1",
		"type": "library",
		"purl": "pkg:apk/alpine/busybox@1.36.1",
		"licenses": [{"license": {"id": "GPL-2.0-only"}}],
	}}])
	result := sbom.deny with input as inp
	count([m | some m in result; contains(m, "Copyleft")]) == 0
}

# ----- DENY: missing tools -----

test_deny_missing_tools if {
	inp := json.remove(valid_sbom, ["/metadata/tools"])
	result := sbom.deny with input as inp
	count([m | some m in result; contains(m, "metadata.tools")]) > 0
}

# ----- DENY: outdated spec version -----

test_deny_old_spec_version if {
	inp := json.patch(valid_sbom, [{"op": "replace", "path": "/specVersion", "value": "1.2"}])
	result := sbom.deny with input as inp
	count([m | some m in result; contains(m, "too old")]) > 0
}

test_no_deny_current_spec_version if {
	result := sbom.deny with input as valid_sbom
	count([m | some m in result; contains(m, "too old")]) == 0
}

# ----- WARN: copyleft in OS package -----

test_warn_copyleft_in_os_package if {
	inp := json.patch(valid_sbom, [{"op": "add", "path": "/components/1", "value": {
		"name": "busybox",
		"version": "1.36.1",
		"type": "library",
		"purl": "pkg:apk/alpine/busybox@1.36.1",
		"licenses": [{"license": {"id": "GPL-2.0-only"}}],
	}}])
	result := sbom.warn with input as inp
	count([m | some m in result; contains(m, "OS package")]) > 0
}

# ----- WARN: unapproved license -----

test_warn_unapproved_license if {
	inp := json.patch(valid_sbom, [{"op": "add", "path": "/components/1", "value": {
		"name": "exotic-lib",
		"version": "1.0.0",
		"type": "library",
		"purl": "pkg:npm/exotic-lib@1.0.0",
		"licenses": [{"license": {"id": "WTFPL"}}],
	}}])
	result := sbom.warn with input as inp
	count([m | some m in result; contains(m, "Unapproved license")]) > 0
}

test_no_warn_approved_license if {
	result := sbom.warn with input as valid_sbom
	count([m | some m in result; contains(m, "Unapproved license")]) == 0
}

# ----- WARN: missing license -----

test_warn_missing_license if {
	inp := json.patch(valid_sbom, [{"op": "add", "path": "/components/1", "value": {
		"name": "no-license-lib",
		"version": "1.0.0",
		"type": "library",
		"purl": "pkg:npm/no-license-lib@1.0.0",
	}}])
	result := sbom.warn with input as inp
	count([m | some m in result; contains(m, "No license info")]) > 0
}

# ----- WARN: deprecated package -----

test_warn_deprecated_package if {
	inp := json.patch(valid_sbom, [{"op": "add", "path": "/components/1", "value": {
		"name": "request",
		"version": "2.88.2",
		"type": "library",
		"purl": "pkg:npm/request@2.88.2",
	}}])
	result := sbom.warn with input as inp
	count([m | some m in result; contains(m, "Deprecated")]) > 0
}

# ----- WARN: high component count -----

test_warn_high_component_count if {
	many_components := [c |
		some i in numbers.range(1, 501)
		c := {
			"name": sprintf("pkg-%d", [i]),
			"version": "1.0.0",
			"type": "library",
			"purl": sprintf("pkg:npm/pkg-%d@1.0.0", [i]),
			"licenses": [{"license": {"id": "MIT"}}],
		}
	]
	inp := json.patch(valid_sbom, [{"op": "replace", "path": "/components", "value": many_components}])
	result := sbom.warn with input as inp
	count([m | some m in result; contains(m, "High component count")]) > 0
}

# ----- VALID SBOM: no denies -----

test_valid_sbom_no_denies if {
	result := sbom.deny with input as valid_sbom
	count(result) == 0
}
