# =============================================================================
# SBOM Compliance Policies
# =============================================================================
# Evaluate with:
#   opa eval -d policies/ -i sbom.json 'data.sbom.deny'
#   opa eval -d policies/ -i sbom.json 'data.sbom.warn'
#   opa eval -d policies/ -i sbom.json 'data.sbom.stats'
# =============================================================================
package sbom

import rego.v1

# ----- Configuration -----

approved_licenses := {
	"MIT",
	"Apache-2.0",
	"BSD-2-Clause",
	"BSD-3-Clause",
	"ISC",
	"MPL-2.0",
	"0BSD",
	"Unlicense",
	"Python-2.0",
	"PSF-2.0",
}

# Packages known to be problematic (example blocklist)
blocked_packages := {
	"event-stream",    # Known supply chain attack
	"ua-parser-js",    # Compromised versions existed
	"colors",          # Sabotaged by maintainer
	"faker",           # Sabotaged by maintainer
}

# ----- DENY rules (blocking — fail the pipeline) -----

# Deny components without version (except system files)
deny contains msg if {
	some component in input.components
	not component.version
	component.type != "file"  # Exclude system files which don't have versions
	msg := sprintf("Component '%s' (type: %s) has no version specified", [component.name, component.type])
}

# Deny components without a package URL
deny contains msg if {
	some component in input.components
	not component.purl
	component.type == "library"
	msg := sprintf("Library '%s@%s' has no Package URL (purl)", [component.name, component.version])
}

# Deny blocked packages
deny contains msg if {
	some component in input.components
	component.name in blocked_packages
	msg := sprintf("BLOCKED package detected: '%s@%s' — known supply chain risk", [component.name, component.version])
}

# Deny if SBOM has no metadata timestamp
deny contains msg if {
	not input.metadata.timestamp
	msg := "SBOM is missing metadata.timestamp — cannot verify freshness"
}

# Deny if SBOM has zero components (empty/broken generation)
deny contains msg if {
	count(input.components) == 0
	msg := "SBOM contains zero components — generation likely failed"
}

# Deny copyleft licenses in production builds (strong copyleft only)
copyleft_licenses := {
	"GPL-2.0-only",
	"GPL-2.0-or-later",
	"GPL-3.0-only",
	"GPL-3.0-or-later",
	"AGPL-3.0-only",
	"AGPL-3.0-or-later",
	"SSPL-1.0",
	"EUPL-1.2",
}

deny contains msg if {
	some component in input.components
	some license_entry in component.licenses
	license_id := license_entry.license.id
	license_id != null
	license_id in copyleft_licenses
	msg := sprintf("Copyleft license '%s' in component '%s@%s' — incompatible with proprietary distribution", [license_id, component.name, component.version])
}

# Deny SBOM without a tool reference (cannot verify how it was generated)
deny contains msg if {
	not input.metadata.tools
	msg := "SBOM has no metadata.tools — cannot verify generation method"
}

# Deny SBOM with an outdated spec version (< 1.4 lacks critical fields)
deny contains msg if {
	spec := input.specVersion
	spec != null
	versions_before_1_4 := {"1.0", "1.1", "1.2", "1.3"}
	spec in versions_before_1_4
	msg := sprintf("SBOM spec version '%s' is too old — minimum 1.4 required for supply chain compliance", [spec])
}

# ----- WARN rules (advisory — don't fail, but flag) -----

# Warn on unapproved licenses
warn contains msg if {
	some component in input.components
	some license_entry in component.licenses
	license_id := license_entry.license.id
	license_id != null
	not license_id in approved_licenses
	not license_id in copyleft_licenses  # Already caught by deny
	msg := sprintf("Unapproved license '%s' in component '%s@%s'", [license_id, component.name, component.version])
}

# Warn on components without license info
warn contains msg if {
	some component in input.components
	component.type == "library"
	not component.licenses
	msg := sprintf("No license info for '%s@%s'", [component.name, component.version])
}

# Warn if too many components (possible bloat / unnecessary deps)
warn contains msg if {
	count(input.components) > 500
	msg := sprintf("High component count: %d — consider dependency cleanup", [count(input.components)])
}

# Warn on components with known deprecated/abandoned status
deprecated_packages := {
	"request",       # Deprecated since 2020
	"nomnom",        # Abandoned
	"istanbul",      # Replaced by nyc
	"jade",          # Renamed to pug
	"github",        # Replaced by @octokit/rest
	"querystring",   # Node.js built-in URLSearchParams preferred
}

warn contains msg if {
	some component in input.components
	component.name in deprecated_packages
	msg := sprintf("Deprecated package '%s@%s' — consider replacement", [component.name, component.version])
}

# Warn if SBOM has no supplier/manufacturer metadata
warn contains msg if {
	not input.metadata.component.supplier
	not input.metadata.component.publisher
	msg := "SBOM has no supplier/publisher metadata — traceability reduced"
}

# ----- STATS (informational) -----

stats := {
	"total_components": count(input.components),
	"libraries": count([c | some c in input.components; c.type == "library"]),
	"os_packages": count([c | some c in input.components; c.type == "operating-system"]),
	"with_version": count([c | some c in input.components; c.version]),
	"with_purl": count([c | some c in input.components; c.purl]),
	"with_license": count([c | some c in input.components; c.licenses]),
	"format": input.bomFormat,
	"spec_version": input.specVersion,
}
