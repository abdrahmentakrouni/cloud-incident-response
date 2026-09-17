# tflint configuration for the incident response pipeline.
# The aws ruleset is bundled; plugin installs stay offline-friendly.

plugin "terraform" {
  enabled = true
  preset  = "recommended"
}

rule "terraform_deprecated_index" {
  enabled = true
}

rule "terraform_unused_declarations" {
  enabled = true
}

rule "terraform_typed_variables" {
  enabled = true
}

rule "terraform_required_version" {
  enabled = false # pinned in versions.tf, >= 1.5.0 is intentional
}
