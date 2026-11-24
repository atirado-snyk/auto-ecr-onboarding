.PHONY: test tf-validate tf-test check scan aws-whoami

MODULE := terraform/modules/snyk-ecr-role

test:            ## unit tests (no network, no credentials)
	uv run python -m unittest discover -s tests -v

tf-validate:     ## terraform fmt (all roots) + validate the module (no credentials needed)
	terraform fmt -check -diff -recursive .
	terraform -chdir=$(MODULE) init -backend=false -input=false >/dev/null
	terraform -chdir=$(MODULE) validate
	bash -n examples/sandbox/e2e.sh

tf-test:         ## terraform test for the example's region => org map (AWS provider mocked, no credentials)
	terraform -chdir=examples init -backend=false -input=false >/dev/null
	terraform -chdir=examples test

check: test tf-validate tf-test

scan:            ## Snyk Code (Python) and Snyk IaC (Terraform); needs `snyk auth`
	snyk code test .
	snyk iac test terraform examples

aws-whoami:      ## read-only: which AWS account/identity will Terraform use?
	aws sts get-caller-identity
