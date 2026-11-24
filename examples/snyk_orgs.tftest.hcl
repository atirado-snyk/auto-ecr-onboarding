# Offline tests for the org inputs of examples/main.tf (the region => Snyk org map and the profiles-mode list) (`terraform test`, AWS provider mocked,
# no credentials). They cover the inputs only; the module's trust policy is computed by the provider.

mock_provider "aws" {
  # The mocked policy documents would otherwise return random strings, which the role rejects as JSON.
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
}

variables {
  snyk_aws_principal = "arn:aws:iam::123456789012:user/example"
}

run "one_region" {
  command = plan

  variables {
    snyk_orgs = { "ap-southeast-2" = "11111111-1111-1111-1111-111111111111" }
  }

  assert {
    condition     = output.snyk_orgs["ap-southeast-2"] == "11111111-1111-1111-1111-111111111111"
    error_message = "The single-region path should plan with one org."
  }
}

run "second_region_shares_the_role" {
  command = plan

  variables {
    snyk_orgs = {
      "ap-southeast-2" = "11111111-1111-1111-1111-111111111111"
      "us-east-1"      = "22222222-2222-2222-2222-222222222222"
    }
  }

  assert {
    condition     = length(output.snyk_orgs) == 2
    error_message = "Two regions of one account should plan against the same module call."
  }
}

run "rejects_the_same_org_in_two_regions" {
  command = plan

  variables {
    snyk_orgs = {
      "ap-southeast-2" = "11111111-1111-1111-1111-111111111111"
      "us-east-1"      = "11111111-1111-1111-1111-111111111111"
    }
  }

  expect_failures = [var.snyk_orgs]
}

run "rejects_keys_that_are_not_regions" {
  command = plan

  variables {
    snyk_orgs = { "prod" = "11111111-1111-1111-1111-111111111111" }
  }

  expect_failures = [var.snyk_orgs]
}

# Both inputs empty: snyk_profile_orgs defaults to [], so this is also "no org at all".
run "rejects_an_empty_map" {
  command = plan

  variables {
    snyk_orgs = {}
  }

  expect_failures = [output.trusted_org_ids]
}

# Feature 002: orgs in profiles mode, listed without regions.
run "profiles_mode_orgs_only" {
  command = plan

  variables {
    snyk_profile_orgs = ["33333333-3333-3333-3333-333333333333"]
  }

  assert {
    condition     = output.trusted_org_ids == tolist(["33333333-3333-3333-3333-333333333333"])
    error_message = "A profiles-mode org should be trusted without a region key."
  }

  assert {
    condition     = length(output.snyk_orgs) == 0
    error_message = "snyk_orgs should be optional when snyk_profile_orgs lists an org."
  }
}

run "an_org_in_both_inputs_is_trusted_once" {
  command = plan

  variables {
    snyk_orgs         = { "ap-southeast-2" = "11111111-1111-1111-1111-111111111111" }
    snyk_profile_orgs = ["33333333-3333-3333-3333-333333333333", "11111111-1111-1111-1111-111111111111"]
  }

  assert {
    condition     = output.trusted_org_ids == tolist(["11111111-1111-1111-1111-111111111111", "33333333-3333-3333-3333-333333333333"])
    error_message = "Each org should be trusted once, whichever input lists it."
  }
}

run "default_mode_inputs_trust_what_they_always_did" {
  command = plan

  variables {
    snyk_orgs = {
      "ap-southeast-2" = "22222222-2222-2222-2222-222222222222"
      "us-east-1"      = "11111111-1111-1111-1111-111111111111"
    }
  }

  assert {
    condition     = output.trusted_org_ids == tolist(["11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"])
    error_message = "Default-mode orgs alone should be trusted exactly as listed (FR-017)."
  }
}

run "rejects_a_profiles_mode_org_that_is_not_a_uuid" {
  command = plan

  variables {
    snyk_profile_orgs = ["prod"]
  }

  expect_failures = [var.snyk_profile_orgs]
}

run "rejects_a_profiles_mode_org_listed_twice" {
  command = plan

  variables {
    snyk_profile_orgs = ["33333333-3333-3333-3333-333333333333", "33333333-3333-3333-3333-333333333333"]
  }

  expect_failures = [var.snyk_profile_orgs]
}
