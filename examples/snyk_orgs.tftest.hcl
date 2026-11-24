# Offline tests for the region => Snyk org map in examples/main.tf (`terraform test`, AWS provider mocked,
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

run "rejects_an_empty_map" {
  command = plan

  variables {
    snyk_orgs = {}
  }

  expect_failures = [var.snyk_orgs]
}
