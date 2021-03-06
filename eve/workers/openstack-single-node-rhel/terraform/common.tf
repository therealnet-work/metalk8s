resource "random_string" "current" {
  length  = 5
  special = false
}

locals {
  prefix = "metalk8s-${random_string.current.result}"
}

variable "rhsm_username" {
  type = string
}

variable "rhsm_password" {
  type = string
}
