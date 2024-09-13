provider "aws" {
  region  = "eu-west-2"
  profile = "default"

  default_tags {
    tags = {
      Environment = "Dev"
      Project     = "petadoption"
    }
  }
 }