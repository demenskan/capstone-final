backend "s3" {
    bucket = "capstone-state"
    key    = "terraform.tfstate"
    region = "us-west-1"
}
