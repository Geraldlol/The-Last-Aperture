# V-010 — VULNERABLE fixture. NOT RUNNABLE. Written from scratch.
#
# Bug class (exactly one): encryption at rest explicitly disabled on a managed
# store that supports disabling it.
# Lens: cloud-and-iac / topic `encryption-at-rest-configuration`
# Expected: High, CWE-311
#
# `storage_encrypted = false` on an RDS instance is not a default and not an
# omission — it is the setting written out, which is what the owning lens's
# severity row requires. The replica inherits nothing: an unencrypted primary
# cannot have an encrypted replica, so the second resource records the blast
# radius rather than a second finding.
#
# Deliberately NOT in this file, so the fixture carries one bug class only:
# `publicly_accessible` is left at its default, there is no security group, no
# ingress rule, no wildcard IAM statement, no public bucket and no missing
# metadata_options block.
#
# NOT RUNNABLE: no provider block, no backend, no region, no variables file and no
# credentials. `terraform init` has nothing to initialise, and the password below
# is a literal placeholder that is not a password — see fixtures/README.md on why
# nothing here is allowed to look like a live secret.

resource "aws_db_subnet_group" "reporting" {
  name       = "reporting"
  subnet_ids = ["subnet-1111111111111111a", "subnet-2222222222222222b"]
}

resource "aws_db_instance" "reporting" {
  identifier     = "reporting"
  engine         = "postgres"
  engine_version = "16"
  instance_class = "db.t4g.medium"

  allocated_storage = 200
  db_subnet_group_name = aws_db_subnet_group.reporting.name

  username = "reporting_app"
  # Placeholder, not a credential: the string states its own invalidity and no
  # deployment reads this file.
  password = "REPLACE-ME-BEFORE-ANY-USE"

  # --- the finding -----------------------------------------------------------
  # The setting is present and it is false. Every page of this database's storage
  # and every automated snapshot taken from it is written unencrypted.
  storage_encrypted = false
  # --- end of the finding ----------------------------------------------------

  backup_retention_period = 7
  skip_final_snapshot     = false
  deletion_protection     = true

  tags = {
    Name = "reporting"
  }
}

# The consequence, stated as configuration rather than as prose: a read replica of
# an unencrypted primary is unencrypted, and the copy lives in a second region.
resource "aws_db_instance" "reporting_replica" {
  identifier          = "reporting-replica"
  replicate_source_db = aws_db_instance.reporting.identifier
  instance_class      = "db.t4g.medium"

  storage_encrypted = false

  skip_final_snapshot = true

  tags = {
    Name = "reporting-replica"
  }
}
