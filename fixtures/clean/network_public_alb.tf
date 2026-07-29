############################################################################
# C-007 — clean fixture. Expected findings at Low or above: ZERO.
#
# Why this pattern-matches as vulnerable:
#   `cidr_blocks = ["0.0.0.0/0"]` appears three times, and one of the hits is
#   eleven lines above `from_port = 22`. A grep for the CIDR lands inside a
#   resource block that also mentions SSH, which is the textbook "SSH open to
#   the world" screenshot. A second decoy sits at the bottom: an RDS instance
#   whose subnet group is named `public`.
#
# Why it is not a finding:
#   Every ingress `0.0.0.0/0` here is scoped to 443 or 80 on a security group
#   that is attached, in this same file, to an internet-facing ALB — which is
#   the intended design and not an exposure. The SSH rule beside it takes
#   `security_groups = [aws_security_group.bastion.id]` and no CIDR at all, so
#   port 22 is reachable only from the bastion group. The egress `0.0.0.0/0` is
#   the provider default and near-universal. `::/0` is declared alongside
#   `0.0.0.0/0` on the web ports, so the IPv6 half is not silently missing.
#   The database sets `publicly_accessible = false`, which is what decides
#   internet reachability — a subnet group's name decides nothing.
#
# False-positive entries exercised:
#   cloud-and-iac (6)  `0.0.0.0/0` reported as exposure; the sensitive-port list
#                      and the all-ports forms are what survive, and the group
#                      IS referenced by a resource in this repository so the
#                      not-attached downgrade does not apply either
############################################################################

variable "vpc_id" {
  type = string
}

variable "public_subnet_ids" {
  type = list(string)
}

variable "private_subnet_ids" {
  type = list(string)
}

# --------------------------------------------------------------------------
# The bastion group. Named first so the reference below resolves.
# --------------------------------------------------------------------------
resource "aws_security_group" "bastion" {
  name        = "bastion-ssh"
  description = "Session-Manager-preferred bastion; SSH retained for break-glass"
  vpc_id      = var.vpc_id

  # No CIDR ingress at all. Access arrives via SSM, which needs no inbound rule.
  egress {
    description = "outbound to the VPC only"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/16"]
  }
}

# --------------------------------------------------------------------------
# The public ALB group. This is the one carrying 0.0.0.0/0, and it is correct.
# --------------------------------------------------------------------------
resource "aws_security_group" "alb" {
  name        = "public-alb"
  description = "Internet-facing ALB: TLS in, HTTP redirect in, app out"
  vpc_id      = var.vpc_id

  ingress {
    description      = "TLS from the internet — this is a public load balancer"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  ingress {
    description      = "HTTP, redirected to 443 by the listener rule below"
    from_port        = 80
    to_port          = 80
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  # The decoy. Port 22 in the same resource block as three 0.0.0.0/0 lines —
  # and reachable only from the bastion group, never from a CIDR.
  ingress {
    description     = "break-glass SSH to the LB host class, bastion only"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion.id]
  }

  egress {
    description = "to the app tier; provider default, retained deliberately"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --------------------------------------------------------------------------
# The attachment. This is what makes the group's exposure intentional rather
# than latent, and it is in the same repository — which is the discriminator
# false positive 6 names.
# --------------------------------------------------------------------------
resource "aws_lb" "public" {
  name                       = "public-edge"
  load_balancer_type         = "application"
  internal                   = false
  security_groups            = [aws_security_group.alb.id]
  subnets                    = var.public_subnet_ids
  drop_invalid_header_fields = true
  enable_deletion_protection = true
}

resource "aws_lb_listener" "redirect" {
  load_balancer_arn = aws_lb.public.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# --------------------------------------------------------------------------
# Second decoy: reads as the exposed-database finding, is not one.
# --------------------------------------------------------------------------
resource "aws_db_subnet_group" "public_named" {
  # The name is historical and misleading. The subnet ids are the private ones.
  name       = "app-public-subnet-group"
  subnet_ids = var.private_subnet_ids
}

resource "aws_db_instance" "app" {
  identifier     = "app-primary"
  engine         = "postgres"
  engine_version = "16.4"
  instance_class = "db.t4g.medium"

  db_subnet_group_name   = aws_db_subnet_group.public_named.name
  vpc_security_group_ids = [aws_security_group.alb.id]

  # This is the field that decides internet reachability.
  publicly_accessible = false

  # Not a missing-encryption case: encryption is on with a customer-managed key.
  storage_encrypted = true
  kms_key_id        = "arn:aws:kms:us-east-1:111122223333:key/1a2b3c4d-5e6f-7081-92a3-b4c5d6e7f809"

  iam_database_authentication_enabled = true
  auto_minor_version_upgrade          = true
  deletion_protection                 = true
  skip_final_snapshot                 = false
  final_snapshot_identifier           = "app-primary-final"
}
