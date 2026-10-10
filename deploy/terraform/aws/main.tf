terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "NimbusVPN"
      ManagedBy = "terraform"
    }
  }
}

data "aws_vpc" "default" {
  default = true
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Allocated before the instance so its address is known at boot (no IP change race).
resource "aws_eip" "vpn" {
  domain = "vpc"
  tags   = { Name = "${var.name}-ip" }
}

locals {
  domain = var.domain != "" ? var.domain : "${replace(aws_eip.vpn.public_ip, ".", "-")}.sslip.io"
}

resource "random_password" "admin" {
  length  = 24
  special = false
}

resource "aws_security_group" "vpn" {
  name_prefix = "${var.name}-"
  description = "NimbusVPN: WireGuard, HTTPS dashboard, optional SSH"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description      = "WireGuard"
    from_port        = var.wg_port
    to_port          = var.wg_port
    protocol         = "udp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  ingress {
    description      = "HTTPS dashboard"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  ingress {
    description      = "HTTP/3 dashboard"
    from_port        = 443
    to_port          = 443
    protocol         = "udp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  ingress {
    description      = "HTTP (ACME challenge + redirect to HTTPS)"
    from_port        = 80
    to_port          = 80
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  dynamic "ingress" {
    for_each = length(var.ssh_allowed_cidrs) > 0 ? [1] : []
    content {
      description = "SSH (restricted)"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = var.ssh_allowed_cidrs
    }
  }

  egress {
    description      = "All outbound (VPN client traffic egresses here)"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_key_pair" "admin" {
  count      = var.ssh_public_key == "" ? 0 : 1
  key_name   = "${var.name}-admin"
  public_key = var.ssh_public_key
}

resource "aws_instance" "vpn" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  vpc_security_group_ids = [aws_security_group.vpn.id]
  key_name               = var.ssh_public_key == "" ? null : aws_key_pair.admin[0].key_name

  # IMDSv2 only, with a hop limit of 1 so containers (one hop away) cannot read
  # instance credentials. VPN clients are additionally blocked from 169.254.0.0/16.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = var.root_volume_gb
    encrypted   = true
  }

  user_data = templatefile("${path.module}/cloud-init.yaml.tftpl", {
    repo_url       = var.repo_url
    repo_ref       = var.repo_ref
    domain         = local.domain
    wg_port        = var.wg_port
    admin_username = var.admin_username
    admin_password = random_password.admin.result
  })
  user_data_replace_on_change = true

  tags = { Name = var.name }

  lifecycle {
    ignore_changes = [ami]
  }
}

resource "aws_eip_association" "vpn" {
  instance_id   = aws_instance.vpn.id
  allocation_id = aws_eip.vpn.id
}
