variable "aws_region" {
  description = "AWS region to deploy into. Pick one close to your users."
  type        = string
  default     = "us-east-1"
}

variable "name" {
  description = "Name prefix for all resources."
  type        = string
  default     = "nimbusvpn"
}

variable "instance_type" {
  description = "EC2 instance type. t3.micro comfortably serves dozens of peers."
  type        = string
  default     = "t3.micro"
}

variable "root_volume_gb" {
  description = "Size of the encrypted root volume."
  type        = number
  default     = 16
}

variable "domain" {
  description = "DNS name for the VPN (create an A record to the output IP). Empty = <ip>.sslip.io."
  type        = string
  default     = ""

  validation {
    condition     = var.domain == "" || can(regex("^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$", var.domain))
    error_message = "domain must be a valid DNS name."
  }
}

variable "wg_port" {
  description = "UDP port WireGuard listens on."
  type        = number
  default     = 51820
}

variable "ssh_public_key" {
  description = "Optional SSH public key for the ubuntu user. Leave empty to disable SSH key setup."
  type        = string
  default     = ""
}

variable "ssh_allowed_cidrs" {
  description = "CIDRs allowed to reach SSH (e.g. [\"203.0.113.4/32\"]). Empty = SSH closed."
  type        = list(string)
  default     = []
}

variable "repo_url" {
  description = "Git URL the instance clones NimbusVPN from."
  type        = string
  default     = "https://github.com/purnendukumarghosh/NimbusVPN.git"
}

variable "repo_ref" {
  description = "Branch or tag to deploy."
  type        = string
  default     = "main"
}

variable "admin_username" {
  description = "Username of the first dashboard admin."
  type        = string
  default     = "admin"
}
