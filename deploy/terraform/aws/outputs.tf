output "public_ip" {
  description = "Static public IP of the VPN server. Point your domain's A record here."
  value       = aws_eip.vpn.public_ip
}

output "dashboard_url" {
  description = "Web dashboard (ready a few minutes after apply, once cloud-init finishes)."
  value       = "https://${local.domain}"
}

output "wireguard_endpoint" {
  value = "${local.domain}:${var.wg_port}"
}

output "admin_username" {
  value = var.admin_username
}

output "admin_password" {
  description = "Initial admin password - change it after first sign-in. Read with: terraform output -raw admin_password"
  value       = random_password.admin.result
  sensitive   = true
}

output "ssh_command" {
  value = length(var.ssh_allowed_cidrs) > 0 && var.ssh_public_key != "" ? "ssh ubuntu@${aws_eip.vpn.public_ip}" : "SSH is closed (set ssh_public_key and ssh_allowed_cidrs to open it)"
}
