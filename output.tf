output "docker-server" {
  value = aws_instance.Docker.private_ip
}

output "nexus-server" {
  value = aws_instance.nexus.public_ip
}
output "sonar-server" {
  value = aws_instance.sonarqube_instance.public_ip
}

output "ansible-server" {
  value = aws_instance.ansible-server.public_ip
}
output "jenkins-server" {
  value = aws_instance.Jenkins.public_ip
}
output "bastion-server" {
  value = aws_instance.Bastion.public_ip
}