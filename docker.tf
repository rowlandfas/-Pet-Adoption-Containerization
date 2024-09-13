locals {
  docker_user_data = <<-EOF
#!/bin/bash
sudo yum update -y
sudo yum upgrade
sudo yum install -y yum-utils
sudo yum config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
sudo yum install docker-ce -y
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker ec2-user   
sudo mkdir /opt/docker
sudo chown -R ec2-user:ec2-user /opt/
cd /opt
sudo chmod 600 /opt/docker
curl -Ls https://download.newrelic.com/install/newrelic-cli/scripts/install.sh | bash && sudo NEW_RELIC_API_KEY=NRAK-R1E391EHZ2VM7H6RNKU3IIYKPT7 NEW_RELIC_ACCOUNT_ID=4666188 NEW_RELIC_REGION=EU /usr/local/bin/newrelic install -y
sudo hostnamectl set-hostname Docker
EOF
}
