locals {
  name = "rowland"
}

terraform {
  backend "s3" {
    bucket         = "chworkspaces3"
    dynamodb_table = "chworkspacedb"
    key            = "row/terraform.tfstate"
    encrypt        = true
    profile        = "default"
    region         = "eu-west-2"
  }
}

# create vpc
resource "aws_vpc" "vpc" {
  cidr_block       = var.cidr
  instance_tenancy = "default"

  tags = {
    Name = "${local.name}-vpc"
  }
}

# create public subnet 1
resource "aws_subnet" "pub_sub1" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.public_subnet_1
  availability_zone = "eu-west-2a"

  tags = {
    Name = "${local.name}-pub_sub1"
  }
}

# create public subnet 2
resource "aws_subnet" "pub_sub2" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.public_subnet_2
  availability_zone = "eu-west-2b"

  tags = {
    Name = "${local.name}-pub_sub2"
  }
}

# create private subnet 1
resource "aws_subnet" "pri_sub1" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.private_subnet_1
  availability_zone = "eu-west-2a"

  tags = {
    Name = "${local.name}-pri_sub1"
  }
}

# create private subnet 2
resource "aws_subnet" "pri_sub2" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.private_subnet_2
  availability_zone = "eu-west-2b"

  tags = {
    Name = "${local.name}-pri_sub2"
  }
}

# create internet gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id

  tags = {
    Name = "${local.name}-igw"
  }
}

# create nat gateway
resource "aws_nat_gateway" "ngw" {
  allocation_id = aws_eip.eip.id
  subnet_id     = aws_subnet.pub_sub1.id

  tags = {
    Name = "${local.name}-ngw"
  }
}

# create elastic ip
resource "aws_eip" "eip" {
  domain = "vpc"

  tags = {
    Name = "${local.name}-eip"
  }
}

// Create route tabble for public subnets
resource "aws_route_table" "pub_rt" {
  vpc_id = aws_vpc.vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = {
    Name = "${local.name}-pub_rt"
  }
}

// Create route tabble for private subnets
resource "aws_route_table" "pri_rt" {
  vpc_id = aws_vpc.vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_nat_gateway.ngw.id
  }
  tags = {
    Name = "${local.name}-pri_rt"
  }
}

// Creating route table association for public_subnet_1
resource "aws_route_table_association" "ass-public_subnet_1" {
  subnet_id      = aws_subnet.pub_sub1.id
  route_table_id = aws_route_table.pub_rt.id
}

// Creating route table association for public_subnet_2
resource "aws_route_table_association" "ass-public_subnet_2" {
  subnet_id      = aws_subnet.pub_sub2.id
  route_table_id = aws_route_table.pub_rt.id
}

// Creating route table association for private_subnet_1
resource "aws_route_table_association" "ass-private_subnet_1" {
  subnet_id      = aws_subnet.pri_sub1.id
  route_table_id = aws_route_table.pri_rt.id
}

// Creating route table association for private_subnet_2
resource "aws_route_table_association" "ass-private_subnet_2" {
  subnet_id      = aws_subnet.pri_sub2.id
  route_table_id = aws_route_table.pri_rt.id
}


#creating keypair RSA key of size 4096 bits
resource "tls_private_key" "key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

//creating private key
resource "local_file" "key" {
  content         = tls_private_key.key.private_key_pem
  filename        = "pet-key"
  file_permission = "600"
}

//creating public key
resource "aws_key_pair" "key" {
  key_name   = "pet-pub-key"
  public_key = tls_private_key.key.public_key_openssh
}



#sonarqube security group

resource "aws_security_group" "sonar-SG" {
  name        = "sonar-SG"
  description = "Allow inbound traffic"
  vpc_id      = aws_vpc.vpc.id
  ingress {
    description = "ssh"
    from_port   = var.sshport
    to_port     = var.sshport
    protocol    = "tcp"
    cidr_blocks = var.all-cidr
  }
  ingress {
    description = "sonarport"
    from_port   = var.sonarport
    to_port     = var.sonarport
    protocol    = "tcp"
    cidr_blocks = var.all-cidr

  }
  ingress {
    description = "http"
    from_port   = var.httpport
    to_port     = var.httpport
    protocol    = "tcp"
    cidr_blocks = var.all-cidr

  }
  ingress {
    description = "https"
    from_port   = var.httpsport
    to_port     = var.httpsport
    protocol    = "tcp"
    cidr_blocks = var.all-cidr

  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = var.all-cidr
  }
  tags = {
    Name = "${local.name}-sonar-SG"
  }
}

#docker security group

resource "aws_security_group" "docker-SG" {
  name        = "docker-SG"
  description = "Allow inbound traffic"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    description = "ssh"
    from_port   = var.sshport
    to_port     = var.sshport
    protocol    = "tcp"
    cidr_blocks = var.all-cidr
  }
  ingress {
    description = "docker port"
    from_port   = var.dockerport
    to_port     = var.dockerport
    protocol    = "tcp"
    cidr_blocks = var.all-cidr
  }

  ingress {
    description = "http"
    from_port   = var.httpport
    to_port     = var.httpport
    protocol    = "tcp"
    cidr_blocks = var.all-cidr

  }
  ingress {
    description = "https"
    from_port   = var.httpsport
    to_port     = var.httpsport
    protocol    = "tcp"
    cidr_blocks = var.all-cidr

  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = var.all-cidr
  }
  tags = {
    Name = "${local.name}-docker-SG"
  }
}
#jenkins security group

resource "aws_security_group" "jenkins-SG" {
  name        = "jenkins-SG"
  description = "Allow inbound traffic"
  vpc_id      = aws_vpc.vpc.id
  ingress {
    description = "ssh"
    from_port   = var.sshport
    to_port     = var.sshport
    protocol    = "tcp"
    cidr_blocks = var.all-cidr

  }
  ingress {
    description = "jenkinsport"
    from_port   = var.jenkinsport
    to_port     = var.jenkinsport
    protocol    = "tcp"
    cidr_blocks = var.all-cidr

  }
  ingress {
    description = "otlp port"
    from_port   = var.otlpport
    to_port     = var.otlpport
    protocol    = "tcp"
    cidr_blocks = var.all-cidr

  }
  ingress {
    description = "http"
    from_port   = var.httpport
    to_port     = var.httpport
    protocol    = "tcp"
    cidr_blocks = var.all-cidr

  }
  ingress {
    description = "https"
    from_port   = var.httpsport
    to_port     = var.httpsport
    protocol    = "tcp"
    cidr_blocks = var.all-cidr

  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = var.all-cidr
  }
  tags = {
    Name = "${local.name}-jenkins-SG"
  }
}

#Ansible baston security group

resource "aws_security_group" "ansible-baston-SG" {
  name        = "ansible-SG"
  description = "Allow inbound traffic"
  vpc_id      = aws_vpc.vpc.id
  ingress {
    description = "ssh"
    from_port   = var.sshport
    to_port     = var.sshport
    protocol    = "tcp"
    cidr_blocks = var.all-cidr

  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = var.all-cidr
  }
  tags = {
    Name = "${local.name}-ansible-SG"
  }
}

#nexus server security group

resource "aws_security_group" "nexus-SG" {
  name        = "nexus-SG"
  description = "Allow inbound traffic"
  vpc_id      = aws_vpc.vpc.id
  ingress {
    description = "ssh"
    from_port   = var.sshport
    to_port     = var.sshport
    protocol    = "tcp"
    cidr_blocks = var.all-cidr
  }
  ingress {
    description = "nexusport"
    from_port   = var.nexusport
    to_port     = var.nexusport
    protocol    = "tcp"
    cidr_blocks = var.all-cidr

  }
  ingress {
    description = "http"
    from_port   = var.httpport
    to_port     = var.httpport
    protocol    = "tcp"
    cidr_blocks = var.all-cidr

  }
  ingress {
    description = "https"
    from_port   = var.httpsport
    to_port     = var.httpsport
    protocol    = "tcp"
    cidr_blocks = var.all-cidr

  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = var.all-cidr
  }
  tags = {
    Name = "${local.name}-nexus-SG"
  }
}

#RDS security group
resource "aws_security_group" "RDS-SG" {
  name        = "RDS-SG"
  description = "Allow outbound traffic"
  vpc_id      = aws_vpc.vpc.id
  ingress {
    description     = "MYSQPORT"
    from_port       = var.mysqlport
    to_port         = var.mysqlport
    protocol        = "tcp"
    security_groups = [aws_security_group.ansible-baston-SG.id, aws_security_group.docker-SG.id]
  }
  egress {
    description = "All TRAFFIC"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "${local.name}-RDS-SG"
  }
}

# Creating Jenkins server
resource "aws_instance" "Bastion" {
  ami                         = var.redhat_ami
  instance_type               = var.instance_type
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.ansible-baston-SG.id]
  subnet_id                   = aws_subnet.pub_sub1.id
  key_name                    = aws_key_pair.key.id
  user_data                   = <<-EOF
#!/bin/bash
echo "${tls_private_key.key.private_key_pem}" >> /home/ec2-user/.ssh/id_rsa
sudo chmod 400 /home/ec2-user/.ssh/id_rsa
sudo chown ec2-user:ec2-user /home/ec2-user/.ssh/id_rsa
sudo yum install mysql -y
sudo hostnamectl set-hostname bastion
EOF
  tags = {
    Name = "${local.name}-Bastion"
  }
}

# Creating Ansible server
resource "aws_instance" "ansible-server" {
  ami                         = var.redhat_ami
  instance_type               = var.instance_type
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.ansible-baston-SG.id]
  subnet_id                   = aws_subnet.pub_sub2.id
  key_name                    = aws_key_pair.key.id
  user_data                   = local.ansible_user_data
  metadata_options {
    http_tokens = "required"
  }
  tags = {
    Name = "${local.name}-ansible-server"
  }
}

# Creating Docker host
resource "aws_instance" "Docker" {
  ami                         = var.redhat_ami
  instance_type               = var.instance_type
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.docker-SG.id]
  subnet_id                   = aws_subnet.pri_sub1.id
  key_name                    = aws_key_pair.key.id
  user_data                   = local.docker_user_data
  metadata_options {
    http_tokens = "required"
  }
  tags = {
    Name = "${local.name}-docker"
  }
}

# Creating Jenkins server
resource "aws_instance" "Jenkins" {
  ami                         = var.redhat_ami
  instance_type               = var.instance_type
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.jenkins-SG.id]
  subnet_id                   = aws_subnet.pub_sub1.id
  key_name                    = aws_key_pair.key.id
  user_data                   = local.jenkins_user_data
  metadata_options {
    http_tokens = "required"
  }
  tags = {
    Name = "${local.name}-jenkins"
  }
}

#creating sonarqube_server
resource "aws_instance" "sonarqube_instance" {
  ami                         = var.ubuntu_ami
  instance_type               = var.instance_type
  key_name                    = aws_key_pair.key.id
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.sonar-SG.id]
  subnet_id                   = aws_subnet.pub_sub1.id
  user_data                   = local.sonarqube_user_data
  metadata_options {
    http_tokens = "required"
  }
  tags = {
    Name = "${local.name}-SonarQube Instance"
  }
}

# Creating Nexus server
resource "aws_instance" "nexus" {
  ami                         = var.redhat_ami
  instance_type               = var.instance_type
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.nexus-SG.id]
  subnet_id                   = aws_subnet.pub_sub1.id
  key_name                    = aws_key_pair.key.id
  user_data                   = local.nexus_user_data
  metadata_options {
    http_tokens = "required"
  }
  tags = {
    Name = "${local.name}-nexus"
  }
}

#Creating secrete manager

resource "aws_secretsmanager_secret" "mysql-secret" {
  name                    = "mysql-secret"
  recovery_window_in_days = 0
}

data "aws_secretsmanager_random_password" "db-password" {
  password_length     = 10
  exclude_punctuation = true
}

resource "aws_secretsmanager_secret_version" "dbase-secret" {
  secret_id     = aws_secretsmanager_secret.mysql-secret.id
  secret_string = data.aws_secretsmanager_random_password.db-password.random_password
}
# creating DB subnet 
resource "aws_db_subnet_group" "database1" {
  name       = "database1"
  subnet_ids = [aws_subnet.pri_sub1.id, aws_subnet.pri_sub2.id]

  tags = {
    Name = "${local.name}-DB-subnet"
  }
}
# creating RDS
resource "aws_db_instance" "multi-az-db" {
  identifier             = var.db-identifier
  db_subnet_group_name   = aws_db_subnet_group.database1.name
  vpc_security_group_ids = [aws_security_group.RDS-SG.id]
  allocated_storage      = 10
  db_name                = var.dbname
  engine                 = "mysql"
  engine_version         = "5.7"
  instance_class         = "db.t3.micro"
  username               = var.dbusername
  password               = aws_secretsmanager_secret_version.dbase-secret.secret_string
  parameter_group_name   = "default.mysql5.7"
  skip_final_snapshot    = true
  publicly_accessible    = false
  storage_type           = "gp2"
}


#creating AMI 
resource "aws_ami_from_instance" "asg_ami" {
  name                    = "asg-ami"
  source_instance_id      = aws_instance.Docker.id
  snapshot_without_reboot = true
  depends_on              = [aws_instance.Docker, time_sleep.ami-sleep]

}

#creating time sleep
resource "time_sleep" "ami-sleep" {
  depends_on      = [aws_instance.Docker]
  create_duration = "360s"

}
#ASg launch configuration
resource "aws_launch_configuration" "lnch_conf" {
  name            = "asg-config"
  image_id        = aws_ami_from_instance.asg_ami.id
  instance_type   = var.instance_type
  security_groups = [aws_security_group.docker-SG.id]
  key_name        = aws_key_pair.key.key_name

  lifecycle {
    create_before_destroy = true
  }
}
# creating autoscaling group
resource "aws_autoscaling_group" "autoscaling_grp" {
  name                      = "${local.name}-asg"
  max_size                  = 5
  min_size                  = 1
  health_check_grace_period = 30
  health_check_type         = "EC2"
  desired_capacity          = 2
  force_delete              = true
  launch_configuration      = aws_launch_configuration.lnch_conf.id
  vpc_zone_identifier       = [aws_subnet.pub_sub1.id, aws_subnet.pub_sub2.id]
  target_group_arns         = [aws_lb_target_group.TG.arn]

  tag {
    key                 = "Name"
    value               = "ASG"
    propagate_at_launch = true
  }
}

# creating autoscaling policy
resource "aws_autoscaling_policy" "autoscaling_grp-policy" {
  autoscaling_group_name = aws_autoscaling_group.autoscaling_grp.name
  name                   = "$(local.name)-asg-policy"
  adjustment_type        = "ChangeInCapacity"
  policy_type            = "TargetTrackingScaling"
  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value = 50.0
  }
}
#creating Jenkins elb
resource "aws_elb" "elb-jenkins" {
  name            = "elb-jenkins"
  security_groups = [aws_security_group.jenkins-SG.id]
  subnets         = [aws_subnet.pub_sub1.id, aws_subnet.pub_sub2.id]

  listener {
    instance_port      = 8080
    instance_protocol  = "http"
    lb_port            = 443
    lb_protocol        = "https"
    ssl_certificate_id = aws_acm_certificate.ssl-cert.id
  }

  health_check {
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 3
    target              = "tcp:8080"
    interval            = 30
  }

  instances                   = [aws_instance.Jenkins.id]
  cross_zone_load_balancing   = true
  idle_timeout                = 400
  connection_draining         = true
  connection_draining_timeout = 400


  tags = {
    Name = "jenkins-elb"
  }
}

#creating nexus elb
resource "aws_elb" "elb-nexus" {
  name            = "elb-nexus"
  security_groups = [aws_security_group.nexus-SG.id]
  subnets         = [aws_subnet.pub_sub1.id, aws_subnet.pub_sub2.id]

  listener {
    instance_port      = 8081
    instance_protocol  = "http"
    lb_port            = 443
    lb_protocol        = "https"
    ssl_certificate_id = aws_acm_certificate.ssl-cert.id
  }

  health_check {
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 3
    target              = "tcp:8081"
    interval            = 30
  }

  instances                   = [aws_instance.nexus.id]
  cross_zone_load_balancing   = true
  idle_timeout                = 400
  connection_draining         = true
  connection_draining_timeout = 400

  tags = {
    Name = "nexus-elb"
  }
}
#creating sonar elb
resource "aws_elb" "elb-sonar" {
  name            = "elb-sonar"
  security_groups = [aws_security_group.sonar-SG.id]
  subnets         = [aws_subnet.pub_sub1.id, aws_subnet.pub_sub2.id]

  listener {
    instance_port      = 9000
    instance_protocol  = "http"
    lb_port            = 443
    lb_protocol        = "https"
    ssl_certificate_id = aws_acm_certificate.ssl-cert.id
  }

  health_check {
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 3
    target              = "tcp:9000"
    interval            = 30
  }

  instances                   = [aws_instance.sonarqube_instance.id]
  cross_zone_load_balancing   = true
  idle_timeout                = 400
  connection_draining         = true
  connection_draining_timeout = 400


  tags = {
    Name = "sonar-elb"
  }
}

# creating target group
resource "aws_lb_target_group" "TG" {
  name     = "pet-TG"
  port     = var.dockerport
  protocol = "HTTP"
  vpc_id   = aws_vpc.vpc.id
  health_check {
    healthy_threshold   = 3
    unhealthy_threshold = 5
    interval            = 60
    timeout             = 10
  }
}

# creating target group attachment
resource "aws_lb_target_group_attachment" "TG-attach" {
  target_group_arn = aws_lb_target_group.TG.arn
  target_id        = aws_instance.Docker.id
  port             = var.dockerport
}
# creating docker application load balancer
resource "aws_lb" "docker-LB" {
  name                       = "docker-LB"
  internal                   = false
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.docker-SG.id]
  subnets                    = [aws_subnet.pub_sub1.id, aws_subnet.pub_sub2.id]
  enable_deletion_protection = false
  tags = {
    Name = "${local.name}-docker_LB"
  }
  drop_invalid_header_fields = true
}

# creating docker load balancer http listener
resource "aws_lb_listener" "docker-http-listener" {
  load_balancer_arn = aws_lb.docker-LB.arn
  port              = var.httpport
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.TG.arn
  }
}

# creating docker load balancer https listener
resource "aws_lb_listener" "docker-https-listener" {
  load_balancer_arn = aws_lb.docker-LB.arn
  port              = var.httpsport
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = aws_acm_certificate.ssl-cert.arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.TG.arn
  }
}

#creating ssl certificate
resource "aws_acm_certificate" "ssl-cert" {
  domain_name               = var.domain
  subject_alternative_names = ["*.${var.domain}"]
  validation_method         = "DNS"
  lifecycle {
    create_before_destroy = true
  }
}
#creating
resource "aws_route53_record" "validate-record" {
  for_each = {
    for dvo in aws_acm_certificate.ssl-cert.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.pet-zone.zone_id
}
resource "aws_acm_certificate_validation" "cert-validation" {
  certificate_arn         = aws_acm_certificate.ssl-cert.arn
  validation_record_fqdns = [for record in aws_route53_record.validate-record : record.fqdn]
}

 #creating route53 hosted zone
 data "aws_route53_zone" "pet-zone" {
   name         = var.domain
   private_zone = false
 }

#creating A jenkins record
resource "aws_route53_record" "jenkins-record" {
  zone_id = data.aws_route53_zone.pet-zone.zone_id
  name    = var.jenkins-domain
  type    = "A"
  alias {
    name                   = aws_elb.elb-jenkins.dns_name
    zone_id                = aws_elb.elb-jenkins.zone_id
    evaluate_target_health = true
  }
}
#creating A sonar record
resource "aws_route53_record" "sonar-record" {
  zone_id = data.aws_route53_zone.pet-zone.zone_id
  name    = var.sonar-domain
  type    = "A"
  alias {
    name                   = aws_elb.elb-sonar.dns_name
    zone_id                = aws_elb.elb-sonar.zone_id
    evaluate_target_health = true
  }
}
#creating A nexus record
resource "aws_route53_record" "nexus-record" {
  zone_id = data.aws_route53_zone.pet-zone.zone_id
  name    = var.nexus-domain
  type    = "A"
  alias {
    name                   = aws_elb.elb-nexus.dns_name
    zone_id                = aws_elb.elb-nexus.zone_id
    evaluate_target_health = true
  }
}
#creating A nexus record
resource "aws_route53_record" "docker-record" {
  zone_id = data.aws_route53_zone.pet-zone.zone_id
  name    = var.docker-domain
  type    = "A"
  alias {
    name                   = aws_lb.docker-LB.dns_name
    zone_id                = aws_lb.docker-LB.zone_id
    evaluate_target_health = true
  }
}



