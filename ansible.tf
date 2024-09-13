locals {
  ansible_user_data = <<-EOF
#!/bin/bash
sudo yum update -y
sudo dnf install -y ansible-core python3 python3-pip
ansible-galaxy collection install community.docker
sudo ansible-galaxy collection install community.docker
sudo yum install -y yum utils
sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
sudo yum install docker-ce -y
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker ec2-user
sudo chown -R ec2-user:ec2-user /etc/ansible
echo "${tls_private_key.key.private_key_pem}" >> /home/ec2-user/.ssh/id_rsa
sudo chown ec2-user:ec2-user /home/ec2-user/.ssh/id_rsa
chmod 400 id_rsa /home/ec2-user/.ssh/id_rsa
cd /etc/ansible
touch hosts
sudo chown ec2-user:ec2-user hosts
cat <<EOT> /etc/ansible/hosts
[all:vars]
ansible_ssh_common_args='-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no'

localhost ansible_connection=local

[docker_host]
${aws_instance.Docker.private_ip} ansible_user=ec2-user ansible_ssh_private_key_file=/home/ec2-user/.ssh/id_rsa

EOT
sudo mkdir /opt/docker
echo "${file(var.newrelicfile)}" >> /opt/docker/newrelic.yml
touch /opt/docker/Dockerfile
cat <<EOT>> /opt/docker/Dockerfile
FROM openjdk:8-jre-slim
FROM ubuntu
FROM tomcat
COPY *.war /usr/local/tomcat/webapps
WORKDIR /usr/local/tomcat/webapps
RUN apt update -y && apt install curl -y
RUN curl -O https://download.newrelic.com/newrelic/java-agent/newrelic-agent/current/newrelic-java.zip && \
    apt-get install unzip -y  && \
    unzip newrelic-java.zip -d  /usr/local/tomcat/webapps
ENV JAVA_OPTS="$JAVA_OPTS -javaagent:/usr/local/tomcat/webapps/newrelic/newrelic.jar"
ENV NEW_RELIC_APP_NAME="myapp"
ENV NEW_RELIC_LOG_FILE_NAME=STDOUT
ENV NEW_RELIC_LICENCE_KEY="4fe454560348c09a686f1ddf970f1af0FFFFNRAL"
WORKDIR /usr/local/tomcat/webapps
ADD ./newrelic.yml /usr/local/tomcat/webapps/newrelic/newrelic.yml
ENTRYPOINT [ "java", "-javaagent:/usr/local/tomcat/webapps/newrelic/newrelic.jar", "-jar", "spring-petclinic-1.0.war", "--server.port=8080"]
EOT

touch /opt/docker/docker-image.yml
cat <<EOT>> /opt/docker/docker-image.yml

---
 - hosts: localhost
   become: true

   tasks:
    - name: Download WAR file from Nexus repository
      get_url:
        url: http://admin:admin123@${aws_instance.nexus.public_ip}:8081/repository/nexus-repo/Petclinic/spring-petclinic/1.0/spring-petclinic-1.0.war
        dest: /opt/docker
    - name: Create docker image from pet Adoption WAR file
      docker_image:
        build:
          path: /opt/docker
        name: testapp
        source: build

    - name: Login to Docker Hub
      docker_login:
        username: cloudhight
        password: CloudHight_Admin123@

    - name: Tag and push image to Docker Hub
      docker_image:
        name: testapp
        repository: cloudhight/testapp
        push: yes
        source: local
      ignore_errors: yes
EOT

touch /opt/docker/docker-container.yml
cat <<EOT>> /opt/docker/docker-container.yml
---
 - hosts: docker_host
   become: true

   tasks:
    - name: Login to Docker Hub
      docker_login:
        username: cloudhight
        password: CloudHight_Admin123@

    - name: Stop any container running
      docker_container:
        name: testAppContainer
        state: stopped
      ignore_errors: yes

    - name: Remove stopped container
      docker_container:
        name: testAppContainer
        state: absent
      ignore_errors: yes

    - name: Remove docker image
      docker_image:
        state: absent
        name: cloudhight/testapp
        tag: testapp
      ignore_errors: yes

    - name: Pull docker image from Docker Hub
      docker_image:
        name: cloudhight/testapp
        source: pull

    - name: Create container from pet adoption image
      docker_container:
        name: testAppContainer
        image: cloudhight/testapp
        state: started
        ports:
          - "8080:8080"
        detach: true
EOT

touch /opt/docker/newrelic-container.yml
# Create yaml file to create a newrelic container
cat << EOT > /opt/docker/newrelic-container.yml
---
 - hosts: docker_host
   become: true
   tasks:
   - name: install newrelic agent
     command: docker run \\
                     -d \
                     --name newrelic-infra \
                    --network=host \
                    --cap-add=SYS_PTRACE \
                    --privileged \
                    --pid=host \
                    -v "/:/host:ro" \
                    -v "/var/run/docker.sock:/var/run/docker.sock" \
                    -e  NRIA_LICENSE_KEY=eu01xx974c3221f28037fb3bc2247e9aFFFFNRAL \
                    newrelic/infrastructure:latest
     ignore_errors: yes
EOT
sudo chown -R ec2-user:ec2-user /opt/docker
sudo chmod -R 700 /opt/docker
curl -Ls https://download.newrelic.com/install/newrelic-cli/scripts/install.sh | bash && sudo NEW_RELIC_API_KEY=NRAK-R1E391EHZ2VM7H6RNKU3IIYKPT7 NEW_RELIC_ACCOUNT_ID=4666188 NEW_RELIC_REGION=EU /usr/local/bin/newrelic install -y
sudo hostnamectl set-hostname Ansible


EOF     
}
