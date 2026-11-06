# Test fixture: the same image with password logins turned off.
FROM alpine:3.22
RUN apk add --no-cache openssh-server \
 && ssh-keygen -A \
 && echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
