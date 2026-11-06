# Test fixture: sshd on Alpine with password logins on (the OpenSSH default).
FROM alpine:3.22
RUN apk add --no-cache openssh-server \
 && ssh-keygen -A
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
