# Use an official Ubuntu base image
FROM ubuntu:latest

# Set environment variables to prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Update the package list and install Kerberos KDC and admin server
RUN apt-get update && \
    apt-get install -y krb5-kdc krb5-admin-server && \
    rm -rf /var/lib/apt/lists/*

# Copy configuration files
COPY krb5.conf /etc/krb5.conf
COPY kdc.conf /etc/krb5kdc/kdc.conf
COPY kadm5.acl /etc/krb5kdc/kadm5.acl

# Initialize the Kerberos database with a password
RUN /usr/sbin/kdb5_util create -s -P adminpassword

# Expose Kerberos KDC and admin server ports
EXPOSE 88 464

# Start both the KDC and the admin server
CMD ["/bin/bash", "-c", "/usr/sbin/krb5kdc && /usr/sbin/kadmind -nofork"]
