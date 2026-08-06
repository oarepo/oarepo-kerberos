#!/usr/bin/env bash
#
# Library-specific test setup hook, sourced by ./run.sh (the OARepo library runner)
# after the virtualenv and Docker services are up, but before pytest runs.
#
# oarepo-kerberos needs a real Kerberos KDC, a service keytab and a valid ticket
# (the auth tests talk to a live HTTP server with requests-kerberos). This builds a
# throwaway local KDC, creates the principals, exports the keytab to tests/flask.keytab,
# obtains a ticket, and points KRB5_CONFIG/KRB5_KTNAME at them for the pytest run.
#
# (C) 2025 CESNET, z.s.p.o.
# oarepo-kerberos is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

echo "Setting up local Kerberos KDC for tests..."

# The auth tests need the Kerberos client tools (kinit) and libkrb5 on the host for
# GSSAPI. They're assumed present for local development, but CI runners need them
# installed. Only attempt an apt-get install when kinit is genuinely missing, so this
# stays a no-op on a developer's already-configured machine.
if ! command -v kinit >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
  echo "kinit not found, installing Kerberos client tools..."
  sudo apt-get update && sudo apt-get install -y krb5-user libkrb5-dev || true
fi

# Recreate the KDC container from scratch so reruns start from a clean database.
docker rm -f kerberos-kdc >/dev/null 2>&1 || true

(
  cd setup_local_kdc
  docker build -t custom-kerberos-kdc .
  docker run -d --name kerberos-kdc -p 2222:88 -p 2223:464 custom-kerberos-kdc
)

# Wait for the KDC to initialize.
sleep 5

# Configure Kerberos principals and the service keytab.
echo -e "userpassword\nuserpassword" | docker exec -i kerberos-kdc kadmin.local -q "addprinc admin/admin@EXAMPLE.COM"
echo -e "userpassword\nuserpassword" | docker exec -i kerberos-kdc kadmin.local -q "addprinc user@EXAMPLE.COM"
docker exec kerberos-kdc kadmin.local -q "addprinc -randkey HTTP/localhost@EXAMPLE.COM"
docker exec kerberos-kdc kadmin.local -q "ktadd -k /etc/krb5kdc/flask.keytab HTTP/localhost@EXAMPLE.COM"

# Copy the keytab to the host where the tests expect it.
docker cp kerberos-kdc:/etc/krb5kdc/flask.keytab ./tests/flask.keytab

# Point the GSSAPI client/server at the local KDC and keytab for the pytest run.
export KRB5_CONFIG="$(pwd)/setup_local_kdc/krb5-client.conf"
export KRB5_KTNAME="$(pwd)/tests/flask.keytab"

# Obtain a ticket for the test user.
echo "Obtaining a Kerberos ticket for user@EXAMPLE.COM..."
kinit user@EXAMPLE.COM <<< "userpassword"
