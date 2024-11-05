# oarepo Kerberos

Library that handles the kerberos authentication

### Setup

1. docker build -t custom-kerberos-kdc setup_local_kdc/Dockerfile 

2. docker run -d --name kerberos-kdc -p 88:88 -p 464:464 custom-kerberos-kdc

3. docker exec -it kerberos-kdc /bin/bash 

4. kadmin.local -q "addprinc admin/admin@EXAMPLE.COM" (choose password)

5. kadmin.local -q "addprinc user@EXAMPLE.COM" (choose password)

6. kadmin.local -q "addprinc -randkey HTTP/localhost@EXAMPLE.COM"

7. kadmin.local -q "ktadd -k /etc/krb5kdc/flask.keytab HTTP/localhost@EXAMPLE.COM"

8. docker cp kerberos-kdc:/etc/krb5kdc/flask.keytab ./flask.keytab

9. Setup env variable `KRB5_KTNAME` to location of flask.keytab and set `app.config['GSSAPI_HOSTNAME'] = 'localhost'`

10. change/create file `/etc/krb5.conf` to:

```
[libdefaults]
    default_realm = EXAMPLE.COM
    dns_lookup_kdc = false
    dns_lookup_realm = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true

[realms]
    EXAMPLE.COM = {
        kdc = localhost:88
        admin_server = localhost:464
    }

[domain_realm]
    .example.com = EXAMPLE.COM
    example.com = EXAMPLE.COM
    172.24.0.1 = EXAMPLE.COM
```



11. kinit user@EXAMPLE.COM or another username created in step 5





