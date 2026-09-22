# OARepo Kerberos

Library for handling Kerberos authentication in OARepo repositories.

### How to use


1. Get a keytab file from your KDC and configure your repository to use it. This involves setting the `KRB5_KTNAME` flask application configuration to the location of the keytab file.

2. Configure your repository to use its hostname in gssapi. This involves setting the `'GSSAPI_HOSTNAME'` flask application configuration to the hostname of your repository.

3. Test the Kerberos authentication by making requests to your repository and verifying that they are authenticated using Kerberos.

### Limitations

#### Multi-leg SPNEGO is not supported

Authentication must complete in a single round trip. The negotiation cannot
be resumed either — a fresh GSSAPI security context is built per request, and the continuation
token is discarded unless that context completed — so a request needing a second leg is answered
with **501 Not Implemented**.

#### A session cookie and a Negotiate token cannot be combined

Successful Kerberos authentication logs the user in, which sets a session cookie. If a client
then sends that cookie *and* `Authorization: Negotiate ...` on a later request, it is presenting
two credentials that may name different principals, so the server refuses with **400 Bad
Request** rather than silently picking one.





