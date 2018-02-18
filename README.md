# docker-registry-tinyauth

This repository contains an example of using a flask app to provide authentication and authorization for the Docker registry (v2) with tinyauth.

When token authorization is turned on in the docker registry unauthenticated requests will trigger a 401 challenge. The `WWW-Authenticate` header will specify a realm; this realm is a URI that can be used to request a JWT token authorizing access to push and pull repositories.

We use flask_tinyauth and provide a micro service that implements the token service and delegates the actual authz to tinyauth. We then use nginx to provide a TLS protected single combined virtualhost entrypoint.
