# Developer tools

Scripts, tools and various helpers for Sentinel:CA developers.


## Dummy components

Dummy *Sentinel:Certificator* components prepared for local development. These
scripts have the same requirements as the `sentinel_ca` and can be run from the
same virtual environment.

- `dev/cert-api.py`
    - A dummy *Cert-API* implementation
    - Needs configuration same as `sentinel_ca` (for Redis connection)
    - Feeds Redis queue with random (both valid and invalid) certificate
      requests
    - Prints list of Redis queue, certificates, authentication states keys

    ```
    python3 dev/cert-api.py -l --config ca.ini
    ```

- `dev/checker.py`
    - A dummy *Checker* implementation
    - Listens on ZMQ socket an
    - Needs *sn* `in` (listening) resource

    ```
    python3 dev/checker.py -l --resource 'in,bind,REP,[::1],5000'
    ```
