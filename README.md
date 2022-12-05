# Sentinel:CA

![pipeline status](https://gitlab.nic.cz/turris/sentinel/ca/badges/master/pipeline.svg)
![coverage report](https://gitlab.nic.cz/turris/sentinel/ca/badges/master/coverage.svg)

A *Certifiator* component

Automated certification authority to issue certificates for authenticated
devices.


## Python requirements

- Python Package Index requirements
    - `cryptography`
    - `redis`
- Custom libraries
    - [Turris:Sentinel network](https://gitlab.nic.cz/turris/sentinel/sn)


## Usage

1. Generate the key and CA certificate

    - For *self-signed* certificate, an example `openssl` configuration is
      provided in `dev/ca_test.cnf`

    - For development purpose, these commands will generate suitable key and cert:

        ```
        openssl ecparam -genkey -name secp384r1 -out key-ca.pem
        openssl req -new -x509 -config dev/ca_test.cnf -days 90 -key key-ca.pem -out cert-ca.pem
        ```

2. Initialize the sqlite database with `scheme.sql`

    ```
    sqlite3 ca.db < scheme.sql
    ```

3. Prepare *Redis* database server
4. Create CA configuration file
    - Example config is in `ca.ini.example`
5. Run `ca.py`
    - *sn* `checker` resource is needed (connection to *Sentinel:Certifiator*
      component [Checker](https://gitlab.nic.cz/turris/sentinel/checker))
    - Path to a config file should be defined (defaults to `ca.ini`)

    ```
    python3 ca.py --config ca.ini --resource 'checker,connect,REQ,[::1],5000' -v
    ```
