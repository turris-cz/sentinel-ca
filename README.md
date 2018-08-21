# Sentinel:CA

A *Certifiator* component

Automated certification authority to issue certificates for authenticated
devices.


## Python requirements

- Python Package Index requirements
    - `cryptography`
    - `redis`
- Custom libraries
    - [Turris:Sentinel network](https://gitlab.labs.nic.cz/turris/sentinel/sn)


## Usage

1. Generate the key and CA certificate
    - For *self-signed* certificate, an example `openssl` configuration is
      provided in `dev/ca_test.cnf`
2. Initialize the sqlite database with `scheme.sql`

    ```
    sqlite3 ca.db < scheme.sql
    ```

3. Prepare *Redis* database server
4. Create CA configuration file
    - Example config is in `ca.ini.example`
5. Run `ca.py`
    - *sn* `checker` resource is needed (connection to *Sentinel:Certifiator*
      component [Checker](https://gitlab.labs.nic.cz/turris/sentinel/checker))
    - Path to a config file should be defined (defaults to `ca.ini`)

    ```
    python3 ca.py --config ca.ini --resource 'checker,connect,REQ,[::1],5000' -v
    ```
