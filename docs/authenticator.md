# Authenticator

Trojan servers can authenticate users according to not only passwords in the config file but also entries in a MySQL (MariaDB) database. To turn this functionality on, set `enabled` field in the MySQL config to `true` and correctly configure the server address, credentials, and etc. If you would like to connect to the database securely, you can to fill the `cafile` field indicating the CA file:

```json
"mysql": {
    "enabled": true,
    "server_addr": "127.0.0.1",
    "server_port": 3306,
    "database": "trojan",
    "username": "trojan",
    "password": "",
    "cafile": ""
}
```

The table has to be named `users`. An example table structure could be:

```sql
CREATE TABLE users (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    username VARCHAR(64) NOT NULL,
    password CHAR(56) NOT NULL,
    quota BIGINT NOT NULL DEFAULT 0,
    download BIGINT UNSIGNED NOT NULL DEFAULT 0,
    upload BIGINT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    INDEX (password)
);
```

Note that trojan will only read/write the `password`, `quota`, `download`, and `upload` fields. Other fields exist for management convenience. The passwords stored in the table have to be hashed by SHA224 for efficiency and security reasons.

Upon receiving a Trojan Request, **if the server fails to match the password with any passwords set in the config file**, it will query the database for the user. If it succeeds, trojan will check whether `download + upload < quota`; if so, the connection is granted. **A negative `quota` value means infinite quota.** After a connection is closed, trojan will increment `download` and `upload` fields of that user by the amount of data the user has used.

The unit of `quota`, `download`, and `upload` fields is Byte.

[Homepage](.) | [Prev Page](config) | [Next Page](build)
