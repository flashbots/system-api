# System API

[![Goreport status](https://goreportcard.com/badge/github.com/flashbots/system-api)](https://goreportcard.com/report/github.com/flashbots/system-api)
[![Test status](https://github.com/flashbots/system-api/actions/workflows/checks.yml/badge.svg?branch=main)](https://github.com/flashbots/system-api/actions?query=workflow%3A%22Checks%22)

An interface between TDX VM services and the operator. Used in [BuilderNet](https://buildernet.org/).

Features:

- **Event log**: Services inside a TDX instance can record events they want exposed to the operator
 used to record and query events. Useful to record service startup/shutdown, errors, progress updates,
 hashes, etc.
- **Actions**: Ability to execute shell commands via API
- **File uploads**
- **HTTP Basic Auth** support
- **TLS encryption support**

Notes:

- Configuration through config file (see [`systemapi-config.toml`](./systemapi-config.toml))
- Actions and file uploads show up in the event log

---

## Getting started

```bash
# Start the server
make run

# Add events
echo "hello world" > pipe.fifo
curl --insecure https://localhost:3535/api/v1/new_event?message=this+is+a+test

# Execute actions
curl --insecure https://localhost:3535/api/v1/actions/echo_test

# Upload files
curl --insecure --data-binary "@README.md" https://localhost:3535/api/v1/file-upload/testfile

# Get event log
curl --insecure https://localhost:3535/logs
2024-11-05T22:03:23Z     hello world
2024-11-05T22:03:26Z     this is a test
2024-11-05T22:03:29Z     [system-api] executing action: echo_test = echo test
2024-11-05T22:03:29Z     [system-api] executing action success: echo_test = echo test
2024-11-05T22:03:31Z     [system-api] file upload: testfile = /tmp/testfile.txt
2024-11-05T22:03:31Z     [system-api] file upload success: testfile = /tmp/testfile.txt - content: 1991 bytes

# Set basic auth secret
curl --insecure --data "foobar" https://localhost:3535/api/v1/set-basic-auth

# Get logs with basic auth (otherwise will be rejected with Unauthorized)
curl --insecure --user admin:foobar https://localhost:3535/logs
```

---

## Event log

Events can be added via local named pipe (i.e. file `pipe.fifo`) or through HTTP API:

```bash
# Start the server
$ make run

# Add events
$ echo "hello world" > pipe.fifo
$ curl --insecure https://localhost:3535/api/v1/new_event?message=this+is+a+test

# Query events (plain text or JSON is supported)
$ curl --insecure https://localhost:3535/logs
2024-10-23T12:04:01Z     hello world
2024-10-23T12:04:07Z     this is a test
```

---

 ## Actions

 Actions are shell commands that can be executed via API. The commands are defined in the config file,
 see [systemapi-config.toml](./systemapi-config.toml) for examples.

Actions are recorded in the event log.

```bash
# Start the server
$ make run

# Execute the example action
$ curl --insecure https://localhost:3535/api/v1/actions/echo_test
```

---

## File Uploads

Upload destinations are defined in the config file (see [systemapi-config.toml](./systemapi-config.toml)).

File uploads are recorded in the event log.

```bash
# Start the server
$ make run

# Upload the file
$ curl --insecure --data-binary "@README.md" https://localhost:3535/api/v1/file-upload/testfile
```

---

## HTTP Basic Auth

All API endpoints can be protected with HTTP Basic Auth.

The API endpoints are initially unauthenticated, until a secret is configured
either via file or via API. If the secret is configured via API, the salted SHA256
hash is be stored in a file (specified in the config file) to enable basic auth protection
across restarts.

The config file ([systemapi-config.toml](./systemapi-config.toml)) includes `basic_auth_secret_path` (and `basic_auth_secret_salt`).
- If the file exists and is not empty, then the APIs are authenticated for passwords that match the salted hash in this file.
- If the file exists and is empty, then the APIs are unauthenticated until a secret is configured.
- If this file is specified but doesn't exist, system-api will create it (empty).

Example:

```bash
# The included systemapi-config.toml uses basic-auth-secret.txt for basic_auth_secret_path
cat systemapi-config.toml

# Start the server
make run

# Initially, requests are unauthenticated
curl --insecure https://localhost:3535/livez

# Set the basic auth secret. From here on, authentication is required for all API requests.
curl --insecure --data "foobar" https://localhost:3535/api/v1/set-basic-auth

# Check that hash was written to the file
cat basic-auth-hash.txt

# API calls with no basic auth credentials are provided fail now, with '401 Unauthorized' because
curl --insecure https://localhost:3535/livez

# API calls work if correct basic auth credentials are provided
curl --insecure --user admin:foobar https://localhost:3535/livez

# The update also shows up in the logs
curl --insecure --user admin:foobar https://localhost:3535/logs

# You can also update the basic auth secret:
curl --insecure --user admin:foobar --data "new_secret" https://localhost:3535/api/v1/set-basic-auth
```

---

## TLS encryption support

TLS encryption is supported. System-API can load the certificate and key from local files (which it can also generate if missing).

The config file ([systemapi-config.toml](./systemapi-config.toml)) includes `tls_cert_path` and `tls_key_path` for the certificate and key files, and
a few other options:

```toml
[general]
# TLS configuration
tls_enabled = true
tls_create_if_missing = true
tls_cert_hosts = ["localhost", ""]
tls_cert_path = "cert.pem"
tls_key_path = "key.pem"
```

If `tls_enabled` is set to `false`, TLS is disabled and regular HTTP requests will work just fine. If `tls_enabled` is set to `true`, requests will be served over HTTPS.

If `tls_create_if_missing` is set to `true`, system-api will generate a self-signed certificate and key if the files are missing. If set to `false`, system-api will fail to start if the files are missing.
