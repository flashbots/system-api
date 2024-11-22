# System API

[![Goreport status](https://goreportcard.com/badge/github.com/flashbots/system-api)](https://goreportcard.com/report/github.com/flashbots/system-api)
[![Test status](https://github.com/flashbots/system-api/actions/workflows/checks.yml/badge.svg?branch=main)](https://github.com/flashbots/system-api/actions?query=workflow%3A%22Checks%22)

System API is an interface between TDX VMs and it's services and the operator.

It currently does the following things:

- **Event log**: Services inside a TDX instance can record events they want exposed to the operator
 used to record and query events. Useful to record service startup/shutdown, errors, progress updates,
 hashes, etc.
- **Actions**: Ability to execute shell commands via API
- **Configuration** through file uploads
- **HTTP Basic Auth** for API endpoints
- All actions show up in the event log

---

## Getting started

```bash
# start the server
make run

# add events
echo "hello world" > pipe.fifo
curl localhost:3535/api/v1/new_event?message=this+is+a+test

# execute actions
curl -v localhost:3535/api/v1/actions/echo_test

# upload files
curl -v -X POST -d "@README.md" localhost:3535/api/v1/file-upload/testfile

# get event log
curl localhost:3535/logs
2024-11-05T22:03:23Z     hello world
2024-11-05T22:03:26Z     this is a test
2024-11-05T22:03:29Z     [system-api] executing action: echo_test = echo test
2024-11-05T22:03:29Z     [system-api] executing action success: echo_test = echo test
2024-11-05T22:03:31Z     [system-api] file upload: testfile = /tmp/testfile.txt
2024-11-05T22:03:31Z     [system-api] file upload success: testfile = /tmp/testfile.txt - content: 1991 bytes
```

---

## Event log

Events can be added via local named pipe (i.e. file `pipe.fifo`) or through HTTP API:

```bash
# Start the server
$ go run cmd/system-api/main.go

# Add events
$ echo "hello world" > pipe.fifo
$ curl localhost:3535/api/v1/new_event?message=this+is+a+test

# Query events (plain text or JSON is supported)
$ curl localhost:3535/logs
2024-10-23T12:04:01Z     hello world
2024-10-23T12:04:07Z     this is a test
```

#### Event timestamps

By default, events are timestamped with the current time. However, the timestamp can be overridden by
providing a valid unix timestamp (in seconds or milliseconds) as first part of the message:

```bash
# Start the server
$ go run cmd/system-api/main.go

# Add regular event
$ echo "hello world" > pipe.fifo

# Add event with custom timestamp
$ echo "1634966400 this is a test" > pipe.fifo

# Query events
$ curl localhost:3535/logs
2024-11-22T13:50:09Z     hello world
2021-10-23T05:20:00Z     1634966400 this is a test      <--- custom timestamp on this entry
```

## Actions

Actions are shell commands that can be executed via API. The commands are defined in the config file,
see [systemapi-config.toml](./systemapi-config.toml) for examples.

Actions are recorded in the event log.

```bash
# Start the server
$ go run cmd/system-api/main.go --config systemapi-config.toml

# Execute the example action
$ curl -v localhost:3535/api/v1/actions/echo_test
```

## File Uploads

Upload destinations are defined in the config file (see [systemapi-config.toml](./systemapi-config.toml)).

File uploads are recorded in the event log.

```bash
# Start the server
$ go run cmd/system-api/main.go --config systemapi-config.toml

# Execute the example action
$ curl -v -X POST -d "@README.md" localhost:3535/api/v1/file-upload/testfile
```

## HTTP Basic Auth

All API endpoints can be protected with HTTP Basic Auth.

The API endpoints are initially unauthenticated, until a secret is configured
either via file or via API. If the secret is configured via API, the salted SHA256
hash is be stored in a file (specified in the config file) to enable basic auth protection
across restarts.

The config file ([systemapi-config.toml](./systemapi-config.toml)) includes a `basic_auth_secret_path`.
- If the file exists and is not empty, then the APIs are authenticated for passwords that match the hash in this file.
- If the file exists and is empty, then the APIs are unauthenticated until a secret is configured.
- If this file is specified but doesn't exist, system-api will create it (empty).

```bash
# The included systemapi-config.toml uses basic-auth-secret.txt for basic_auth_secret_path
cat systemapi-config.toml

# Start the server
go run cmd/system-api/main.go --config systemapi-config.toml

# Initially, requests are unauthenticated
curl -v localhost:3535/livez

# Set the basic auth secret. From here on, authentication is required for all API requests.
curl -d "foobar" localhost:3535/api/v1/set-basic-auth

# Check that hash was written to the file
cat basic-auth-secret.txt

# API calls with no basic auth credentials are provided fail now, with '401 Unauthorized' because
curl -v localhost:3535/livez

# API calls work if correct basic auth credentials are provided
curl -v -u admin:foobar localhost:3535/livez

# The update also shows up in the logs
curl -u admin:foobar localhost:3535/logs
```
