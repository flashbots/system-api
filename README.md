# System API

System API is used as interface between TDX services and the operator.

It currently does the following things:

- **Event log**: Services inside a TDX instance can record events they want exposed to the operator
 used to record and query events. Useful to record service startup/shutdown, errors, progress updates,
 hashes, etc.

Future features:

- Operator can set a password for http-basic-auth (persisted, for all future requests)
- Operator-provided configuration (i.e. config values, secrets, etc.)
- Restart of services / execution of scripts

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
$ curl -s localhost:3535/api/v1/events?format=text
2024-10-23T12:04:01Z     hello world
2024-10-23T12:04:07Z     this is a test
```
