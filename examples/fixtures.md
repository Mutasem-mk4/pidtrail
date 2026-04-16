# Examples

These examples are intended to run on Linux.

Start a local fixture server:

```sh
go run ./examples/http-fixture-server
```

Generate local client traffic:

```sh
go run ./examples/http-fixture-client
```

Generate a local smoke workload that opens `/etc/hosts` and performs an HTTP request:

```sh
go run ./examples/http-smoke-workload
```

Trace a PID:

```sh
sudo ./pidtrail --pid 1234
```

Trace a process name:

```sh
sudo ./pidtrail --process curl
```

Launch and trace a command with a report:

```sh
sudo ./pidtrail --report-dir report -- /usr/bin/curl http://127.0.0.1:18080/hello
```

Run diagnostics:

```sh
sudo ./pidtrail --pid 1234 --diagnose
```

Run the full Linux smoke harness:

```sh
sudo sh packaging/linux-smoke.sh
```
