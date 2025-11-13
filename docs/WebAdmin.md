# Web Admin API

The built-in HTTP listener can now expose a small JSON API so you can run the usual
telnet / console commands from a browser, dashboard or automation script. The API
always forces a synchronous world save before any shutdown/restart command is
executed, which prevents the few-minute data loss that used to happen when the server
was restarted manually without issuing `#` beforehand.

## Enabling the service

1. Ensure `UseHttp` is set to `1` or `2` in `sphere.ini` so the HTTP listener is
   running.
2. Configure the admin API right below that section:

   ```ini
   UseHttp=2
   WebAdmin=1
   WebAdminAllow=127.0.0.1,::1
   WebAdminToken=change-me
   ```

   * `WebAdmin` — toggles the feature. Disabled by default.
   * `WebAdminAllow` — comma-separated list of IPv4/IPv6 addresses that are allowed
     to call the API. Use `*` to allow every address (not recommended).
   * `WebAdminToken` — optional bearer token that must be sent through the
     `Authorization: Bearer <token>` header or a `token=<token>` query/body
     parameter. Leave empty if you only want to rely on the allow list.

Restart Sphere (or resync the INI) after changing those values.

## Endpoints

All endpoints live under `http://<host>:<port>/admin/api/…` and return JSON.

| Method | Path            | Description                                                         |
| ------ | --------------- | ------------------------------------------------------------------- |
| GET    | `/status`       | Current stats (clients/items/chars), uptime, save state, exit flag. |
| POST   | `/command`      | Executes a console command (`cmd=<value>`).                         |
| POST   | `/save`         | Forces a synchronous `#` save. Optional `statics=1` saves statics.  |
| POST   | `/restart`      | Save → (optional statics) → graceful shutdown (exit flag 2).        |
| POST   | `/shutdown`     | Alias for `/restart` (service managers usually restart the binary). |

### Examples

Status check:

```bash
curl -H "Authorization: Bearer change-me" \
     http://127.0.0.1:2593/admin/api/status
```

Execute a console command (for example `?` to list available commands):

```bash
curl -X POST \
     -H "Authorization: Bearer change-me" \
     -d "cmd=%3F" \
     http://127.0.0.1:2593/admin/api/command
```

Save and restart, forcing a statics save as well:

```bash
curl -X POST \
     -H "Authorization: Bearer change-me" \
     -d "statics=1" \
     http://127.0.0.1:2593/admin/api/restart
```

Every restart/shutdown request now performs a synchronous world save first. If a
save is already running, the API returns a `409 Conflict` response so you can retry
later instead of interrupting the running save.

## Security notes

* Keep `WebAdminAllow` as small as possible (ideally only loopback/management
  network) and set a long `WebAdminToken` before exposing the API.
* The built-in HTTP server does **not** support TLS. If you need remote access,
  put the listener behind a reverse proxy that terminates HTTPS.
* All requests are logged with `LOGM_HTTP`, so you can audit usage directly from
  the console/log file.
