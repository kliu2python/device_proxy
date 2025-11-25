# Device Proxy

This project provides a lightweight API and front-end to view and control a pool of automation devices. It exposes endpoints for registering nodes, monitoring availability, and opening devices in STF (Smartphone Test Farm).

## Services

The backend is split into two processes so HTTP traffic and background work can
scale independently:

* **API service** – start with ``uvicorn backend.main:app``. It provides the
  HTTP endpoints and serves the UI. By default it no longer launches the
  monitor loop; for single-process development you can set
  ``ENABLE_IN_PROCESS_MONITOR=true`` to restore the previous behaviour.
* **Worker service** – start with ``python -m backend.worker``. It runs the
  monitor logic from ``backend.monitor`` (device capability sync, STF
  reservation expiry, idle-session cleanup, and node health checks). Run as
  many workers as needed. The idle-session reaper considers a session inactive
  when it has not proxied any requests for three minutes; adjust the threshold
  with the ``SESSION_IDLE_TIMEOUT_SECONDS`` environment variable when needed.

Both services use Redis for shared state. Ensure Redis is reachable before
starting either service. The worker preloads the CSV nodes by default; set
``WORKER_PRELOAD_CSV=false`` to skip that step when nodes are already
registered.

## Enabling the "Open in STF" action

The UI only enables the **Open in STF** button for devices that have sufficient STF configuration. You can provide this configuration globally via environment variables or on a per-node basis via the node resources JSON.

### Option 1: Environment variables (global defaults)

Set the following variables for the backend service before starting it:

| Variable | Description |
| --- | --- |
| `STF_BASE_URL` | Required. The base URL of your STF deployment (for example `https://stf.example.com`). |
| `STF_CONTROL_URL_TEMPLATE` | Optional. Path or URL used to open a device. Defaults to `/#!/control/{udid}` when omitted. |
| `STF_JWT` and `STF_JWT_QUERY_PARAM` | Optional. Provide a static token that is appended to the launch URL. |
| `STF_SESSION_TTL_SECONDS` | Optional. Default reservation length in seconds. |
| `STF_MAX_SESSION_TTL_SECONDS` | Optional. Upper bound for reservations. |
| `STF_ENABLED` | Optional boolean flag (`true`/`false`) to force-enable or disable STF globally. |

Any non-empty value for `STF_BASE_URL` enables STF globally as long as the target node has a UDID. When JWT settings are present they are appended automatically to the launch URL that opens in a new tab.

### Option 2: Per-node resources (CSV or API)

If you prefer to configure STF only for specific devices, include an `stf` object in the node's `resources` JSON. This can be supplied via the CSV import (`backend/node_resources.csv`) or the `/register` API. Example:

```json
{
  "session_data": {
    "device": "metadata"
  },
  "stf": {
    "base_url": "https://stf.example.com",
    "control_path_template": "/#!/control/{udid}",
    "enabled": true
  }
}
```

The updated CSV template that you can download from `/nodes/template` now includes this example. Ensure that the node definition also includes a UDID; otherwise STF cannot be enabled for that device.

### Additional requirements

* The node must report `status` as `online` and have available sessions (`max_sessions` > `active_sessions`).
* Physical devices must include a `udid` so the default STF path template can substitute it.
* The browser must allow popups for the Device Proxy UI so the STF tab can be opened successfully.

Once the configuration is in place, reload the UI. Eligible devices will display the **Open in STF** button, and selecting it will initiate a reservation and open the STF control interface in a new tab.

## SSL/HTTPS Configuration

The Device Proxy can be configured to run with SSL/HTTPS encryption on port 443.

### Quick Setup

Device Proxy runs on HTTPS port 443 only (no port 80):
- Device Proxy: `https://devicehub.qa.fortinet-us.com`
- STF Server: Runs independently on `http://10.160.13.118/stf`

### Documentation

- **[SIMPLE_SSL_SETUP.md](SIMPLE_SSL_SETUP.md)** - Complete guide for SSL configuration on port 443, including:
  - Nginx reverse proxy setup
  - SSL certificate installation
  - Docker deployment steps
  - Troubleshooting guide

- **[nginx-reverse-proxy.conf](nginx-reverse-proxy.conf)** - Ready-to-use Nginx configuration

The application Docker containers run on internal ports (8080 for frontend, 8090 for backend), and the main Nginx reverse proxy handles SSL termination on port 443.

### Advanced: Multiple Services on Port 443

If you need both Device Proxy and STF on the same port 443, see **[SSL_AND_STF_SETUP.md](SSL_AND_STF_SETUP.md)** for path-based or hostname-based routing options.
