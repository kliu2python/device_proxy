# Device Proxy

This project provides a lightweight API and front-end to view and control a pool of automation devices. It exposes endpoints for registering nodes, monitoring availability, and opening devices in STF (Smartphone Test Farm).

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

## Using STF device controls from the proxy UI

When STF exposes its REST API, the proxy can surface additional device controls directly within the portal. Configure the following environment variables (or provide matching values in the node `resources.stf` object) so the backend can reach the API:

| Variable | Description |
| --- | --- |
| `STF_API_BASE_URL` | Base URL of the STF REST API (for example `https://stf.example.com/api/v1`). Defaults to `<STF_BASE_URL>/api/v1` when omitted. |
| `STF_API_TOKEN` | API token used for bearer authentication when calling STF. |
| `STF_API_VERIFY_SSL` | Optional boolean flag to disable TLS verification for self-signed deployments. |
| `STF_API_TIMEOUT_SECONDS` | Optional request timeout for STF API calls. |

With these values in place, opening a device in STF displays a control panel beneath the embedded session. The panel includes actions to **Use device**, **Stop using**, **Install app**, **Screenshot**, and **Refresh status**, mirroring the common controls available in the native STF dashboard. The status refresh renders the latest STF device metadata within the page, while the install and screenshot actions proxy their respective STF API endpoints.
