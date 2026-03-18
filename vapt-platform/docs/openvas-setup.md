# OpenVAS / Greenbone Setup

This project uses the official Greenbone Community Edition multi-container deployment in a separate compose file:

- [openvas-compose.yml](/C:/Users/User/Documents/VAPT%20project/vapt-platform/docker/openvas-compose.yml)

## Start Greenbone

Run this from the project root:

```bash
docker compose -f docker/openvas-compose.yml up -d
```

The first start can take a long time because it downloads the feed and several large images.

## Access Greenbone

- Greenbone web/API gateway: `https://127.0.0.1:9392`

## How the main API reaches it

The main platform API container is configured with `host.docker.internal` so it can call the Greenbone endpoint exposed on the host.

Use this in your `.env`:

```env
OPENVAS_API_URL=https://host.docker.internal:9392
OPENVAS_SOCKET_PATH=/run/gvmd/gvmd.sock
```

## Notes

- Greenbone is intentionally kept outside the main application compose stack because it is a heavy multi-container deployment with its own lifecycle.
- Once Greenbone is up, the next engineering step is replacing the mock OpenVAS orchestration path with live task creation, polling, and result ingestion against the Greenbone API.
