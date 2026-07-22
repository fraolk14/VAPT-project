# Deployment Guide

## Local Docker deployment

1. Review and update values in `.env.example`.
2. Build and start the platform:

```bash
docker compose up --build
```

3. Access services:

- API: `http://localhost:8000`
- Frontend: `http://localhost:18080`
- Kibana: `http://localhost:5601`
- Greenbone UI: `http://localhost:9392`
- ZAP daemon: `http://localhost:8080`

On Windows, ports in the `5173` range may be reserved by the OS. This project defaults the Docker frontend to `FRONTEND_PORT=18080` to avoid that bind failure.

## Production recommendations

- Put the API and frontend behind an ingress controller or reverse proxy with TLS.
- Replace demo credentials with vault-backed secrets and rotate them automatically.
- Run Celery workers separately from the API and scale them by scan type.
- Move PostgreSQL to a managed HA deployment and enable PITR backups.
- Run Elasticsearch with dedicated storage and ILM policies for log retention.
- Use object storage for large reports and raw scanner artifacts.
- Package the Electron shell with signed installers for Windows, macOS, and Linux.

## Kubernetes-ready mapping

- `api`: Deployment + Service + HPA
- `worker`: Deployment + HPA
- `frontend`: Deployment + Service or static site bucket/CDN
- `postgres`, `redis`, `elasticsearch`: managed services where possible
- `openvas`, `zap`, `mobsf`: dedicated worker node pools or isolated namespaces
