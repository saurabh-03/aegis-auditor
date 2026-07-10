# Kubernetes deployment

Manifests for a production-shaped Aegis deployment: a horizontally-scaled **API**
(enqueues scans, serves REST + dashboard) and separately-scaled **workers** (run
the engine, including the headless-browser Core Web Vitals module), backed by
PostgreSQL and Redis.

```
config.yaml   namespace + ConfigMap + Secret template
data.yaml     PostgreSQL + Redis (swap for managed services in prod)
api.yaml      API Deployment (AEGIS_ROLE=api) + Service + Ingress (+ migrate initContainer)
worker.yaml   Worker Deployment (AEGIS_ROLE=worker) + HPA
kustomization.yaml
```

## Deploy

```bash
# 1) Build & push the image (repo root Dockerfile)
docker build -t ghcr.io/you/aegis-auditor:$(git rev-parse --short HEAD) .
docker push ghcr.io/you/aegis-auditor:<sha>

# 2) Point kustomize at your image + real secrets (use sealed-secrets/external-secrets)
cd k8s
kustomize edit set image aegis-auditor=ghcr.io/you/aegis-auditor:<sha>

# 3) Apply
kubectl apply -k .
kubectl -n aegis rollout status deploy/aegis-api
```

## Notes

- **Roles.** `AEGIS_ROLE=api` enqueues only; `AEGIS_ROLE=worker` processes scans.
  Scale them independently. The CWV browser run happens on workers (higher memory
  limit for Chromium); the API defers it (see `webvitals.ts`).
- **Migrations.** The API's `migrate` initContainer runs `prisma migrate deploy`.
  It needs the Prisma CLI in the image — either build a variant that keeps dev
  deps, or run migrations as a one-off `Job` with a migration image.
- **Secrets.** `config.yaml` ships a *template* Secret with placeholders. Never
  commit real values — use sealed-secrets, external-secrets, or your platform's
  secret store, and replace `POSTGRES_PASSWORD` / `JWT_SECRET` at minimum.
- **WebSockets.** Live scan progress (`/api/scans/:id/stream`) needs long proxy
  timeouts; the Ingress sets them for nginx-ingress. Adjust for your controller.
- **Queue-depth autoscaling.** The included HPA scales workers on CPU. For
  scale-to-demand on backlog, install [KEDA](https://keda.sh) and add a
  `ScaledObject` with the Redis-list trigger on the BullMQ queue key.
- **TLS.** The Ingress references a `aegis-tls` secret; provision it with
  cert-manager (`Certificate`) or your platform.
