# syntax=docker/dockerfile:1.7
FROM node:24-alpine AS deps
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

# Vite dev server
FROM deps AS dev
COPY . .
EXPOSE 5173
CMD ["pnpm", "dev", "--host", "0.0.0.0"]

FROM deps AS build
COPY . .
RUN pnpm build

FROM nginxinc/nginx-unprivileged:stable-alpine@sha256:f5116ed4606f3eb015dd4a8e28cb9b351476dc0ad4bc6e9f93b19cec130cdf03 AS runtime
ENV BACKEND_URL=http://backend:8000 \
    MAX_UPLOAD_MB=50 \
    REAL_IP_FROM=127.0.0.1/32 \
    NGINX_ENVSUBST_FILTER="^(BACKEND_URL|MAX_UPLOAD_MB|REAL_IP_FROM)$"
COPY nginx/default.conf.template /etc/nginx/templates/default.conf.template
COPY nginx/security-headers.conf /etc/nginx/snippets/security-headers.conf
COPY nginx/docs-security-headers.conf /etc/nginx/snippets/docs-security-headers.conf
COPY --from=build /app/dist /usr/share/nginx/html
USER 101
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --retries=5 CMD wget -qO- http://127.0.0.1:8080/nginx-health || exit 1
