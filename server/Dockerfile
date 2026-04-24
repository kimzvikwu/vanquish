FROM node:20-alpine AS builder
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev
COPY . ./

FROM node:20-alpine
WORKDIR /app
COPY --from=builder /app ./
RUN apk add --no-cache postgresql-client

EXPOSE 4000
ENTRYPOINT ["/app/docker-entrypoint.sh"]
