FROM node:20-alpine AS builder
WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install

COPY . ./

FROM node:20-alpine
WORKDIR /app

COPY --from=builder /app ./
RUN apk add --no-cache postgresql-client

EXPOSE 4000
CMD ["sh", "-c", "until pg_isready -h postgres -U postgres; do echo waiting for postgres; sleep 1; done; npm run init-db && npm run dev"]
