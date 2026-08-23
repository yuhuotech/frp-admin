# Local Compose deployment

Create a local `.env` with a long one-time bootstrap token, then start the stack:

```bash
cp .env.example .env
docker compose up --build
```

Open `http://127.0.0.1:3000`. On first launch the UI asks for the bootstrap token and creates the administrator account.

The SQLite database and Agent PKI are stored in the `frp-admin-data` volume. Port `8443` is the Agent gRPC endpoint. For enrollment against the generated local CA, securely copy `data/pki/ca.crt` from the Server volume to the Agent host and pass it with the Agent enrollment CA option.

For production, terminate browser HTTPS at a reverse proxy, configure a stable DNS name in the Server certificate, set secure cookies, and use externally managed secrets. MySQL/PostgreSQL are selected through `FRP_ADMIN_DATABASE_DRIVER` and `FRP_ADMIN_DATABASE_DSN`; do not run more than one database backend for the same Server instance.

