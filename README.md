# Socket Chat App

Realtime Socket.IO chat protected by OIDC login.

## Run locally

```sh
npm install
npm run dev
```

The app runs on `http://localhost:9000`.

## OIDC environment variables

Set these before running or deploying:

```sh
OIDC_ISSUER=https://autho.brewcodex.online/
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret
SESSION_SECRET=replace-with-a-long-random-secret
BASE_URL=http://localhost:9000
PORT=9000
```

For production, set `BASE_URL` to your deployed app URL, for example:

```sh
BASE_URL=https://chat.your-domain.com
```

In the OIDC server, add this redirect/callback URL:

```text
https://chat.your-domain.com/auth/callback
```

For local testing, add:

```text
http://localhost:9000/auth/callback
```
