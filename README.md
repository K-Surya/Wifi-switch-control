# WiFi Switch Control

A Node.js web app for two ESP32 relay switches. The browser talks to this server; MQTT credentials and broker traffic stay on the server.

## MQTT topics

- `esp32/health`: every message refreshes the node's online status. It becomes offline after `HEALTH_ONLINE_TIMEOUT_MS` without a message (30 seconds by default).
- `esp32/switch1` and `esp32/switch2`: subscribe for reported state; publish `ON` or `OFF` when the matching toggle is used.

The toggle reflects the last reported state and is enabled as soon as the broker connects. If no state has arrived yet, its first tap sends `ON`; later taps switch the requested value until the ESP32 reports a state. Publish retained switch states from the ESP32 to show the actual state immediately after startup. Commands are not retained.

## Configure credentials and broker

Set app credentials in `.env` using `APP_USERNAME` and `APP_PASSWORD`. `.env.example` intentionally leaves both empty; the app has no built-in username or password. Keep `.env` private.

Alternatively, set `CREDENTIALS_FILE` to a server-side JSON file containing string fields named `username` and `password`. Do not configure both credential methods. Keep the file readable only by the service account and do not commit it.

Set `MQTT_URL` to the broker address (defaults to `mqtt://192.168.1.11:1883`). `MQTT_USERNAME` and `MQTT_PASSWORD` are optional if the broker allows anonymous access. Set a strong `HEALTH_ONLINE_TIMEOUT_MS` value that fits the ESP32 heartbeat interval.

## Local development

Use Node.js 22 or newer. Set the required values in `.env`, then start the app:

```sh
npm install
npm start
```

Open `http://localhost:3000`. The browser and this computer must be able to reach the app and broker respectively. Web Crypto is available on localhost, so the login challenge works for local testing over HTTP.

## Login and session security

The browser derives a password verifier with PBKDF2-SHA-256 and proves it against a single-use server challenge with HMAC. The password itself is not sent to the app server. This does not replace HTTPS: a network attacker who can alter the served JavaScript could capture the password. Use HTTPS outside localhost. In production mode the server refuses login unless the reverse proxy forwards `X-Forwarded-Proto: https`.

After login, the browser receives a 30-day persistent HttpOnly, SameSite=Strict cookie. The server stores only a SHA-256 hash of the random session token in `data/sessions.json`; logout revokes the token. Keep the data directory private. Local sessions survive server restarts.

Login attempts are limited to eight failures per client address in a 15-minute window. Use a reverse proxy that forwards the original client address correctly if you need separate limits per remote user.

## Docker Compose and HTTPS

Configure `.env`, then run:

```sh
docker compose up -d --build
```

Compose binds the app to `127.0.0.1:3000`, attaches a persistent Docker volume for sessions, and uses production mode. Put Nginx or another HTTPS reverse proxy in front. It must set `X-Forwarded-Proto` to the incoming scheme, overwrite `X-Forwarded-For` with the actual client address, and preserve the `Host` header. Do not expose the app port directly to untrusted networks.

The container must be able to route to the MQTT broker. Restrict its MQTT account to the three app topics where the broker supports topic ACLs.

## Configuration

| Variable | Purpose | Default |
| --- | --- | --- |
| `PORT` | Web server port | `3000` |
| `MQTT_URL` | MQTT broker URL | `mqtt://192.168.1.11:1883` |
| `MQTT_USERNAME` / `MQTT_PASSWORD` | Optional broker login | unset |
| `MQTT_CLIENT_ID` | MQTT client ID | generated at startup |
| `HEALTH_ONLINE_TIMEOUT_MS` | Time without health message before offline | `30000` |
| `APP_USERNAME` / `APP_PASSWORD` | App login credentials | required unless using file |
| `CREDENTIALS_FILE` | Path to JSON credential file | unset |
| `SESSION_STORE_FILE` | Persistent hashed session store | `data/sessions.json` |
| `TRUST_PROXY` | Trust proxy-supplied client address for login limits | `false` |
