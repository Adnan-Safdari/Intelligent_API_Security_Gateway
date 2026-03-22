# Intelligent API Security Gateway — Demo Frontend

A minimal React (Vite) frontend for demonstrating API attacks and gateway protection.

## Structure

```
src/
  pages/
    Login.jsx       ← Auth demo + spam/slow attack buttons
    Products.jsx    ← Data fetch demo + spam/slow attack buttons
  services/
    api.js          ← All API calls via gateway (localhost:8080)
  App.jsx           ← Shell with nav, no routing library
  App.css           ← Dark terminal aesthetic
  main.jsx          ← Vite entry point
```

## Setup

```bash
npm install
npm run dev
```

Frontend runs on **http://localhost:3000**  
All API traffic routes through **http://localhost:8080** (your gateway)

## Attack Modes

| Button | Behavior |
|---|---|
| ▶ Login / ↻ Reload | Single normal request |
| 🔥 Spam Attack | 50–100 requests fired simultaneously (Promise.all) |
| 🐢 Slow Attack | 20 requests with 100ms delay between each |

## API Endpoints Expected

| Method | Path | Used by |
|---|---|---|
| POST | /login | Login page — body: `{ username, password }` |
| GET | /products | Products page |

All responses are shown in the live traffic log panel. HTTP status codes
are color-coded: green = 2xx, red = 4xx/5xx/network error, orange = attack markers.
