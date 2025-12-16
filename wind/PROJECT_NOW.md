# What This Project Does (Current State)

This repository is a **FastAPI-based backend** for an **AI Threat Detection / SOC-style platform**.

It currently provides:
- **User management** (create/list/get)
- **Authentication** using JWT access tokens (OAuth2 password flow)
- **Alerts** management (create/list)
- **Incidents** management (create/list)
- A **health check** endpoint that verifies DB connectivity

The project is connected to a **PostgreSQL** database via SQLAlchemy.

## How To Run

### 1) Start the server
On Windows, run:

```powershell
.\venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

The server will run at:
- http://127.0.0.1:8000

API docs:
- http://127.0.0.1:8000/docs

Health check:
- http://127.0.0.1:8000/health

### 2) Database
The backend expects a PostgreSQL database configured via `DATABASE_URL`.

## Available API Endpoints (Current)

Base prefix: **`/api`**

### Authentication
- `POST /api/auth/register`
  - Create a new user
- `POST /api/auth/token`
  - Login and receive a JWT access token
- `GET /api/auth/me`
  - Get the current user (requires `Authorization: Bearer <token>`)

### Users
- `GET /api/users/`
- `POST /api/users/`
- `GET /api/users/{user_id}`

### Alerts
- `GET /api/alerts/`
- `POST /api/alerts/`

### Incidents
- `GET /api/incidents/`
- `POST /api/incidents/`

## Working End-to-End Flows

### Auth flow (verified)
1. Register: `POST /api/auth/register`
2. Login: `POST /api/auth/token`
3. Fetch profile: `GET /api/auth/me`

### Alerts flow (verified)
1. Create: `POST /api/alerts/`
2. List: `GET /api/alerts/`

### Incidents flow (verified)
1. Create: `POST /api/incidents/`
2. List: `GET /api/incidents/`

### Users flow (verified)
1. Create: `POST /api/users/`
2. List: `GET /api/users/`
3. Get by id: `GET /api/users/{user_id}`

## Notes About Current Design

- IDs are currently **integers** (not UUIDs).
- The API uses **`/api/...`** paths (not `/api/v1/...`).
- JWT token subject (`sub`) currently uses the **username** (with an email fallback in lookup).

## Database / Migrations

- Alembic migrations are set up under `migrations/`.
- A migration was added to create the missing `incident_entities` table.

To apply migrations:

```powershell
.\venv\Scripts\python.exe -m alembic upgrade head
```

## What’s Next (Future Work)

Common next steps for this project:
- Add update/delete endpoints for alerts/incidents/users
- Add role-based authorization on endpoints (admin/analyst/viewer)
- Add filtering, pagination, and search for alerts/incidents
- Implement the "Models" endpoints described in architecture docs (not currently implemented)
- Add automated tests for API and DB
