# AI Threat Detection - Backend Architecture

## Table of Contents
1. [System Architecture](#system-architecture)
2. [Core Components](#core-components)
3. [API Endpoints](#api-endpoints)
4. [Data Models](#data-models)
5. [Machine Learning Pipeline](#machine-learning-pipeline)
6. [Database Schema](#database-schema)
7. [Authentication & Authorization](#authentication--authorization)
8. [Testing Strategy](#testing-strategy)
9. [Deployment](#deployment)
10. [Monitoring & Logging](#monitoring--logging)

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Backend Services                        │
├─────────────────────────────────────────────────────────────┤
│  ┌───────────────┐    ┌─────────────────┐  ┌─────────────┐  │
│  │ API Gateway   │    │ Stream          │  │ Batch       │  │
│  │ (FastAPI)     │◄──►│ Processing      │◄─► Processing  │  │
│  └───────┬───────┘    │ (Kafka Streams) │  │ (Airflow)   │  │
│          │            └─────────────────┘  └─────────────┘  │
│          v                           │                      │
│  ┌───────────────┐            ┌─────┴────────┐             │
│  │ Authentication│            │ ML Model     │             │
│  │ &             │            │ Serving      │             │
│  │ Authorization │            └──────────────┘             │
│  └───────────────┘                      │                   │
│          │                              │                   │
│          v                              v                   │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                     Database Layer                    │  │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────────┐   │  │
│  │  │ PostgreSQL │  │  Redis     │  │   Elasticsearch │   │  │
│  │  │ (Metadata) │  │  (Cache)   │  │   (Logs/Search) │   │  │
│  │  └────────────┘  └────────────┘  └────────────────┘   │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. API Service (FastAPI)
- RESTful API endpoints for frontend communication
- WebSocket support for real-time updates
- Request validation and response formatting
- Rate limiting and request throttling

### 2. Stream Processing (Kafka)
- Real-time event processing
- Anomaly detection on streaming data
- Alert generation and notification

### 3. Batch Processing (Airflow)
- Scheduled model retraining
- Data aggregation and reporting
- Historical analysis

### 4. ML Model Serving
- Model versioning and A/B testing
- Online predictions
- Model monitoring and drift detection

### 5. Authentication Service
- JWT-based authentication
- Role-based access control (RBAC)
- API key management

## API Endpoints

### Authentication
- `POST /api/auth/token` - User login (OAuth2 password flow)
- `POST /api/auth/register` - User registration
- `GET /api/auth/me` - Get current authenticated user

### Alerts
- `GET /api/alerts/` - List all alerts
- `POST /api/alerts/` - Create new alert

### Incidents
- `GET /api/incidents/` - List all incidents
- `POST /api/incidents/` - Create new incident

### Users
- `GET /api/users/` - List all users
- `POST /api/users/` - Create new user
- `GET /api/users/{user_id}` - Get user details

### Models
- Not implemented in current codebase

## Data Models

### Alert
```python
class Alert(BaseModel):
    id: int
    detected_at: datetime
    severity: Literal["low", "medium", "high", "critical"]
    type: str
    source: str
    description: str
    status: str
    metadata: dict
    related_entities: List[Entity]
    related_alerts: List[int]
```

### Incident
```python
class Incident(BaseModel):
    id: int
    title: str
    description: str
    status: Literal["open", "investigating", "contained", "resolved"]
    severity: Literal["low", "medium", "high", "critical"]
    created_at: datetime
    updated_at: datetime
    assigned_to: Optional[int]  # User ID
    related_alerts: List[int]
    comments: List[Comment]
    tags: List[str]
```

## Machine Learning Pipeline

1. **Data Collection**
   - Network traffic (PCAP, NetFlow)
   - System logs
   - Authentication logs

2. **Feature Engineering**
   - Time-based features
   - Statistical features
   - Behavioral patterns
   - Network graph features

3. **Model Training**
   - Isolation Forest for anomaly detection
   - LSTM for sequence-based detection
   - Random Forest for classification

4. **Model Serving**
   - REST API for real-time inference
   - Batch prediction service
   - Model versioning

## Database Schema

### alerts
- id (int, PK)
- detected_at (timestamp)
- source (string)
- type (string)
- severity (enum)
- status (enum)
- metadata (JSON)
- created_at (timestamp)
- updated_at (timestamp)

### incidents
- id (int, PK)
- title (string)
- description (text)
- type (enum)
- status (enum)
- severity (enum)
- created_by (int, FK)
- assigned_to (int, FK, nullable)
- created_at (timestamp)
- updated_at (timestamp)

## Authentication & Authorization

### JWT Authentication
- Access tokens (short-lived)
- Refresh tokens (long-lived)
- Token blacklisting

### Roles
- Admin: Full system access
- Analyst: View and manage alerts/incidents
- Viewer: Read-only access

## Testing Strategy

### Unit Tests
- Individual component testing
- Mock external dependencies
- Test business logic

### Integration Tests
- API endpoint testing
- Database operations
- Service interactions

### Load Testing
- API performance testing
- Concurrent user simulation
- Stress testing

## Deployment

### Development
- Docker Compose for local development
- Hot-reload for development
- Local database instances

### Production
- Kubernetes cluster
- Horizontal pod autoscaling
- Database replication
- CI/CD pipeline

## Monitoring & Logging

### Metrics
- Request rates
- Error rates
- Latency percentiles
- Resource utilization

### Logging
- Structured JSON logging
- Log aggregation (ELK Stack)
- Log retention policies

### Alerting
- System health alerts
- Anomaly detection alerts
- On-call rotation

## Development Setup

### Prerequisites
- Python 3.9+
- Docker & Docker Compose
- Make

### Local Development
```bash
# Clone the repository
git clone <repository-url>
cd wind

# Set up environment
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate

# Install dependencies
pip install -r requirements-dev.txt

# Start services
docker-compose up -d

# Run migrations
alembic upgrade head

# Start development server
uvicorn app.main:app --reload
```

## Next Steps

1. Implement core data collection services
2. Set up the ML pipeline
3. Develop the API endpoints
4. Build the authentication system
5. Create monitoring and alerting
6. Implement the frontend dashboard
7. Set up CI/CD pipelines
8. Prepare production deployment

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
