# 🛡️ AI-Powered Cybersecurity Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen)](https://nodejs.org/)
[![MongoDB](https://img.shields.io/badge/MongoDB-4EA94B?logo=mongodb&logoColor=white)](https://www.mongodb.com/)
[![Redis](https://img.shields.io/badge/Redis-DC382D?logo=redis&logoColor=white)](https://redis.io/)
[![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)

**Author:** IRFAN AHMMED

A comprehensive, production-ready cybersecurity platform that combines vulnerability scanning, threat intelligence, AI/ML risk prediction, SOC automation, and real-time security monitoring in a unified SaaS solution.

## 🚀 Features

### Core Security Features
- **🔍 Vulnerability Scanning**
  - Nmap network scanning
  - Nikto web application scanning
  - Custom security assessments
  - Safe brute force simulations (SSH, FTP, HTTP)

- **🧠 Threat Intelligence**
  - CVE database integration
  - OSINT collection
  - Dark web monitoring (Tor onion crawling)
  - IOC enrichment and correlation

- **🤖 AI/ML Risk Prediction**
  - Python FastAPI ML microservice
  - sklearn/PyTorch integration
  - Automated risk scoring
  - Predictive threat analysis

- **📊 MITRE ATT&CK Integration**
  - Technique mapping
  - Heatmap visualization
  - D3/Cytoscape interactive charts

### SOC Automation
- **🚨 Automated Response**
  - Auto-generated playbooks
  - Containment & mitigation workflows
  - Firewall API integration
  - Okta identity management

- **📧 Advanced Notifications**
  - Telegram bot integration
  - Slack webhooks
  - Email alerts
  - Jira ticket auto-creation

### Enterprise Features
- **👥 Multi-Tenant SaaS**
  - Role-based access control (Admin, Manager, Analyst, Viewer)
  - Organization-level isolation
  - Usage tracking and limits

- **💰 Billing & Subscription**
  - Stripe payment integration
  - PayPal support
  - Multiple subscription tiers
  - Usage-based billing

- **📈 Real-time Dashboard**
  - Socket.IO live updates
  - D3.js data visualizations
  - Cytoscape network graphs
  - Executive reporting

### Security & Compliance
- **🔐 Enterprise Security**
  - JWT + bcrypt authentication
  - MFA support (TOTP)
  - Rate limiting & brute force protection
  - Comprehensive audit logging

- **📋 Compliance Reporting**
  - PDF/HTML report generation (Puppeteer/pdfkit)
  - SOC2, ISO27001, NIST frameworks
  - Executive summaries
  - Custom report templates

- **🎭 Phishing Simulation**
  - Safe phishing email campaigns
  - User training metrics
  - Template management
  - Awareness reporting

### DevSecOps Integration
- **🔧 CI/CD API**
  - Pre-deployment security scanning
  - Pipeline integration
  - Security gates
  - Vulnerability feedback

## 🏗️ Architecture

### Tech Stack
- **Frontend:** React 18 + Tailwind CSS + D3.js + Cytoscape.js
- **Backend:** Node.js + Express.js + MongoDB + Redis
- **ML Service:** Python + FastAPI + scikit-learn + PyTorch
- **Real-time:** Socket.IO
- **Queue System:** Bull (Redis-based)
- **Documentation:** Swagger/OpenAPI
- **Containerization:** Docker + Docker Compose
- **Orchestration:** Kubernetes ready

### System Components
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   React SPA     │    │   Node.js API   │    │  Python ML API  │
│   (Frontend)    │◄──►│   (Backend)     │◄──►│   (ML Service)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
    ┌─────────┐             ┌─────────┐             ┌─────────┐
    │ Nginx   │             │ MongoDB │             │  Redis  │
    │ (Proxy) │             │ (Data)  │             │ (Cache) │
    └─────────┘             └─────────┘             └─────────┘
         │                       │                       │
         │                  ┌─────────┐             ┌─────────┐
         └─────────────────►│ Docker  │◄────────────│ Bull    │
                           │Compose  │             │(Queues) │
                           └─────────┘             └─────────┘
```

## 📋 Prerequisites

- **Node.js** 18.0.0 or higher
- **MongoDB** 6.0 or higher
- **Redis** 7.0 or higher
- **Docker** 20.10+ and Docker Compose 2.0+
- **Python** 3.9+ (for ML service)
- **Git** for version control

### Optional Security Tools
- **Nmap** for network scanning
- **Nikto** for web application scanning
- **SQLMap** for SQL injection testing
- **Tor** for dark web intelligence

## 🚀 Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/cybersec-platform.git
cd cybersec-platform
```

### 2. Environment Setup
```bash
# Copy environment template
cp .env.example .env

# Edit environment variables
nano .env
```

### 3. Docker Deployment (Recommended)
```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Access the application
# Frontend: http://localhost:3000
# API: http://localhost:5000
# API Docs: http://localhost:5000/api-docs
# ML Service: http://localhost:8000
```

### 4. Manual Development Setup

#### Backend Setup
```bash
cd backend
npm install
npm run dev
```

#### Frontend Setup
```bash
cd frontend
npm install
npm start
```

#### ML Service Setup
```bash
cd ml-service
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

#### Database Setup
```bash
# Start MongoDB
mongod --dbpath ./data/db

# Start Redis
redis-server

# Initialize database
cd backend
npm run migrate
npm run seed
```

## 🔧 Configuration

### Environment Variables

#### Core Configuration
```env
NODE_ENV=development
PORT=5000
FRONTEND_URL=http://localhost:3000
MONGODB_URI=mongodb://localhost:27017/cybersec-platform
REDIS_URL=redis://localhost:6379
```

#### Security Configuration
```env
JWT_SECRET=your-super-secret-jwt-key
JWT_EXPIRE=24h
BCRYPT_ROUNDS=12
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
```

#### External Integrations
```env
# Stripe Billing
STRIPE_SECRET_KEY=sk_test_...
STRIPE_PUBLISHABLE_KEY=pk_test_...

# Notification Services
TELEGRAM_BOT_TOKEN=your-telegram-bot-token
SLACK_WEBHOOK_URL=https://hooks.slack.com/...

# Threat Intelligence APIs
CVE_API_KEY=your-cve-api-key
VIRUSTOTAL_API_KEY=your-virustotal-api-key
SHODAN_API_KEY=your-shodan-api-key
```

## 📚 API Documentation

### Authentication Endpoints
```http
POST /api/auth/register     # User registration
POST /api/auth/login        # User login
POST /api/auth/logout       # User logout
POST /api/auth/refresh      # Token refresh
GET  /api/auth/me          # Current user profile
```

### Scanning Endpoints
```http
GET    /api/scans           # List scans
POST   /api/scans           # Create scan
GET    /api/scans/:id       # Get scan details
POST   /api/scans/:id/start # Start scan
POST   /api/scans/:id/pause # Pause scan
DELETE /api/scans/:id       # Delete scan
```

### Dashboard Endpoints
```http
GET /api/dashboard/overview      # Dashboard overview
GET /api/dashboard/real-time     # Real-time metrics
GET /api/dashboard/mitre-heatmap # MITRE ATT&CK heatmap
GET /api/dashboard/risk-score    # Organization risk score
```

### Interactive API Documentation
- **Development:** http://localhost:5000/api-docs
- **Production:** https://your-domain.com/api-docs

## 🧪 Testing

### Backend Tests
```bash
cd backend
npm test                    # Run all tests
npm run test:watch         # Watch mode
npm run test:coverage      # Coverage report
```

### ML Service Tests
```bash
cd ml-service
pytest                     # Run Python tests
pytest --cov=src          # Coverage report
```

### Integration Tests
```bash
# E2E tests
npm run test:e2e

# API tests
npm run test:api
```

## 🚀 Deployment

### Production Deployment with Docker

#### 1. Production Environment
```bash
# Set production environment
export NODE_ENV=production

# Build production images
docker-compose -f docker-compose.prod.yml build

# Deploy with Docker Swarm
docker stack deploy -c docker-compose.prod.yml cybersec-platform
```

#### 2. Kubernetes Deployment
```bash
# Apply Kubernetes manifests
kubectl apply -f k8s/

# Scale services
kubectl scale deployment backend --replicas=3
kubectl scale deployment ml-service --replicas=2
```

### Cloud Deployment Options

#### Render.com
```bash
# Deploy backend
render deploy --service backend

# Deploy frontend
render deploy --service frontend
```

#### Vercel (Frontend)
```bash
# Deploy React frontend
vercel --prod
```

#### Railway
```bash
# Deploy full stack
railway up
```

### Environment-Specific Configurations

#### Production Optimizations
- Enable Redis clustering
- Configure MongoDB replica sets
- Set up load balancing
- Enable SSL/TLS termination
- Configure CDN for static assets

## 🔐 Security Considerations

### Authentication & Authorization
- JWT tokens with expiration
- MFA support with TOTP
- Role-based access control
- API rate limiting
- Brute force protection

### Data Protection
- Encryption at rest
- TLS/SSL in transit
- Input validation & sanitization
- XSS protection
- CSRF protection
- SQL injection prevention

### Infrastructure Security
- Container security scanning
- Dependency vulnerability checks
- Security headers
- OWASP compliance
- Regular security audits

## 📊 Monitoring & Logging

### Application Monitoring
- Winston structured logging
- ELK Stack integration (Elasticsearch, Logstash, Kibana)
- Performance metrics
- Error tracking
- Health checks

### Security Monitoring
- Authentication events
- Failed login attempts
- API access patterns
- Vulnerability scan results
- Threat intelligence feeds

## 🛠️ Development

### Project Structure
```
cybersec-platform/
├── frontend/               # React frontend
│   ├── src/
│   │   ├── components/     # React components
│   │   ├── pages/         # Page components
│   │   ├── hooks/         # Custom hooks
│   │   └── utils/         # Utility functions
│   ├── tailwind.config.js
│   └── package.json
├── backend/               # Node.js backend
│   ├── src/
│   │   ├── controllers/   # Request handlers
│   │   ├── routes/        # Express routes
│   │   ├── middleware/    # Custom middleware
│   │   ├── models/        # MongoDB models
│   │   ├── services/      # Business logic
│   │   └── config/        # Configuration
│   ├── Dockerfile
│   └── package.json
├── ml-service/            # Python ML API
│   ├── main.py           # FastAPI application
│   ├── models/           # ML models
│   ├── utils/            # Utility functions
│   └── requirements.txt
├── intel-collectors/      # Intelligence gathering
│   ├── darkweb_crawler.py
│   ├── cve_feed.py
│   └── ioc_enrichment.py
├── shared-utils/          # Shared utilities
│   ├── pdf_report/
│   ├── mitre_mapper/
│   └── slack_notifier/
├── scripts/               # Database scripts
│   ├── migrate.js
│   └── seed.js
├── docker-compose.yml
├── .github/workflows/     # CI/CD
└── README.md
```

### Contributing
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

### Code Style
- ESLint (Airbnb configuration)
- Prettier code formatting
- Conventional commits
- Comprehensive documentation

## 📞 Support

### Documentation
- [API Documentation](http://localhost:5000/api-docs)
- [User Guide](./docs/user-guide.md)
- [Administrator Manual](./docs/admin-guide.md)
- [Developer Guide](./docs/developer-guide.md)

### Community
- [GitHub Issues](https://github.com/your-username/cybersec-platform/issues)
- [Discussions](https://github.com/your-username/cybersec-platform/discussions)
- [Security Advisory](./SECURITY.md)

### Commercial Support
For enterprise support, custom development, and consulting services, contact: **IRFAN AHMMED**

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- MITRE ATT&CK Framework
- OWASP Security Guidelines
- NIST Cybersecurity Framework
- CVE Program
- Open Source Security Community

---

**Built with ❤️ by IRFAN AHMMED**

*Empowering organizations with AI-driven cybersecurity solutions*