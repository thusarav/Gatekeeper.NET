# Gatekeeper.NET 🛡️  

### ASP.NET Core API Gateway with JWT Authentication

Gatekeeper.NET is a security-focused API Gateway built using **ASP.NET Core** and **YARP (Yet Another Reverse Proxy)**.  
It centralizes request routing and **JWT-based authentication** for backend services, enforcing authorization policies at the gateway layer before forwarding requests.

The project follows real-world backend and microservice architecture patterns by keeping authentication and access control at the gateway, while backend services remain stateless and authentication-agnostic.

---

##  Key Features

- API Gateway built with **ASP.NET Core**
- Reverse proxy routing using **YARP**
- Centralized **JWT authentication**
- Role-based access control (RBAC) at the gateway
- Authorization enforced at the gateway layer
- Stateless backend services
- Clean separation of gateway and service responsibilities
- Developed and tested on **Linux (Linux Mint)**

---

##  Architecture Overview
1. Client requests a token from:
2. Gatekeeper issues a signed JWT with claims and expiry
3. Client includes the token in subsequent requests:
4. Gatekeeper validates the JWT and evaluates authorization policies
5. Authorized requests are forwarded to backend services
6. Unauthorized requests receive `401 Unauthorized`

---
## High-level structure:

Client
  ↓
Gatekeeper (JWT + RBAC + YARP)
  ├── /service-a/*  → ServiceA
  └── /admin/*      → ServiceAdmin

## Role-Based Access Control (RBAC)

Authorization is enforced centrally at the API Gateway using JWT role claims.

Supported Roles

User – default role issued at login

Admin – elevated role for administrative service




## 📡 Example Requests

### Get JWT Token
http://localhost:5168/auth/login

## Get JWT Token (Admin)
POST http://localhost:5168/auth/login?role=Admin


### Access Protected Backend Route
GET http://localhost:5168/service-a/hello
Authorization: Bearer <JWT>

## Access Admin-Only Route
GET http://localhost:5168/admin/dashboard
Authorization: Bearer <ADMIN_JWT>

## 🛠️ Running the Project Locally

### Prerequisites
- .NET 8 SDK
- Linux / macOS / Windows

### Run Backend Services
```bash
dotnet run --project backends/ServiceA
dotnet run --project Gatekeeper
