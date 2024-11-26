# AUTH_PART

Auth-Part is a basic authentication microservice designed to handle user authentication and session management. It includes JWT-based token issuance and refreshing mechanisms, along with IP-based session validation and email warnings for suspicious activities.

## Getting Started

### Configuration

You can configure the service using environment variables. Below is an example of the configuration:

```env
# APP Configuration
ENV=local
LOG_LEVEL=debug

# HTTP Server Configuration
PORT=8080
IDLE_TIMEOUT=10s
REQUEST_TIMEOUT=5s

# Token Configuration
ACCESS_TOKEN_TTL=15m
REFRESH_TOKEN_TTL=720h
TOKEN_SECRET=my_secret

# PostgreSQL Configuration
POSTGRES_USER=postgres
POSTGRES_PASSWORD=admin
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_DBNAME=auth-part
POSTGRES_SSLMODE=disable

# Email Warnings Configuration
APP_EMAIL=my_email@gmail.com
APP_PASSWORD=3289hn923cdh923
SMTP_HOST=smtp.gmail.com
```

### API Endpoints

#### 1. Issue Tokens

**Endpoint:** `GET /auth/tokens?user_id={uuid}`

- **Description:** Issues a new pair of Access and Refresh tokens for the specified user. These tokens are set as HTTP-only cookies in the response.
- **Request:**

  - **Method:** `GET`
  - **Query Parameters:**
    - `user_id` (UUID) - The unique identifier of the user for whom the tokens are being issued.

- **Response:**
  - **Cookies:**
    - `access_token` - JWT access token.
    - `refresh_token` - Base64-encoded refresh token.

#### 2. Refresh Tokens

**Endpoint:** `POST /auth/refresh`

- **Description:** Refreshes the Access and Refresh tokens using the tokens stored in the HTTP-only cookies. The IP address is validated, and if changed, an email warning is sent.

- **Request:**
  - **Method:** `POST`
  - **Headers:**
    - Ensure that `access_token` and `refresh_token` cookies are included in the request.
- **Response:**
  - **Cookies:**
    - New `access_token` and `refresh_token` cookies are issued.
