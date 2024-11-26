CREATE TABLE sessions(
    id SERIAL PRIMARY KEY,
    user_id UUID NOT NULL,
    access_token_jti VARCHAR(255) NOT NULL,
    refresh_token TEXT NOT NULL,
    refresh_token_exp TIMESTAMP NOT NULL,
    client_ip VARCHAR(50) NOT NULL,
    updated_at TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW()
);