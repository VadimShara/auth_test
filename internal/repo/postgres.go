package repo

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kuromii5/auth-part/internal/config"
	"github.com/kuromii5/auth-part/internal/models"
)

var (
	ErrSessionNotFound = errors.New("user session not found")
)

func PGConnectionStr(config config.PostgresConfig) string {
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=%s",
		config.User,
		config.Password,
		config.Host,
		config.Port,
		config.DBName,
		config.SSLMode,
	)
}

type DB struct {
	Pool *pgxpool.Pool
}

func NewDB(config config.PostgresConfig) *DB {
	dbUrl := PGConnectionStr(config)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	poolConfig, err := pgxpool.ParseConfig(dbUrl)
	if err != nil {
		log.Fatal("unable to parse db url")
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		log.Fatal("unable to connect to db")
	}

	return &DB{Pool: pool}
}

func (db *DB) Close() {
	db.Pool.Close()
}

func (d *DB) SaveSession(session models.Session) error {
	const query = "INSERT INTO sessions (user_id, access_token_jti, refresh_token, refresh_token_exp, client_ip) VALUES ($1, $2, $3, $4, $5)"

	_, err := d.Pool.Exec(context.Background(), query, session.UserID, session.AccessTokenJTI, session.RefreshToken, session.RefreshTokenExp, session.ClientIP)
	if err != nil {
		return fmt.Errorf("failed to save session: %w", err)
	}

	return nil
}

func (d *DB) DeleteSession(sessionID int) error {
	const query = `DELETE FROM sessions WHERE id = $1`

	_, err := d.Pool.Exec(context.Background(), query, sessionID)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	return nil
}

func (d *DB) GetSession(jti string) (models.Session, error) {
	const query = `
		SELECT id, user_id, access_token_jti, refresh_token, refresh_token_exp, client_ip, created_at, updated_at
		FROM sessions
		WHERE access_token_jti = $1;
	`

	var session models.Session
	err := d.Pool.QueryRow(context.Background(), query, jti).Scan(
		&session.ID,
		&session.UserID,
		&session.AccessTokenJTI,
		&session.RefreshToken,
		&session.RefreshTokenExp,
		&session.ClientIP,
		&session.CreatedAt,
		&session.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return models.Session{}, ErrSessionNotFound
		}
		return models.Session{}, fmt.Errorf("failed to get session: %w", err)
	}

	return session, nil
}
