package config

import (
	"log"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
	"github.com/joho/godotenv"
)

type Config struct {
	Env      string `env:"ENV" env-default:"local"`
	LogLevel string `env:"LOG_LEVEL" env-default:"info"`

	Port        int           `env:"PORT" env-required:"true"`
	IdleTimeout time.Duration `env:"IDLE_TIMEOUT" env-default:"10s"`
	ReqTimeout  time.Duration `env:"REQUEST_TIMEOUT" env-default:"5s"`

	AppEmail    string `env:"APP_EMAIL" env-required:"true"`
	AppPassword string `env:"APP_PASSWORD" env-required:"true"`
	SmtpHost    string `env:"SMTP_HOST" env-required:"true"`

	TokenConfig TokenConfig
	PGConfig    PostgresConfig
}

type TokenConfig struct {
	AccessTTL  time.Duration `env:"ACCESS_TOKEN_TTL" env-default:"15m"`
	RefreshTTL time.Duration `env:"REFRESH_TOKEN_TTL" env-default:"720h"`
	Secret     string        `env:"TOKEN_SECRET" env-required:"true"`
}

type PostgresConfig struct {
	User     string `env:"POSTGRES_USER" env-required:"true"`
	Password string `env:"POSTGRES_PASSWORD" env-required:"true"`
	Host     string `env:"POSTGRES_HOST" env-required:"true"`
	Port     int    `env:"POSTGRES_PORT" env-required:"true"`
	DBName   string `env:"POSTGRES_DBNAME" env-required:"true"`
	SSLMode  string `env:"POSTGRES_SSLMODE" env-default:"disable"`
}

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
}

func Load() Config {
	var config Config

	if err := cleanenv.ReadEnv(&config); err != nil {
		log.Fatal("couldn't bind settings to config")
	}

	return config
}
