package main

import (
	"context"
	"database/sql"
	"kernalert/config"
	"kernalert/pkg/server"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/go-redis/redis/v8"
	_ "github.com/lib/pq"
)

type KernelReport struct {
	Hostname  string   `json:"hostname"`
	Modules   []string `json:"modules"`
	DmesgLogs []string `json:"dmesg_logs"`
}

func init() {
	config.TelegramBotToken = os.Getenv("TELEGRAM_BOT_TOKEN")
	config.TelegramChatID = os.Getenv("TELEGRAM_CHAT_ID")

	for _, mod := range config.AllowedModules {
		config.AllowedSet[mod] = struct{}{}
	}

	configDir := os.Getenv("CONFIG_DIR")
	if configDir == "" {
		configDir = "config"
		log.Printf("[DEBUG] CONFIG_DIR not set, using default: %s", configDir)
	} else {
		log.Printf("[DEBUG] Using CONFIG_DIR: %s", configDir)
	}

	configPath := filepath.Join(configDir, "alert_config.json")
	log.Printf("[DEBUG] Loading alert config from path: %s", configPath)

	if err := config.LoadAlertConfig(configPath); err != nil {
		log.Printf("[ERROR] Failed to load alert config: %v", err)
	}
}

func main() {
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbUser := os.Getenv("DB_USER")
	dbPass := os.Getenv("DB_PASS")
	dbName := os.Getenv("DB_NAME")
	redisAddr := os.Getenv("REDIS_ADDR")
	tlsCert := os.Getenv("TLS_CERT")
	tlsKey := os.Getenv("TLS_KEY")

	connStr := "host=" + dbHost + " port=" + dbPort + " user=" + dbUser + " password=" + dbPass + " dbname=" + dbName + " sslmode=disable"

	var err error
	server.DB, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Error connecting to PostgreSQL: %v", err)
	}
	if err = server.DB.Ping(); err != nil {
		log.Fatalf("PostgreSQL is not responding: %v", err)
	}
	defer server.DB.Close()

	_, err = server.DB.Exec(`CREATE TABLE IF NOT EXISTS reports (
		id           SERIAL PRIMARY KEY,
		host         TEXT,
		time         TIMESTAMP,
		modules      TEXT,
		dmesg        TEXT,
		full_report  JSONB
	)`)
	if err != nil {
		log.Fatalf("Error creating table in DB: %v", err)
	}

	server.RDB = redis.NewClient(&redis.Options{Addr: redisAddr})
	ctx := context.Background()
	if _, err = server.RDB.Ping(ctx).Result(); err != nil {
		log.Fatalf("Error connecting to Redis: %v", err)
	}
	defer server.RDB.Close()

	http.HandleFunc("/report", server.HandleReport)

	log.Printf("Server is running, waiting for connections on port 8443 (HTTPS)")
	log.Printf("Telegram configuration: Bot Token: %v, Chat ID: %v",
		config.TelegramBotToken != "", config.TelegramChatID != "")

	err = http.ListenAndServeTLS(":8443", tlsCert, tlsKey, nil)
	if err != nil {
		log.Fatalf("Error starting HTTPS server: %v", err)
	}
}
