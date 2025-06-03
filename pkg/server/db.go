package server

import (
	"context"
	"database/sql"

	"github.com/go-redis/redis/v8"
)

var (
	DB  *sql.DB
	RDB *redis.Client
)

func InitDB(connStr string) error {
	var err error
	DB, err = sql.Open("postgres", connStr)
	if err != nil {
		return err
	}
	if err = DB.Ping(); err != nil {
		return err
	}
	return nil
}

func InitRedis(addr string) error {
	RDB = redis.NewClient(&redis.Options{Addr: addr})
	if _, err := RDB.Ping(context.Background()).Result(); err != nil {
		return err
	}
	return nil
}

func CloseDB() error {
	if DB != nil {
		return DB.Close()
	}
	return nil
}

func CloseRedis() error {
	if RDB != nil {
		return RDB.Close()
	}
	return nil
}
