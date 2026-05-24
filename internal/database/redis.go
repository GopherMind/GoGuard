package database

import (
	"context"

	"github.com/redis/go-redis/v9"
)

var (
	Ctx    = context.Background()
	Client *redis.Client
)

func InitRedis() {
	Client = redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})

	err := Client.Ping(Ctx).Err()

	if err != nil {
		panic(err)
	}
}
