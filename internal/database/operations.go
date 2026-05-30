package database


import (
	"context"
	"time"
)

func Set(key string, value interface{}, ttl time.Duration) error {
	return Client.Set(Ctx, key, value, ttl).Err()
}

func Get(key string) (string, error) {
	return Client.Get(Ctx, key).Result()
}

func Incr(ctx context.Context, key string) (int64, error) {
	return Client.Incr(ctx, key).Result()
}

func Expire(key string, ttl time.Duration) error {
	return Client.Expire(Ctx, key, ttl).Err()
}

func Del(key string) error {
	return Client.Del(Ctx, key).Err()
}

