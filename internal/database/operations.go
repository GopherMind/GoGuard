package database


import "time"

func Set(key string, value interface{}, ttl time.Duration) error {
	return Client.Set(Ctx, key, value, ttl).Err()
}

func Get(key string) (string, error) {
	return Client.Get(Ctx, key).Result()
}

func Incr(key string) error {
	return Client.Incr(Ctx, key).Err()
}

func Expire(key string, ttl time.Duration) error {
	return Client.Expire(Ctx, key, ttl).Err()
}
