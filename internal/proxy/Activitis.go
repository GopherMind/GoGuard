package proxy

import (
	"GoGuard/internal/database"
	"fmt"
	"log"
	"strconv"
)

func CheckActivity() {
	for host, domain := range Domains {
		key := fmt.Sprintf("requests:%s", host)

		// Получаем количество запросов из Redis
		val, err := database.Get(key)
		if err != nil {
			log.Printf("[%s] No activity data in Redis", host)
			continue
		}

		// Конвертируем в число
		requestCount, err := strconv.Atoi(val)
		if err != nil {
			log.Printf("[%s] Invalid request count: %v", host, err)
			continue
		}

		// Проверяем активность
		if requestCount > 0 {
			log.Printf("[%s] Active: %d requests in last 5 seconds -> %s",
				host, requestCount, domain.Target)
		} else {
			log.Printf("[%s] Inactive: no requests", host)
		}
	}
}