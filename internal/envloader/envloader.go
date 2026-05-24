package envloader

import (
	"github.com/joho/godotenv"
	"log"
)

func init() {
	err := godotenv.Overload()
	if err != nil {
		log.Printf("Warning: .env file not found or could not be loaded: %v", err)
	}
}
