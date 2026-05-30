package envloader

import (
	"github.com/joho/godotenv"
)

func init() {
	_ = godotenv.Overload(".env")
	_ = godotenv.Overload("../.env")
	_ = godotenv.Overload("../../.env")
}
