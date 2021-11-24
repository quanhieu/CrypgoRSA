package crypgo

import (
	"os"
)

type Config struct {
	dotKeys  string
	idRsa    string
	idRsaPub string
	keySize  int
}

var config = Config{
	dotKeys:  getEnv("DOT_KEYS", ".keys"),
	idRsa:    getEnv("ID_RSA", ".keys/id_rsa"),
	idRsaPub: getEnv("ID_RSA_PUB", ".keys/id_rsa.pub"),
	keySize:  2048,
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}

	return fallback
}
