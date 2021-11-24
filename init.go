package main

import (
	"crypgo-master/crypgo"
	"fmt"
)

func callOut() int {
	// first init key pair
	fmt.Println("Outside is beinge executed\n\n")
	return 1
}

var test = callOut()

func init() {
	// Init RSA key
	crypgo.InitCrypto()
	fmt.Println("InitCrypto is being executed\n\n")
}
