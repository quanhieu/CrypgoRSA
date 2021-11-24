package main

import (
	"crypgo-master/crypgo"
	"encoding/json"
	"fmt"
	"log"
)

func main() {
	// first init key pair
	// crypgo.InitCrypto()

	// get private key
	puk := crypgo.GetIdRsaPubStr()
	log.Printf("INFO: public key - %s \n\n", puk)

	// get private key
	prk := crypgo.GetIdRsaStr()
	log.Printf("INFO: private key - %s \n\n ", prk)

	// sign
	sig, err := crypgo.Sign("Test123123123", crypgo.GetIdRsa())
	if err != nil {
		log.Printf("ERROR: fail to sign - %s", err.Error())
	}
	log.Printf("INFO: signature - %s \n\n", sig)

	// verify
	// Try with "Test123"
	err = crypgo.Verify("Test123123123", sig, crypgo.GetIdRsaPub())
	if err != nil {
		log.Printf("ERROR: fail to verify - %s", err.Error())
	}
	log.Printf("INFO: verify - %s \n\n", err)

	// encrypt
	ciperText, err := crypgo.Encrypt(`
		{
			"username": "Hieu",
			"apikey": "cef553c35c3848bef858a94a55c99e1f47ece6b3d88dd002077887ea9f684afa"
		}
	`, crypgo.GetIdRsaPub())
	if err != nil {
		log.Printf("ERROR: fail encrypt - %s", err.Error())
	}
	log.Printf("INFO: ciper text - %s\n\n", ciperText)

	// decrypt
	plainText, err := crypgo.Decrypt(ciperText, crypgo.GetIdRsa())
	if err != nil {
		log.Printf("ERROR: fail decrypt - %s\n\n", err.Error())
	}

	log.Printf("INFO: plain text - %s", plainText)
	fmt.Printf("planText2%v, %T\n\n", plainText, plainText)

	type userStruct struct {
		Username string `json:"username"`
		Apikey   string `json:"apikey"`
	}

	data := userStruct{}

	json.Unmarshal([]byte(plainText), &data)

	fmt.Println("\nApikey: ", data.Apikey)
	fmt.Println("Username: ", data.Username)
}
