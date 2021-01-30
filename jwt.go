package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

type Payload struct {
	Sub      int64  `json:"sub"`
	Username string `json:"username"`
	Iat      int64  `json:"iat"`
	Exp      int64  `json:"exp"`
}

type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

func Base64Encode(src string) string {
	return strings.
		TrimSpace(base64.URLEncoding.
			EncodeToString([]byte(src)))
}

func Base64Decode(src string) (string, error) {
	decoded, err := base64.URLEncoding.DecodeString(src)
	if err != nil {
		errMsg := fmt.Errorf("Decoding Error %s", err)
		return "", errMsg
	}
	return string(decoded), nil
}

func Hash(src string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(src))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func IsValidHash(value string, hash string, secret string) bool {
	return hash == Hash(value, secret)
}

// Encode generates a jwt.
func Encode(payload Payload, secret string) string {

	header := Header{
		Alg: "HS256",
		Typ: "JWT",
	}
	str, _ := json.Marshal(header)
	headerEncode := Base64Encode(string(str))
	encodedPayload, _ := json.Marshal(payload)
	signatureValue := headerEncode + "." + Base64Encode(string(encodedPayload))
	return signatureValue + "." + Hash(signatureValue, secret)

}

func Decode(jwt string, secret string) (interface{}, error) {
	token := strings.Split(jwt, ".")
	fmt.Println("Token split is %s", token)

	if len(token) != 3 {
		tokenLenErr := errors.New("Invalid token: token should contain header, payload and secret")
		return nil, tokenLenErr
	}

	// decode payload
	decodedPayload, PayloadErr := Base64Decode(token[1])

	if PayloadErr != nil {
		return nil, fmt.Errorf("Invalid payload: %s", PayloadErr.Error())
	}

	payload := Payload{}

	// parses payload from string to a struct using unmarshall
	ParseErr := json.Unmarshal([]byte(decodedPayload), &payload)

	if ParseErr != nil {
		return nil, fmt.Errorf("Invalid payload: %s", ParseErr.Error())
	}

	signatureValue := token[0] + "." + token[1]

	// verifies if the header and signature is exactly whats in the signature
	if IsValidHash(signatureValue, token[2], secret) == false {
		return nil, errors.New("Invalid token")
	}
	return payload, nil
}

/**
1. Create a map and create a token
2. Write to token to file
3. Read from file and verify it
4. change token directly in file and again verify it

**/

// type Payload struct {
// 	Sub int64 `json:"sub"`
// 	Username string `json:"username"`
// 	Iat      int64 `json:"iat"`
// 	Exp      int64 `json:"exp"`
// }
const secret = "aravindvp"

func CreateJWT() {

	payload := Payload{
		Sub:      1,
		Username: "admin",
		Iat:      123212,
		Exp:      123124,
	}

	token := Encode(payload, secret)

	f, err := os.Create("token.txt")
	if err != nil {
		panic(err)
	}

	defer f.Close()
	d := []byte(token)
	num, err := f.Write(d)

	if err != nil {
		panic(err)
	}
	fmt.Println("num %d ", num)

	fmt.Println("Token is %s", token)

}

func ValidateJWT() {
	token, err := ioutil.ReadFile("token.txt")
	if err != nil {
		panic(err)
	}

	fmt.Println("Token read is %s", string(token))
	fmt.Println("----------------------------------------------------------------")

	fmt.Println(Decode(string(token), secret))

}

func main() {

	CreateJWT()
	fmt.Println("----------------------------------------------------------------")

	ValidateJWT()
}
