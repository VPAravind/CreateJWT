# CreateJWT
Build a token for your application from scratch as part of a self study for Golang. 

## Language
- Golang

## Instructions
Run the file and see the token add to a file called token.txt
- Command: ```go run jwt.go```

The file has 2 functions: encrypt and decrypt
- Encrypt: Encrypts the data and header with the secret. Writes it to token.txt
- Decrypt: Decrypts the token in the token.txt file using the secret and check whether it is valid by comparing the signature.

The above file has an hard-coded secret. Feel free to make changes to the code however you see fit. 
