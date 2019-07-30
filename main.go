package main

import (
	"encoding/base64"
	"flag"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	key             []byte = []byte("shameful scene, the one that doe")
	header          []byte = []byte("Amanda")
	dataFromPython  string
	nonceFromPython string
	tagFromPython   string
)

func init() {
	flag.StringVar(&dataFromPython, "data", "", "encrypted base64 encoded data")
	flag.StringVar(&nonceFromPython, "nonce", "", "encrypted base64 encoded nonce")
	flag.StringVar(&tagFromPython, "tag", "", "encrypted base64 encoded tag")
	flag.Parse()
}

func main() {
	if dataFromPython == "" || nonceFromPython == "" || tagFromPython == "" {
		fmt.Println("Should pass -data, -tag and -nonce, can't decrypt nothing ;-)")
		return
	}

	fmt.Printf("Received\nEncrypted:\"%v\"\nNonce:\"%v\"\nTag:\"%s\"\n", dataFromPython, nonceFromPython, tagFromPython)

	decoded, err := base64.StdEncoding.DecodeString(dataFromPython)
	if err != nil {
		fmt.Println("Encrypted base64 decode failed: %v", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(nonceFromPython)
	if err != nil {
		fmt.Println("Nonce base64 decode failed: %v", err)
	}
	tag, err := base64.StdEncoding.DecodeString(tagFromPython)
	if err != nil {
		fmt.Println("Tag base64 decode failed: %v", err)
	}

	result, err := decrypt(nonce, decoded, tag, header)
	if err != nil {
		fmt.Printf("Didn't decrypt: %v\n", err)
	}

	fmt.Printf("Decrypted\n%v\n", string(result))

}

func decrypt(nonce, data, tag, header []byte) ([]byte, error) {
	aed, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("Couldn't set up ChaCha20_Poly1305 cipher for decryption: %v", err)
	}
	// Python (PyCryptodome) implementation gives the tag as a separate var,
	// Go expects the tag to be at the end of `data`, 16 bytes of length, check:
	// https://github.com/golang/crypto/blob/4def268fd1a49955bfb3dda92fe3db4f924f2285/chacha20poly1305/chacha20poly1305_generic.go#L49
	// Version from commit:
	// https://github.com/golang/crypto/commit/594708b89f21ece706681be23d04a6513a22de6e | 2016-10-10
	data = append(data, tag...)

	plaintext, err := aed.Open(nil, nonce, data, header)

	if err != nil {
		return nil, fmt.Errorf("Unable to open sealed data: %v", err)
	}

	return plaintext, nil
}
