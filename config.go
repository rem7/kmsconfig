package config

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"log"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
)

var kmssvc *kms.KMS

func init() {

	awsRegion := "us-west-2"
	config := &aws.Config{
		Region: aws.String(awsRegion),
	}
	sess := session.New(config)
	kmssvc = kms.New(sess)
}

type EncryptedConfig struct {
	EncryptedAESKey string `json:"encrypted_aes_key"`
	EncryptedData   string `json:"encrypted_data"`
}

func Pad(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func encrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	iv := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	mode := cipher.NewCBCEncrypter(block, iv)
	msg := Pad(text)
	ciphertext := make([]byte, len(msg))
	mode.CryptBlocks(ciphertext, msg)
	return ciphertext, nil
}

func decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	iv := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	decrypted := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(decrypted, ciphertext)

	padding := decrypted[len(decrypted)-1]
	return decrypted[:len(decrypted)-int(padding)], nil
}

func DecryptFile(src string, config interface{}) {

	f, err := os.Open(src)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	v := EncryptedConfig{}
	err = json.NewDecoder(f).Decode(&v)
	if err != nil {
		log.Fatal(err)
	}

	aesEncryptedKey, err := base64.StdEncoding.DecodeString(v.EncryptedAESKey)
	if err != nil {
		log.Fatal(err)
	}

	input := &kms.DecryptInput{
		CiphertextBlob: aesEncryptedKey,
	}

	output, err := kmssvc.DecryptWithContext(context.Background(), input)
	if err != nil {
		log.Fatal(err)
	}

	ciphertext, err := hex.DecodeString(v.EncryptedData)
	if err != nil {
		log.Fatal(err)
	}

	data, err := decrypt(output.Plaintext, ciphertext)
	if err != nil {
		log.Fatal(err)
	}

	err = json.Unmarshal(data, config)
	if err != nil {
		log.Fatal(err)
	}

}

func EncryptFile(src, dst string) {

	f, err := os.Open(src)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	v := make(map[string]interface{})
	err = json.NewDecoder(f).Decode(&v)
	if err != nil {
		log.Fatal(err)
	}

	kmsKeyId := ""
	if val, ok := v["kms_key_id"].(string); ok {
		kmsKeyId = val
	} else {
		log.Fatal("kms_key_id missing")
	}

	data, err := json.MarshalIndent(v, "", "    ")
	if err != nil {
		log.Fatal(err)
	}

	key := make([]byte, 32)
	_, err = rand.Read(key)
	if err != nil {
		log.Fatal(err)
	}

	encryptedData, err := encrypt(key, data)
	if err != nil {
		panic(err)
	}

	input := &kms.EncryptInput{
		KeyId:     aws.String(kmsKeyId),
		Plaintext: key,
	}

	output, err := kmssvc.EncryptWithContext(context.Background(), input)
	if err != nil {
		log.Fatal(err)
	}

	econfig := EncryptedConfig{
		EncryptedAESKey: base64.StdEncoding.EncodeToString(output.CiphertextBlob),
		EncryptedData:   hex.EncodeToString(encryptedData),
	}

	jsonData, err := json.MarshalIndent(econfig, "", "    ")
	err = ioutil.WriteFile(dst, jsonData, 0700)
	if err != nil {
		log.Fatal(err)
	}
}
