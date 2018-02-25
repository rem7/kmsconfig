/*
 * Copyright (c) 2018 Yanko Bolanos
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

// Use this package to encrypt/decrypt configuration files with AES and
// encrypt the AES key with AWS KMS.
package kmsconfig // import "github.com/rem7/kmsconfig"

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
)

func connectToKMS(awsRegion string) *kms.KMS {

	if awsRegion == "" {
		s := session.Must(session.NewSession())
		ec2Meta := ec2metadata.New(s)
		region, err := ec2Meta.Region()
		if err != nil {
			log.Fatalf("kms failed to get region for kms key", err.Error())
		}
		awsRegion = region
	}

	config := &aws.Config{
		Region: aws.String(awsRegion),
	}
	sess := session.New(config)
	return kms.New(sess)
}

type ConfigWriter struct {
	buf       bytes.Buffer
	kmsKeyID  string
	dst       string
	kmsRegion string
}

// Create a ConfigWriter. It meets io.ReadCloser interface and anything
// written will get encrypted once closed.
func CreateConfigWriter(kmsKeyId, kmsRegion, dst string) *ConfigWriter {
	return &ConfigWriter{
		buf:       bytes.Buffer{},
		kmsKeyID:  kmsKeyId,
		dst:       dst,
		kmsRegion: kmsRegion,
	}
}

func (c *ConfigWriter) Write(data []byte) (int, error) {
	return c.buf.Write(data)
}

func (c *ConfigWriter) Close() error {
	return EncryptDataWriteFile(c.buf.Bytes(), c.kmsKeyID, c.kmsRegion, c.dst)
}

// This is the json structure used to output the file that your application
// will read from
type EncryptedConfig struct {
	EncryptedAESKey string `json:"encrypted_aes_key"`
	EncryptedData   string `json:"encrypted_data"`
	KmsKeyRegion    string `json:"kms_key_region"`
}

func pad(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

// every time we encrypt we generate a new key
// so we leave the iv as 0s
func encrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	iv := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	mode := cipher.NewCBCEncrypter(block, iv)
	msg := pad(text)
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

func kmsDecryptAESKey(aesEncryptedKey []byte, region string) []byte {
	svc := connectToKMS(region)
	input := &kms.DecryptInput{
		CiphertextBlob: aesEncryptedKey,
	}
	output, err := svc.DecryptWithContext(context.Background(), input)
	if err != nil {
		log.Fatal(err)
	}
	return output.Plaintext
}

func kmsEncryptAESKey(kmsKeyId string, aesKey []byte, region string) string {
	svc := connectToKMS(region)
	input := &kms.EncryptInput{
		KeyId:     aws.String(kmsKeyId),
		Plaintext: aesKey,
	}

	output, err := svc.EncryptWithContext(context.Background(), input)
	if err != nil {
		log.Fatal(err)
	}

	return base64.StdEncoding.EncodeToString(output.CiphertextBlob)
}

// This will return an io.Reader that when read will return
// the data unencrypted. This can be passed to a decoder (json,yaml,etc).
func ReadConfig(src string) (io.Reader, error) {

	f, err := os.Open(src)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	v := EncryptedConfig{}
	err = json.NewDecoder(f).Decode(&v)
	if err != nil {
		return nil, err
	}

	aesEncryptedKey, err := base64.StdEncoding.DecodeString(v.EncryptedAESKey)
	if err != nil {
		return nil, err
	}

	aesKey := kmsDecryptAESKey(aesEncryptedKey, v.KmsKeyRegion)
	if err != nil {
		return nil, err
	}

	ciphertext, err := hex.DecodeString(v.EncryptedData)
	if err != nil {
		return nil, err
	}

	data, err := decrypt(aesKey, ciphertext)
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(data), nil
}

func EncryptDataWriteFile(data []byte, kmsKeyId, region, dst string) error {

	aesKey := make([]byte, 32)
	_, err := rand.Read(aesKey)
	if err != nil {
		return err
	}

	encryptedData, err := encrypt(aesKey, data)
	if err != nil {
		return err
	}

	encryptedAESKey := kmsEncryptAESKey(kmsKeyId, aesKey, region)

	econfig := EncryptedConfig{
		EncryptedAESKey: encryptedAESKey,
		EncryptedData:   hex.EncodeToString(encryptedData),
		KmsKeyRegion:    region,
	}

	jsonData, err := json.MarshalIndent(econfig, "", "    ")
	return ioutil.WriteFile(dst, jsonData, 0700)

}

// Helper function that will encrypt a JSON file.
// The JSON file must contain a "kms_key_id" and a "kms_key_region"
func EncryptJSONFile(src, dst string) {

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

	kmsKeyRegion := ""
	if val, ok := v["kms_key_region"].(string); ok {
		kmsKeyRegion = val
	} else {
		log.Fatal("kms_key_id missing")
	}

	data, err := json.MarshalIndent(v, "", "    ")
	if err != nil {
		log.Fatal(err)
	}

	err = EncryptDataWriteFile(data, kmsKeyId, kmsKeyRegion, dst)
	if err != nil {
		log.Fatal(err)
	}
}
