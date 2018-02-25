package main

import (
	"fmt"
	"github.com/rem7/kmsconfig"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

const usage = `
usage:

	kmsconfig encrypt file kms_key_id kms_region
	kmsconfig show file
`

func main() {

	if len(os.Args) >= 4 && os.Args[1] == "encrypt" {
		src := os.Args[2]
		kmsKeyId := os.Args[3]
		kmsRegion := os.Args[4]
		err := encryptFile(src, kmsKeyId, kmsRegion)
		if err != nil {
			log.Fatal(err)
		}
	} else if len(os.Args) >= 3 && os.Args[1] == "show" {
		f := os.Args[2]
		data := decryptFile(f)
		fmt.Printf("%s", data)
	} else {
		fmt.Print(usage)
	}
}

func encryptFile(src, kmskeyid, kmsRegion string) error {
	r, err := os.Open(src)
	if err != nil {
		return err
	}
	defer r.Close()

	data, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}

	ext := filepath.Ext(src)
	dst := fmt.Sprintf("%s.encrypted%s", src[:len(src)-len(ext)], ext)
	return kmsconfig.EncryptDataWriteFile(data, kmskeyid, kmsRegion, dst)
}

func decryptFile(file string) []byte {

	r, err := kmsconfig.ReadConfig(file)
	if err != nil {
		log.Fatal(err)
	}

	data, err := ioutil.ReadAll(r)
	if err != nil {
		log.Fatal(err)
	}
	return data
}
