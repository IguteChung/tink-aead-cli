package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	tinkaeadcli "github.com/IguteChung/tink-aead-cli/pkg"
)

type modeType string

const (
	modeEncrypt modeType = "encrypt"
	modeDecrypt modeType = "decrypt"
	modeNewKey  modeType = "newkey"
)

var template string
var cipherTextFile, plainTextFile, keyFile string
var keyURI, credentials string
var associatedData string
var mode string

func init() {
	// modify the default usage text.
	originalUsage := flag.Usage
	flag.Usage = func() {
		fmt.Println(`Usage Examples:
1. Encrypt plain text file by envelope encryption (DEK is stored in output cipher text file)
  tink-aead-cli -m encrypt -p plainTextFile -c cipherTextFile -s credentials.json -u gcp-kms://xxx

2. Decrypt cipher text file by envelope encryption (DEK is stored in input cipher text file)
  tink-aead-cli -m decrypt -p plainTextFile -c cipherTextFile -s credentials.json -u gcp-kms://xxx

3. Encrypt plain text file by stored keyset. (DEK is stored in a separate file)
  tink-aead-cli -m encrypt -p plainTextFile -c cipherTextFile -k keyFile -s credentials.json -u gcp-kms://xxx

4. Decrypt cipher text file by stored keyset. (DEK is stored in a separate file)
  tink-aead-cli -m decrypt -p plainTextFile -c cipherTextFile -k keyFile -s credentials.json -u gcp-kms://xxx

5. Create a data encryption key (DEK). (DEK will be stored in a separate file)
  tink-aead-cli -m newkey -k keyFile -s credentials.json -u gcp-kms://xxx`)

		originalUsage()
	}

	// read all flags.
	flag.StringVar(&template, "t", "AES128GCM", "Key template for aead or streaming_aead")
	flag.StringVar(&plainTextFile, "p", "", "Platin text file path to be encrypted/decrypted")
	flag.StringVar(&cipherTextFile, "c", "", "Cipher text file path to be encrypted/decrypted")
	flag.StringVar(&keyFile, "k", "", "Stored DEK that is encrypted by KEK in KMS")
	flag.StringVar(&keyURI, "u", "", "kms key uri, can only be started with gcp-kms://")
	flag.StringVar(&credentials, "s", "", "cerdential file for accessing kms")
	flag.StringVar(&associatedData, "a", "", "associated data to be encrypted/decrypted")
	flag.StringVar(&mode, "m", "", "mode configuration, can be one of 'encrypt', 'decrypt' or 'newkey'")
}

func main() {
	flag.Parse()

	// create config.
	kf := keyFile
	if modeType(mode) == modeNewKey {
		// if generating new key, do not pass the key file.
		kf = ""
	}
	cfg := tinkaeadcli.Config{
		Template:    tinkaeadcli.KeyTemplate(template),
		KeyURI:      keyURI,
		Credentials: credentials,
		KeyFile:     kf,
	}

	// check the template is stream or not.
	isStream, err := cfg.Template.IsStream()
	if err != nil {
		log.Fatalf("invalid template: %v", err)
	}

	// determine the encrypter/decrypter to use.
	if isStream {
		if err := handleStream(cfg); err != nil {
			log.Fatalf("failed to handle stream: %v", err)
		}
	} else {
		if err := handle(cfg); err != nil {
			log.Fatalf("failed to handle: %v", err)
		}
	}

}

func handle(cfg tinkaeadcli.Config) error {
	e, err := tinkaeadcli.NewEncrypterDecrypter(cfg)
	if err != nil {
		flag.Usage()
		return fmt.Errorf("failed to new encrypter decrypter: %v", err)
	}

	switch modeType(mode) {
	case modeEncrypt:
		// do the encryption.
		if err := e.EncryptFile(plainTextFile, cipherTextFile, []byte(associatedData)); err != nil {
			return fmt.Errorf("failed to encrypt: %v", err)
		}

	case modeDecrypt:
		// do the decryption.
		if err := e.DecryptFile(cipherTextFile, plainTextFile, []byte(associatedData)); err != nil {
			return fmt.Errorf("failed to decrypt: %v", err)
		}

	case modeNewKey:
		// generate a local key.
		if err := e.NewDataKey(keyFile); err != nil {
			return fmt.Errorf("failed to new data key: %v", err)
		}

	default:
		return fmt.Errorf("invalid mode %s", mode)
	}

	return nil
}

func handleStream(cfg tinkaeadcli.Config) error {
	e, err := tinkaeadcli.NewStreamEncrypterDecrypter(cfg)
	if err != nil {
		flag.Usage()
		return fmt.Errorf("failed to new stream encrypter decrypter: %v", err)
	}

	switch modeType(mode) {
	case modeEncrypt:
		// open src and dst files for writing.
		srcFile, err := os.Open(plainTextFile)
		if err != nil {
			return fmt.Errorf("failed to open %s: %v", plainTextFile, err)
		}
		defer srcFile.Close()

		ctFile, err := os.Create(cipherTextFile)
		if err != nil {
			return fmt.Errorf("failed to create %s: %v", cipherTextFile, err)
		}
		defer ctFile.Close()

		// do the stream encryption.
		if err := e.Encrypt(srcFile, ctFile, []byte(associatedData)); err != nil {
			return fmt.Errorf("failed to encrypt stream: %v", err)
		}

	case modeDecrypt:
		// open ct and dst files for writing.
		ctFile, err := os.Open(cipherTextFile)
		if err != nil {
			return fmt.Errorf("failed to open %s: %v", cipherTextFile, err)
		}
		defer ctFile.Close()

		dstFile, err := os.Create(plainTextFile)
		if err != nil {
			return fmt.Errorf("failed to create %s: %v", plainTextFile, err)
		}
		defer dstFile.Close()

		// do the stream decryption.
		if err := e.Decrypt(ctFile, dstFile, []byte(associatedData)); err != nil {
			return fmt.Errorf("failed to decrypt stream: %v", err)
		}

	case modeNewKey:
		// generate a local key.
		if err := e.NewDataKey(keyFile); err != nil {
			return fmt.Errorf("failed to new data key: %v", err)
		}

	default:
		return fmt.Errorf("invalid mode %s", mode)
	}

	return nil
}
