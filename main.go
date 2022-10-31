package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/integration/gcpkms"
	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/streamingaead"
	"github.com/google/tink/go/tink"
)

type modeType string

const (
	modeEncrypt modeType = "encrypt"
	modeDecrypt modeType = "decrypt"
	modeNewKey  modeType = "newkey"
)

type keyTemplate func() *tinkpb.KeyTemplate

var templates = map[string]keyTemplate{
	"AES128CTRHMACSHA256": aead.AES128CTRHMACSHA256KeyTemplate,
	"AES128GCM":           aead.AES128GCMKeyTemplate,
	"AES256CTRHMACSHA256": aead.AES256CTRHMACSHA256KeyTemplate,
	"AES256GCMNoPrefix":   aead.AES256GCMNoPrefixKeyTemplate,
	"ChaCha20Poly1305":    aead.ChaCha20Poly1305KeyTemplate,
}

var streamTemplates = map[string]keyTemplate{
	"AES128CTRHMACSHA256Segment1MB": streamingaead.AES128CTRHMACSHA256Segment1MBKeyTemplate,
	"AES128CTRHMACSHA256Segment4KB": streamingaead.AES128CTRHMACSHA256Segment4KBKeyTemplate,
	"AES128GCMHKDF1MB":              streamingaead.AES128GCMHKDF1MBKeyTemplate,
	"AES128GCMHKDF4KB":              streamingaead.AES128GCMHKDF4KBKeyTemplate,
	"AES256CTRHMACSHA256Segment1MB": streamingaead.AES256CTRHMACSHA256Segment1MBKeyTemplate,
	"AES256CTRHMACSHA256Segment4KB": streamingaead.AES256CTRHMACSHA256Segment4KBKeyTemplate,
	"AES256GCMHKDF1MB":              streamingaead.AES256GCMHKDF1MBKeyTemplate,
	"AES256GCMHKDF4KB":              streamingaead.AES256GCMHKDF4KBKeyTemplate,
}

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
  tink-aead-cli -m newkey -k keyFile -s credentials.json -u gcp-kms://xxx
`)

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

	// validate input arguments.
	t, isStream, err := checkArgs()
	if err != nil {
		flag.Usage()
		log.Fatalf("check args failed: %v", err)
	}

	// start the process.
	if err := process(t, isStream); err != nil {
		log.Fatalf("failed to process: %v", err)
	}
}

func checkArgs() (t keyTemplate, isStream bool, err error) {
	// check template and decide is stream ot not.
	t, ok := templates[template]
	if !ok {
		if t, ok = streamTemplates[template]; !ok {
			return nil, false, fmt.Errorf("template '%s' not supported", template)
		}
		isStream = true
	}

	// check key uri and credentials file.
	if keyURI == "" {
		return nil, false, errors.New("missing kms key uri")
	} else if credentials == "" {
		return nil, false, errors.New("missing kms credentials file")
	}

	// check mode.
	if mode == "" || (mode != string(modeEncrypt) && mode != string(modeDecrypt) && mode != string(modeNewKey)) {
		return nil, false, fmt.Errorf("mode %s should be one of 'encrypt', 'decrypt' or 'newkey'", mode)
	}

	// check files.
	if mode != string(modeNewKey) && (plainTextFile == "" || cipherTextFile == "") {
		return nil, false, errors.New("missing plainTextFile or cipherTextFile")
	} else if mode == string(modeNewKey) && keyFile == "" {
		return nil, false, errors.New("missing key file")
	}

	return
}

func process(template keyTemplate, isStream bool) error {
	// register GCP KMS.
	gcpClient, err := gcpkms.NewClientWithCredentials(keyURI, credentials)
	if err != nil {
		return fmt.Errorf("failed to new gcp kms: %v", err)
	}
	registry.RegisterKMSClient(gcpClient)

	// if mode = newkey, encrypt the key and store to keyFile.
	if mode == string(modeNewKey) {
		return encryptKey(gcpClient, template)
	}

	// create the client for generating dek.
	kh, err := decryptKey(gcpClient, template, isStream)
	if err != nil {
		return fmt.Errorf("failed to new keyset handle: %v", err)
	}

	if !isStream {
		// generate aead primitive for encrypt/decrypt.
		a, err := aead.New(kh)
		if err != nil {
			return fmt.Errorf("failed to new key for aead: %v", err)
		}

		// determine to encrypt or decrypt.
		if mode == string(modeEncrypt) {
			if err := encryptNormal(a); err != nil {
				return fmt.Errorf("failed to encrypt: %v", err)
			}
		} else {
			if err := decryptNormal(a); err != nil {
				return fmt.Errorf("failed to decrypt: %v", err)
			}
		}
	} else {
		// generate aead stream for encrypt/decrypt.
		a, err := streamingaead.New(kh)
		if err != nil {
			return fmt.Errorf("failed to new key for streamingaead: %v", err)
		}

		// determine to encrypt or decrypt.
		if mode == string(modeEncrypt) {
			if err := encryptStream(a); err != nil {
				return fmt.Errorf("failed to encrypt: %v", err)
			}
		} else {
			if err := decryptStream(a); err != nil {
				return fmt.Errorf("failed to decrypt: %v", err)
			}
		}
	}

	return nil
}

func decryptKey(gcpClient registry.KMSClient, template keyTemplate, isStream bool) (*keyset.Handle, error) {
	if keyFile == "" {
		// streaming aead does not support envelope encryption.
		if isStream {
			return nil, errors.New("streamingAEAD does not support envelope encryption")
		}

		// no key file specified, use envelope encryption.
		dekTemplate := template()
		return keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate(keyURI, dekTemplate))
	}

	// key file specified, use master key in KMS.
	masterKey, err := gcpClient.GetAEAD(keyURI)
	if err != nil {
		return nil, fmt.Errorf("failed to get key %s from KMS: %v", keyURI, err)
	}

	// read from key file.
	file, err := os.Open(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to oepn %s: %v", keyFile, err)
	}
	r := keyset.NewJSONReader(file)

	return keyset.Read(r, masterKey)
}

func encryptKey(gcpClient registry.KMSClient, template keyTemplate) error {
	// key file specified, use master key in KMS.
	masterKey, err := gcpClient.GetAEAD(keyURI)
	if err != nil {
		return fmt.Errorf("failed to get key %s from KMS: %v", keyURI, err)
	}

	// prepare key file.
	file, err := os.Create(keyFile)
	if err != nil {
		return fmt.Errorf("failed to create %s: %v", keyFile, err)
	}
	w := keyset.NewJSONWriter(file)

	// generate a new key.
	kh, err := keyset.NewHandle(template())
	if err != nil {
		return fmt.Errorf("failed to new key handle: %v", err)
	}
	if err := kh.Write(w, masterKey); err != nil {
		return fmt.Errorf("failed to write key file: %v", err)
	}

	return nil
}

func encryptNormal(a tink.AEAD) error {
	// read the plainTextFile.
	b, err := ioutil.ReadFile(plainTextFile)
	if err != nil {
		return fmt.Errorf("failed to read plainTextFile %s: %v", plainTextFile, err)
	}

	// encrypt the bytes with associated data.
	ct, err := a.Encrypt(b, []byte(associatedData))
	if err != nil {
		return fmt.Errorf("failed to encrypt: %v", err)
	}

	// write the cipherTextFile.
	if err := ioutil.WriteFile(cipherTextFile, ct, 0644); err != nil {
		return fmt.Errorf("failed to write cipherTextFile %s: %v", cipherTextFile, err)
	}

	return nil
}

func encryptStream(a tink.StreamingAEAD) error {
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

	// crete the writer.
	w, err := a.NewEncryptingWriter(ctFile, []byte(associatedData))
	if err != nil {
		return fmt.Errorf("failed to new encrypting writer: %v", err)
	}
	defer w.Close()

	// write the file to cipherTextFile.
	if _, err := io.Copy(w, srcFile); err != nil {
		return fmt.Errorf("failed to write: %v", err)
	}

	return nil
}

func decryptNormal(a tink.AEAD) error {
	// read the cipherTextFile.
	ct, err := ioutil.ReadFile(cipherTextFile)
	if err != nil {
		return fmt.Errorf("failed to read cipherTextFile %s: %v", cipherTextFile, err)
	}

	// decrypt the bytes with associated data.
	b, err := a.Decrypt(ct, []byte(associatedData))
	if err != nil {
		return fmt.Errorf("failed to decrypt: %v", err)
	}

	// write the plainTextFile.
	if err := ioutil.WriteFile(plainTextFile, b, 0644); err != nil {
		return fmt.Errorf("failed to write plainTextFile %s: %v", plainTextFile, err)
	}

	return nil
}

func decryptStream(a tink.StreamingAEAD) error {
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

	// crete the writer.
	r, err := a.NewDecryptingReader(ctFile, []byte(associatedData))
	if err != nil {
		return fmt.Errorf("failed to new decrypting reader: %v", err)
	}

	// write the file to cipherTextFile.
	if _, err := io.Copy(dstFile, r); err != nil {
		return fmt.Errorf("failed to read: %v", err)
	}

	return nil
}
