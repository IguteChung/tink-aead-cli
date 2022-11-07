package tinkaeadcli

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/integration/gcpkms"
	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/streamingaead"
	"github.com/google/tink/go/tink"
)

type impl struct {
	template  func() *tinkpb.KeyTemplate
	gcpClient registry.KMSClient
	keyHandle *keyset.Handle
	isStream  bool
	a         tink.AEAD
	as        tink.StreamingAEAD
}

func (i *impl) EncryptFile(src, dst string, ad []byte) error {
	if i.a == nil {
		return errors.New("missing tink.AEAD")
	}

	// read the plainTextFile.
	b, err := ioutil.ReadFile(src)
	if err != nil {
		return fmt.Errorf("failed to read plainTextFile %s: %v", src, err)
	}

	// encrypt the bytes with associated data.
	ct, err := i.a.Encrypt(b, ad)
	if err != nil {
		return fmt.Errorf("failed to encrypt: %v", err)
	}

	// write the cipherTextFile.
	if err := ioutil.WriteFile(dst, ct, 0644); err != nil {
		return fmt.Errorf("failed to write cipherTextFile %s: %v", dst, err)
	}

	return nil
}

func (i *impl) DecryptFile(src, dst string, ad []byte) error {
	if i.a == nil {
		return errors.New("missing tink.AEAD")
	}

	// read the cipherTextFile.
	ct, err := ioutil.ReadFile(src)
	if err != nil {
		return fmt.Errorf("failed to read cipherTextFile %s: %v", src, err)
	}

	// decrypt the bytes with associated data.
	b, err := i.a.Decrypt(ct, ad)
	if err != nil {
		return fmt.Errorf("failed to decrypt: %v", err)
	}

	// write the plainTextFile.
	if err := ioutil.WriteFile(dst, b, 0644); err != nil {
		return fmt.Errorf("failed to write plainTextFile %s: %v", dst, err)
	}

	return nil
}

func (i *impl) Encrypt(src io.Reader, dst io.Writer, ad []byte) error {
	if i.as == nil {
		return errors.New("missing tink.StreamingAEAD")
	}

	// crete the writer.
	w, err := i.as.NewEncryptingWriter(dst, ad)
	if err != nil {
		return fmt.Errorf("failed to new encrypting writer: %v", err)
	}
	defer w.Close()

	// write the file to cipherTextFile.
	if _, err := io.Copy(w, src); err != nil {
		return fmt.Errorf("failed to write: %v", err)
	}

	return nil
}

func (i *impl) Decrypt(src io.Reader, dst io.Writer, ad []byte) error {
	if i.as == nil {
		return errors.New("missing tink.StreamingAEAD")
	}

	// crete the writer.
	r, err := i.as.NewDecryptingReader(src, ad)
	if err != nil {
		return fmt.Errorf("failed to new decrypting reader: %v", err)
	}

	// write the file to cipherTextFile.
	if _, err := io.Copy(dst, r); err != nil {
		return fmt.Errorf("failed to read: %v", err)
	}

	return nil
}

func (i *impl) NewDataKey(keypath string) error {
	// prepare key file.
	file, err := os.Create(keypath)
	if err != nil {
		return fmt.Errorf("failed to create %s: %v", keypath, err)
	}
	w := keyset.NewJSONWriter(file)

	// generate a new key.
	if err := i.keyHandle.Write(w, i.a); err != nil {
		return fmt.Errorf("failed to write key file: %v", err)
	}

	return nil
}

func newImpl(config Config, isStream bool) (*impl, error) {
	// find template from config.
	template, ok := validTemplate[config.Template]
	if !ok {
		return nil, fmt.Errorf("failed to find template %s", config.Template)
	}

	// check key uri and credentials file.
	if config.KeyURI == "" {
		return nil, errors.New("missing kms key uri")
	} else if config.Credentials == "" {
		return nil, errors.New("missing kms credentials file")
	}

	// register GCP KMS.
	gcpClient, err := gcpkms.NewClientWithCredentials(config.KeyURI, config.Credentials)
	if err != nil {
		return nil, fmt.Errorf("failed to new gcp kms: %v", err)
	}
	registry.RegisterKMSClient(gcpClient)

	// initialize the keyset handle for encrypt/decrypt.
	var a tink.AEAD
	var as tink.StreamingAEAD
	if config.KeyFile == "" {
		// streaming aead does not support envelope encryption.
		if isStream {
			return nil, errors.New("streamingAEAD does not support envelope encryption")
		}

		// no key file specified, use envelope encryption.
		dekTemplate := template()
		keyHandle, err := keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate(config.KeyURI, dekTemplate))
		if err != nil {
			return nil, fmt.Errorf("failed to new key handle with %s: %v", config.KeyURI, err)
		}

		// create the aead handler.
		if a, err = aead.New(keyHandle); err != nil {
			return nil, fmt.Errorf("failed to new aead handler: %v", err)
		}
	} else {
		// key file specified, use master key in KMS to decrypt the local key.
		masterKey, err := gcpClient.GetAEAD(config.KeyURI)
		if err != nil {
			return nil, fmt.Errorf("failed to get key %s from KMS: %v", config.KeyURI, err)
		}

		// read from key file.
		file, err := os.Open(config.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to oepn %s: %v", config.KeyFile, err)
		}
		r := keyset.NewJSONReader(file)

		keyHandle, err := keyset.Read(r, masterKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse key file %s: %v", config.KeyFile, err)
		}

		// create the streaming aead handler.
		if as, err = streamingaead.New(keyHandle); err != nil {
			return nil, fmt.Errorf("failed to new streaming aead handler: %v", err)
		}
	}

	return &impl{
		template:  template,
		gcpClient: gcpClient,
		isStream:  isStream,
		a:         a,
		as:        as,
	}, nil
}
