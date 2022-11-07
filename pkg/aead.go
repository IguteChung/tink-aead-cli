package tinkaeadcli

import (
	"github.com/google/tink/go/aead"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

// EncrypterDecrypter defines the interface for encrypting and decrypting.
type EncrypterDecrypter interface {
	// EncryptFile encrypts source plain text file to destination cipher text file.
	// Use envelope encryption if KeyFile is not provided, otherwise use KeyFile for local encryption.
	// ad indicates the associated data for authenticated encryption, optionally.
	EncryptFile(src, dst string, ad []byte) error

	// DecryptFile decrypts source cipher text file to destination plain text file.
	// Use envelope decryption if KeyFile is not provided, otherwise use KeyFile for local decryption.
	// ad indicates the associated data for authenticated decryption, optionally.
	DecryptFile(src, dst string, ad []byte) error

	// NewDataKey cretes a new local DEK that will be encrypted.
	// Use remote encryption if KeyFile is not provided, otherwise use KeyFile for local encryption.
	NewDataKey(keypath string) error
}

// enum for all key templates supported in tink.
var (
	AES128CTRHMACSHA256KeyTemplate KeyTemplate = "AES128CTRHMACSHA256"
	AES128GCMKeyTemplate           KeyTemplate = "AES128GCM"
	AES256CTRHMACSHA256KeyTemplate KeyTemplate = "AES256CTRHMACSHA256"
	AES256GCMNoPrefixKeyTemplate   KeyTemplate = "AES256GCMNoPrefix"
	ChaCha20Poly1305KeyTemplate    KeyTemplate = "ChaCha20Poly1305"
)

var validTemplate = map[KeyTemplate]func() *tinkpb.KeyTemplate{
	AES128CTRHMACSHA256KeyTemplate: aead.AES128CTRHMACSHA256KeyTemplate,
	AES128GCMKeyTemplate:           aead.AES128GCMKeyTemplate,
	AES256CTRHMACSHA256KeyTemplate: aead.AES256CTRHMACSHA256KeyTemplate,
	AES256GCMNoPrefixKeyTemplate:   aead.AES256GCMNoPrefixKeyTemplate,
	ChaCha20Poly1305KeyTemplate:    aead.ChaCha20Poly1305KeyTemplate,
}

// NewEncrypterDecrypter returns a valid EncrypterDecrypter.
func NewEncrypterDecrypter(config Config) (EncrypterDecrypter, error) {
	return newImpl(config, false)
}
