package tinkaeadcli

import (
	"io"

	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/streamingaead"
)

// StreamEncrypterDecrypter defines the interface for encrypting and decrypting.
type StreamEncrypterDecrypter interface {
	// Encrypt encrypts source input stream to destination output stream.
	// Use KeyFile for local encryption.
	// ad indicates the associated data for authenticated encryption, optionally.
	Encrypt(src io.Reader, dst io.Writer, ad []byte) error

	// Decrypt decrypts source input stream to destination output stream.
	// Use KeyFile for local decryption.
	// ad indicates the associated data for authenticated decryption, optionally.
	Decrypt(src io.Reader, dst io.Writer, ad []byte) error

	// NewDataKey cretes a new local DEK that will be encrypted remotely and stored in local KeyFile.
	// Use remote KEK to encrypt the DEK.
	NewDataKey(keypath string) error
}

// enum for all stream key templates supported in tink.
var (
	AES128CTRHMACSHA256Segment1MBKeyTemplate KeyTemplate = "AES128CTRHMACSHA256Segment1MB"
	AES128CTRHMACSHA256Segment4KBKeyTemplate KeyTemplate = "AES128CTRHMACSHA256Segment4KB"
	AES128GCMHKDF1MBKeyTemplate              KeyTemplate = "AES128GCMHKDF1MB"
	AES128GCMHKDF4KBKeyTemplate              KeyTemplate = "AES128GCMHKDF4KB"
	AES256CTRHMACSHA256Segment1MBKeyTemplate KeyTemplate = "AES256CTRHMACSHA256Segment1MB"
	AES256CTRHMACSHA256Segment4KBKeyTemplate KeyTemplate = "AES256CTRHMACSHA256Segment4KB"
	AES256GCMHKDF1MBKeyTemplate              KeyTemplate = "AES256GCMHKDF1MB"
	AES256GCMHKDF4KBKeyTemplate              KeyTemplate = "AES256GCMHKDF4KB"
)

var validStreamTemplate = map[KeyTemplate]func() *tinkpb.KeyTemplate{
	AES128CTRHMACSHA256Segment1MBKeyTemplate: streamingaead.AES128CTRHMACSHA256Segment1MBKeyTemplate,
	AES128CTRHMACSHA256Segment4KBKeyTemplate: streamingaead.AES128CTRHMACSHA256Segment4KBKeyTemplate,
	AES128GCMHKDF1MBKeyTemplate:              streamingaead.AES128GCMHKDF1MBKeyTemplate,
	AES128GCMHKDF4KBKeyTemplate:              streamingaead.AES128GCMHKDF4KBKeyTemplate,
	AES256CTRHMACSHA256Segment1MBKeyTemplate: streamingaead.AES256CTRHMACSHA256Segment1MBKeyTemplate,
	AES256CTRHMACSHA256Segment4KBKeyTemplate: streamingaead.AES256CTRHMACSHA256Segment4KBKeyTemplate,
	AES256GCMHKDF1MBKeyTemplate:              streamingaead.AES256GCMHKDF1MBKeyTemplate,
	AES256GCMHKDF4KBKeyTemplate:              streamingaead.AES256GCMHKDF4KBKeyTemplate,
}

// NewStreamEncrypterDecrypter returns a valid StreamEncrypterDecrypter.
func NewStreamEncrypterDecrypter(config Config) (StreamEncrypterDecrypter, error) {
	return newImpl(config, true)
}
